// Checks relay/crypto.js against docs/VECTORS.json (shared with the Android and Mac apps).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  deriveProof,
  idFromProof,
  deriveId,
  deriveKeys,
  fingerprint,
  seal,
  open,
  padHead,
  serializeHead,
  validateHead,
  decryptHead,
  buildItem,
  readItem,
  toWords,
  fromWords,
  toQr,
  fromQr,
  generateSecret,
  TEXT_MAX,
  HEAD_MAX,
  ENC_MAX,
  FILE_MAX,
} from "../crypto.js";
import { WORDS } from "../bip39-english.js";

const V = JSON.parse(readFileSync(new URL("../../docs/VECTORS.json", import.meta.url), "utf8"));
const S = V.S;
const sha256 = (d) => createHash("sha256").update(d).digest("hex");

test("official BIP39 English list", () => {
  assert.equal(WORDS.length, 2048);
  assert.equal(sha256(WORDS.join("\n") + "\n"), V.wordlist_sha256);
});

test("proof, chain id and keys", () => {
  assert.equal(deriveProof(S).toString("hex"), V.P);
  assert.equal(idFromProof(Buffer.from(V.P, "hex")), V.id);
  assert.equal(deriveId(S), V.id);
  const k = deriveKeys(S);
  assert.equal(k.enc.toString("hex"), V.K_enc);
  assert.equal(k.mac.toString("hex"), V.K_mac);
});

test("words and QR code", () => {
  assert.deepEqual(toWords(S), V.words);
  assert.equal(fromWords(V.words.join("  ").toUpperCase()).toString("hex"), S);
  assert.throws(() => fromWords(V.words.slice(0, 11)), /12 words/);
  const swapped = [...V.words];
  [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
  assert.throws(() => fromWords(swapped), /checksum|Unknown/);
  assert.equal(toQr(S), V.qr);
  assert.equal(toQr(S, V.qr_with_relay.relay), V.qr_with_relay.text);
  assert.deepEqual(fromQr(V.qr), { secret: Buffer.from(S, "hex"), relay: null });
  assert.equal(fromQr(V.qr_with_relay.text).relay, V.qr_with_relay.relay);
  assert.throws(() => fromQr("https://example.com/#s=AAECAwQFBgcICQoLDA0ODw"));
  assert.throws(() => fromQr("clipway:AAECAwQFBgcICQoLDA0O"));
});

test("fingerprint and envelope", () => {
  const k = deriveKeys(S);
  assert.equal(fingerprint(k.mac, Buffer.from(V.fingerprint.content_utf8, "utf8")), V.fingerprint.fp);
  const e = V.envelope;
  assert.deepEqual(seal(k.enc, e.aad, Buffer.from(e.plaintext_utf8, "utf8"), e.nonce), e.envelope);
  assert.equal(open(k.enc, e.aad, e.envelope).toString("utf8"), e.plaintext_utf8);
  assert.throws(() => open(k.enc, V.id, V.negative.tampered_envelope), /authentication/);
  assert.throws(() => open(k.enc, V.negative.wrong_aad, V.text_item.envelope), /authentication/);
});

const ITEMS = ["text_item", "hello_item", "offer_item", "offer_file_item", "reply_item"];

test("limits: texts of 64 KiB, heads of 172 x 512 bytes, envelopes of 117 440 base64 characters", () => {
  assert.deepEqual(V.limits.text, TEXT_MAX);
  assert.equal(TEXT_MAX, 65_536);
  assert.equal(HEAD_MAX, V.limits.head);
  assert.equal(HEAD_MAX, 172 * 512);
  assert.equal(ENC_MAX, V.limits.enc);
  assert.equal(ENC_MAX, Math.ceil((HEAD_MAX + 16) / 3) * 4);
  assert.equal(FILE_MAX, V.limits.file);
  // The largest text with an ordinary name fits, with room to spare.
  const built = buildItem(S, { type: "text", device: { id: "0".repeat(32), name: "x".repeat(64), kind: "mac" }, ts: Date.now(), content: Buffer.alloc(TEXT_MAX, 0x7a) });
  assert.ok(built.envelopes[0].enc.length <= ENC_MAX);
  assert.throws(() => buildItem(S, { type: "text", device: { id: "0".repeat(32), name: "x", kind: "mac" }, ts: 1, content: Buffer.alloc(TEXT_MAX + 1) }), /too big/);
});

test("padding", () => {
  assert.equal(padHead(V.padding.unpadded), V.padding.padded);
  assert.equal(Buffer.byteLength(V.padding.padded), V.padding.padded_bytes);
  for (const name of ITEMS) {
    assert.equal(Buffer.byteLength(V[name].plaintext) % 512, 0, name);
    assert.equal(serializeHead(V[name].head), V[name].plaintext, name);
  }
});

test("items: seal the exact plaintext with the fixed nonce, and read them back", () => {
  const k = deriveKeys(S);
  for (const name of ITEMS) {
    const v = V[name];
    assert.deepEqual(seal(k.enc, V.id, Buffer.from(v.plaintext, "utf8"), v.envelope.nonce), v.envelope, name);
    assert.deepEqual(decryptHead(S, v.envelope), v.head, name);
  }
  const t = readItem(S, [V.text_item.envelope]);
  assert.equal(t.content.toString("utf8"), V.fingerprint.content_utf8);
  const offer = readItem(S, [V.offer_item.envelope]);
  assert.equal(offer.content, null);
  assert.deepEqual([offer.head.media, offer.head.name, offer.head.port, offer.head.hosts], ["image", "dot.png", 41234, ["192.168.1.23", "10.0.0.7"]]);
  assert.deepEqual(readItem(S, [V.reply_item.envelope]).head.status, "unreachable");
  assert.equal(readItem(S, [V.hello_item.envelope]).content, null);
  // One envelope per item, always.
  assert.throws(() => readItem(S, [V.text_item.envelope, V.text_item.envelope]), /one part/);
});

test("images and files inside items, and chunks, are refused", () => {
  for (const c of V.refused_heads.cases) assert.throws(() => decryptHead(S, c.envelope), /Invalid head/, c.why);
  assert.throws(() => decryptHead(S, V.refused_heads.cases[0].envelope), /travel directly/);
});

test("head validation", () => {
  const ok = V.text_item.head;
  assert.deepEqual(validateHead({ ...ok, pad: "  ", extra: 1 }), ok);
  assert.throws(() => validateHead({ ...ok, v: 2 }), /version/);
  assert.throws(() => validateHead({ ...ok, type: "exe" }), /type/);
  assert.throws(() => validateHead({ ...ok, type: "image", mime: "image/png" }), /travel directly/);
  assert.throws(() => validateHead({ ...ok, type: "file", name: "a.bin" }), /travel directly/);
  assert.throws(() => validateHead({ ...ok, size: ok.size + 1 }), /length/);
  assert.throws(() => validateHead({ ...ok, chunks: 1 }), /chunks/);
  assert.throws(() => validateHead({ ...ok, name: "a.txt" }), /name/);
  assert.throws(() => validateHead({ ...ok, device: { ...ok.device, kind: "linux" } }), /kind/);
  const { data, ...noData } = ok;
  assert.throws(() => validateHead(noData), /data/);

  const offer = V.offer_item.head;
  assert.deepEqual(validateHead({ ...offer, pad: " " }), offer);
  assert.throws(() => validateHead({ ...offer, media: "video" }), /media/);
  assert.throws(() => validateHead({ ...offer, mime: "application/pdf" }), /image mime/);
  assert.throws(() => validateHead({ ...offer, size: FILE_MAX + 1 }), /too big/);
  assert.throws(() => validateHead({ ...offer, port: 0 }), /port/);
  assert.throws(() => validateHead({ ...offer, port: 65_536 }), /port/);
  assert.throws(() => validateHead({ ...offer, hosts: [] }), /hosts/);
  assert.throws(() => validateHead({ ...offer, hosts: Array(9).fill("10.0.0.1") }), /hosts/);
  assert.throws(() => validateHead({ ...offer, hosts: ["fe80::1"] }), /hosts/);
  assert.throws(() => validateHead({ ...offer, hosts: ["10.0.0.01"] }), /hosts/);
  assert.throws(() => validateHead({ ...offer, data: "AAAA" }), /no content/);
  const { name, ...noName } = V.offer_file_item.head;
  assert.throws(() => validateHead(noName), /file without name/);
  const { name: imageName, ...imageNoName } = offer;
  assert.deepEqual(validateHead(imageNoName), imageNoName);

  const reply = V.reply_item.head;
  assert.deepEqual(validateHead(reply), reply);
  assert.throws(() => validateHead({ ...reply, status: "maybe" }), /status/);
  assert.throws(() => validateHead({ ...reply, offer: "nope" }), /offer/);
});

test("random secrets round trip", () => {
  for (let i = 0; i < 50; i++) {
    const s = generateSecret();
    assert.deepEqual(fromWords(toWords(s)), s);
    assert.deepEqual(fromQr(toQr(s)).secret, s);
  }
});
