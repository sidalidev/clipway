// Writes docs/VECTORS.json: test vectors shared by the relay, the Android app and the Mac app.
// Usage, from the repository root: node tools/gen-vectors.mjs
// Every value is deterministic (fixed secret, ids, timestamps and nonces): running the script
// twice gives the same file. Never use fixed nonces outside tests.

import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  deriveId,
  deriveProof,
  deriveKeys,
  fingerprint,
  seal,
  open,
  padHead,
  buildItem,
  readItem,
  serializeHead,
  encryptHead,
  decryptHead,
  toWords,
  fromWords,
  toQr,
  fromQr,
  DEFAULT_RELAY,
  PAD_BLOCK,
  TEXT_MAX,
  HEAD_MAX,
  ENC_MAX,
  FILE_MAX,
} from "../relay/crypto.js";
import { WORDS } from "../relay/bip39-english.js";
import * as nearby from "../relay/nearby.js";
import * as direct from "../relay/direct.js";

const S = "000102030405060708090a0b0c0d0e0f";
const TS = 1792300000000;
const MAC = { id: "f0e1d2c3b4a5968778695a4b3c2d1e0f", name: "Test Mac", kind: "mac" };
const PIXEL = { id: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", name: "Test Pixel", kind: "android" };
const HEAD_NONCE = "0a0b0c0d0e0f101112131415";
const sha256 = (data) => createHash("sha256").update(data).digest("hex");

const id = deriveId(S);
const keys = deriveKeys(S);

// A 1x1 transparent PNG (67 bytes).
const PNG = Buffer.from(
  "89504e470d0a1a0a0000000d4948445200000001000000010806000000" +
    "1f15c4890000000d4944415478da63fcffff3f0300050001ff5a4e86e10000000049454e44ae426082",
  "hex",
);

// Content of the direct transfer vector: byte i = i mod 251, 150 000 bytes, so 3 records
// (65 536 + 65 536 + 18 928).
const BIG_SIZE = 150_000;
const big = Buffer.alloc(BIG_SIZE);
for (let i = 0; i < BIG_SIZE; i++) big[i] = i % 251;

function itemVector(note, input, nonce) {
  const built = buildItem(S, input, { nonce });
  const back = readItem(S, built.envelopes);
  if (back.head.item !== built.head.item) throw new Error("round trip failed");
  return {
    note,
    head: built.head,
    plaintext: built.headJson,
    plaintext_bytes: Buffer.byteLength(built.headJson, "utf8"),
    envelope: built.envelopes[0],
    built,
  };
}

const text = itemVector(
  "Text copied on the Mac, inline. AAD of the head = chain id. The plaintext is the exact padded JSON string.",
  { type: "text", item: "00112233445566778899aabbccddeeff", device: MAC, ts: TS, content: Buffer.from("Copied on the Mac: café ☕ 👋", "utf8") },
  HEAD_NONCE,
);

const hello = itemVector(
  "hello: sent once after joining a chain and when the device name changes. No content fields.",
  { type: "hello", item: "0123456789abcdef0123456789abcdef", device: PIXEL, ts: TS + 2000 },
  "3a3b3c3d3e3f404142434445",
);

const offerImage = itemVector(
  "An image offered by the phone: the content stays on the phone, which listens on port 41234 at the addresses listed. The receiver connects there (section 14). name is optional for an image.",
  { type: "offer", item: "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", device: PIXEL, ts: TS + 1000, media: "image", mime: "image/png", name: "dot.png", content: PNG, port: 41234, hosts: ["192.168.1.23", "10.0.0.7"] },
  "2a2b2c2d2e2f303132333435",
);

const offerFile = itemVector(
  "A file of 150 000 bytes (byte i = i mod 251) offered by the Mac. The direct block below transfers it.",
  { type: "offer", item: "ffeeddccbbaa99887766554433221100", device: MAC, ts: TS + 3000, media: "file", mime: "application/octet-stream", name: "pattern.bin", content: big, port: 50123, hosts: ["192.168.1.10"] },
  "4a0b0c0d0e0f101112131415",
);

const reply = itemVector(
  "The phone could not connect to any address of the Mac's offer: it says so through the relay.",
  { type: "reply", item: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", device: PIXEL, ts: TS + 4000, offer: "ffeeddccbbaa99887766554433221100", status: "unreachable" },
  "5a5b5c5d5e5f606162636465",
);

// Heads every implementation must refuse: an image or a file inside an item (Clipway 0.2 and
// earlier) and a text cut in chunks. They travel directly now, never through the relay.
const legacyImage = { v: 1, type: "image", item: "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", device: PIXEL, ts: TS + 1000, mime: "image/png", name: "dot.png", size: PNG.length, fp: fingerprint(keys.mac, PNG), data: PNG.toString("base64") };
const legacyImageJson = padHead(JSON.stringify(legacyImage));
const legacyChunked = { v: 1, type: "text", item: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", device: MAC, ts: TS, mime: "text/plain", size: 1_500_000, fp: fingerprint(keys.mac, big), chunks: 2 };
const refusedHeads = [
  ["image inside an item", legacyImageJson, "6a6b6c6d6e6f707172737475"],
  ["text in chunks", padHead(JSON.stringify(legacyChunked)), "7a7b7c7d7e7f808182838485"],
  ["text over 64 KiB", padHead(JSON.stringify({ v: 1, type: "text", item: "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", device: MAC, ts: TS, mime: "text/plain", size: TEXT_MAX + 1, fp: fingerprint(keys.mac, Buffer.alloc(TEXT_MAX + 1, 0x61)), data: Buffer.alloc(TEXT_MAX + 1, 0x61).toString("base64") })), "8a8b8c8d8e8f909192939495"],
  ["offer without hosts", padHead(JSON.stringify({ ...offerImage.head, hosts: [] })), "9a9b9c9d9e9fa0a1a2a3a4a5"],
  ["offer with a host name", padHead(JSON.stringify({ ...offerImage.head, hosts: ["mac.local"] })), "aaabacadaeafb0b1b2b3b4b5"],
].map(([why, json, nonce]) => {
  const envelope = encryptHead(S, json, nonce);
  let refused = false;
  try {
    decryptHead(S, envelope);
  } catch {
    refused = true;
  }
  if (!refused) throw new Error(`refused head accepted: ${why}`);
  return { why, envelope };
});

// The largest text: 64 KiB, with the largest device name the protocol allows, fits in HEAD_MAX.
{
  const worst = { id: MAC.id, name: "\u0001".repeat(64), kind: "android" };
  const json = serializeHead({ v: 1, type: "text", item: "00112233445566778899aabbccddeeff", device: worst, ts: 9_999_999_999_999, mime: "text/plain", size: TEXT_MAX, fp: "0".repeat(32), data: Buffer.alloc(TEXT_MAX).toString("base64") });
  if (Buffer.byteLength(json) !== HEAD_MAX) throw new Error(`largest head is ${Buffer.byteLength(json)}, not ${HEAD_MAX}`);
}

// Negative cases: every implementation must refuse them.
const tampered = { ...text.envelope, enc: text.envelope.enc.slice(0, -4) + (text.envelope.enc.endsWith("AAAA") ? "BBBB" : "AAAA") };
for (const [label, fn] of [
  ["tampered", () => open(keys.enc, id, tampered)],
  ["wrong aad", () => open(keys.enc, "00000000000000000000000000000000", text.envelope)],
]) {
  let failed = false;
  try {
    fn();
  } catch {
    failed = true;
  }
  if (!failed) throw new Error(`negative case accepted: ${label}`);
}

const relay = "http://127.0.0.1:7710";
if (fromWords(toWords(S)).toString("hex") !== S) throw new Error("words round trip failed");
if (fromQr(toQr(S, relay)).relay !== relay) throw new Error("QR round trip failed");

const vectors = {
  description:
    "Clipway test vectors, protocol v1 (see docs/PROTOCOL.md). Binary values are lowercase hex unless stated. Generated by tools/gen-vectors.mjs from relay/crypto.js.",
  S,
  S_base64url: Buffer.from(S, "hex").toString("base64url"),
  P: deriveProof(S).toString("hex"),
  id,
  K_enc: keys.enc.toString("hex"),
  K_mac: keys.mac.toString("hex"),
  derivation:
    "P = HKDF-SHA256(S, empty salt, info clipway-proof, 16). id = hex(SHA-256(clipway-id || P))[0:32]. K_enc = HKDF-SHA256(S, empty salt, clipway-enc, 32). K_mac = HKDF-SHA256(S, empty salt, clipway-mac, 32).",
  words: toWords(S),
  wordlist_sha256: sha256(WORDS.join("\n") + "\n"),
  qr: toQr(S),
  qr_with_relay: { relay, text: toQr(S, relay) },
  subprotocol: `clipway.v1, clipway.p.${deriveProof(S).toString("hex")}`,
  fingerprint: {
    note: "fp = hex(HMAC-SHA256(K_mac, content)[0:16]).",
    content_utf8: "Copied on the Mac: café ☕ 👋",
    fp: fingerprint(keys.mac, Buffer.from("Copied on the Mac: café ☕ 👋", "utf8")),
  },
  envelope: {
    note: "AES-256-GCM, iv = nonce (12 bytes), aad = UTF-8 string, enc = standard base64 of ciphertext followed by the 16-byte tag. Same format as the Sonne encrypted state.",
    aad: id,
    plaintext_utf8: "hello",
    nonce: HEAD_NONCE,
    envelope: seal(keys.enc, id, Buffer.from("hello", "utf8"), HEAD_NONCE),
  },
  padding: {
    note: `The head plaintext is padded with spaces in a "pad" field, before the final brace, to the smallest multiple of ${PAD_BLOCK} bytes that is at least its length + 9.`,
    unpadded: '{"v":1}',
    padded: padHead('{"v":1}'),
    padded_bytes: Buffer.byteLength(padHead('{"v":1}'), "utf8"),
  },
  limits: {
    note: "The relay carries texts only: one envelope per item, at most the size of a 64 KiB text. Images and files (25 MiB at most) go directly (section 14).",
    text: TEXT_MAX,
    head: HEAD_MAX,
    enc: ENC_MAX,
    file: FILE_MAX,
  },
  text_item: { note: text.note, head: text.head, plaintext: text.plaintext, plaintext_bytes: text.plaintext_bytes, envelope: text.envelope },
  hello_item: { note: hello.note, head: hello.head, plaintext: hello.plaintext, plaintext_bytes: hello.plaintext_bytes, envelope: hello.envelope },
  offer_item: { note: offerImage.note, head: offerImage.head, plaintext: offerImage.plaintext, plaintext_bytes: offerImage.plaintext_bytes, envelope: offerImage.envelope },
  offer_file_item: { note: offerFile.note, head: offerFile.head, plaintext: offerFile.plaintext, plaintext_bytes: offerFile.plaintext_bytes, envelope: offerFile.envelope },
  reply_item: { note: reply.note, head: reply.head, plaintext: reply.plaintext, plaintext_bytes: reply.plaintext_bytes, envelope: reply.envelope },
  refused_heads: {
    note: "Envelopes that open, but whose head must be refused (dropped and acknowledged): images and files never travel inside items any more, and nothing is cut in chunks.",
    cases: refusedHeads,
  },
  negative: {
    note: "Both must be refused: authentication fails.",
    tampered_envelope: tampered,
    wrong_aad: "00000000000000000000000000000000",
  },
  frames: {
    note: "Examples of relay frames (JSON text WebSocket frames). See docs/PROTOCOL.md, Relay.",
    welcome: { kind: "welcome", v: 1, epoch: "5f3a9c0d1e2b4a68", devices: 2, limits: { frame: 131072, parts: 1, text: TEXT_MAX, enc: ENC_MAX, items: 50, bytes: 6291456, ttl: 86400000 } },
    sync: { kind: "sync", epoch: "5f3a9c0d1e2b4a68", after: 41 },
    synced: { kind: "synced", last: 42 },
    upload: { kind: "item", ref: 7, part: 0, parts: 1, blob: text.envelope },
    stored: { kind: "stored", ref: 7, seq: 43 },
    delivery: { kind: "item", seq: 43, part: 0, parts: 1, ts: TS + 5, blob: text.envelope },
    ack: { kind: "ack", seq: 43 },
    delivered: { kind: "delivered", seq: 43 },
    presence: { kind: "presence", devices: 1 },
    ping: { kind: "ping" },
    pong: { kind: "pong" },
    error: { kind: "error", ref: 7, code: "too_big", message: "this relay carries texts of 64 KB at most: images and files go directly between your devices" },
  },
};

vectors.direct = directVectors();
vectors.nearby = nearbyVectors();

const out = fileURLToPath(new URL("../docs/VECTORS.json", import.meta.url));
writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
console.log(`Wrote docs/VECTORS.json (chain id ${id})`);

// ---------------------------------------------------------------------------
// Direct transfer of images and files (docs/PROTOCOL.md, section 14)
// ---------------------------------------------------------------------------

function directVectors() {
  const hex = (b) => Buffer.from(b).toString("hex");
  const transfer = offerFile.head.item;
  const kDirect = direct.directKey(S);
  const kT = direct.transferKey(kDirect, transfer);
  const recordNonce = (dir, i) => (dir === "get" ? "e0e1e2e3e4e5e6e7e8e9" : "f0f1f2f3f4f5f6f7f8f9") + i.toString(16).padStart(4, "0");
  const record = (dir, index, plaintext) => {
    const bytes = direct.sealRecord(kT, transfer, dir, index, plaintext, Buffer.from(recordNonce(dir, index), "hex"));
    const back = direct.openRecord(kT, transfer, dir, index, bytes.subarray(4));
    if (!back.equals(Buffer.from(plaintext))) throw new Error("record round trip failed");
    return { dir, index, aad: direct.recordAad(transfer, dir, index), nonce: recordNonce(dir, index), plaintext_bytes: Buffer.from(plaintext).length, bytes };
  };
  const get0 = record("get", 0, direct.getRequest(transfer));
  const get1 = record("get", 1, direct.getStatus("done"));
  const puts = [];
  for (let i = 0; i < direct.recordCount(BIG_SIZE); i++) {
    puts.push(record("put", i, big.subarray(i * direct.RECORD_DATA, Math.min(BIG_SIZE, (i + 1) * direct.RECORD_DATA))));
  }
  // Negative cases: a record opened in the other direction, at another index, or tampered.
  const tamperedGet = Buffer.from(get0.bytes);
  tamperedGet[tamperedGet.length - 1] ^= 0x01;
  for (const [label, fn] of [
    ["wrong direction", () => direct.openRecord(kT, transfer, "put", 0, get0.bytes.subarray(4))],
    ["wrong index", () => direct.openRecord(kT, transfer, "get", 1, get0.bytes.subarray(4))],
    ["other transfer", () => direct.openRecord(direct.transferKey(kDirect, offerImage.head.item), offerImage.head.item, "get", 0, get0.bytes.subarray(4))],
    ["tampered", () => direct.openRecord(kT, transfer, "get", 0, tamperedGet.subarray(4))],
  ]) {
    let failed = false;
    try {
      fn();
    } catch {
      failed = true;
    }
    if (!failed) throw new Error(`direct negative case accepted: ${label}`);
  }
  return {
    note: "Direct transfer of the file offered in offer_file_item. Records are length (4 bytes, big-endian) || nonce || ciphertext || tag; record nonces are fixed here, random in the apps.",
    derivation: "K_direct = HKDF-SHA256(S, empty salt, clipway-direct, 32). K_t = HKDF-SHA256(K_direct, empty salt, clipway-direct|<transfer>, 32). AAD of a record = clipway-direct|<transfer>|<get or put>|<index>.",
    K_direct: hex(kDirect),
    transfer,
    K_t: hex(kT),
    preamble: hex(direct.preamble(transfer)),
    record_data: direct.RECORD_DATA,
    record_max: direct.RECORD_MAX,
    content_rule: "byte i = i mod 251",
    size: BIG_SIZE,
    content_sha256: sha256(big),
    get0: { ...get0, plaintext_utf8: direct.getRequest(transfer), bytes: hex(get0.bytes) },
    puts: puts.map((r) => ({ index: r.index, aad: r.aad, nonce: r.nonce, plaintext_bytes: r.plaintext_bytes, length: r.bytes.length, sha256: sha256(r.bytes) })),
    put0_head: hex(puts[0].bytes.subarray(0, 64)),
    put_last: { index: puts.at(-1).index, bytes: hex(puts.at(-1).bytes) },
    get1: { ...get1, plaintext_utf8: direct.getStatus("done"), bytes: hex(get1.bytes) },
    negative: {
      note: "Each must be refused: get0 opened as put 0, get0 opened as get 1, get0 with another transfer's key, get0 with its last byte flipped.",
      tampered_get0: hex(tamperedGet),
    },
    private_hosts: {
      note: "Addresses a receiver may connect to (the local network): 10/8, 172.16/12, 192.168/16, 169.254/16. Debug builds also allow loopback.",
      allowed: ["10.0.0.7", "172.16.0.1", "172.31.255.254", "192.168.1.23", "169.254.10.20"],
      refused: ["8.8.8.8", "172.32.0.1", "172.15.0.1", "100.64.0.1", "127.0.0.1", "0.0.0.0", "255.255.255.255", "192.169.0.1", "192.168.1", "fe80::1", "mac.local"],
    },
  };
}

// ---------------------------------------------------------------------------
// Nearby pairing over Bluetooth (docs/PROTOCOL.md, section 13)
// ---------------------------------------------------------------------------

function nearbyVectors() {
  const hex = (b) => Buffer.from(b).toString("hex");
  // RFC 7748, section 6.1: the Mac is Alice, the phone is Bob. Z is the RFC's shared secret.
  const MAC_SK = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
  const PHONE_SK = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
  const RFC_Z = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
  const NONCE = "c0c1c2c3c4c5c6c7c8c9cacb";
  const NONCE_RELAY = "d0d1d2d3d4d5d6d7d8d9dadb";
  const LOCAL_RELAY = "http://127.0.0.1:7710";

  const pkMac = nearby.publicFromPrivate(MAC_SK);
  const pkPhone = nearby.publicFromPrivate(PHONE_SK);
  const z = nearby.sharedSecret(MAC_SK, pkPhone);
  if (hex(z) !== RFC_Z || hex(nearby.sharedSecret(PHONE_SK, pkMac)) !== RFC_Z) throw new Error("X25519 does not match RFC 7748");
  const k = nearby.deriveNearby(z, pkMac, pkPhone);
  const sas = nearby.sasCode(k.sas, pkMac, pkPhone);
  const confirm = nearby.confirmTag(k.sas, pkMac, pkPhone);
  const commit = nearby.commitment(pkMac);
  const phone = nearby.phoneHandshake(PHONE_SK, commit, pkMac);
  if (phone.sas !== sas || !phone.confirm.equals(confirm) || !phone.key.equals(k.key)) throw new Error("phone and Mac disagree");

  const packetVector = (relay, nonce) => {
    const code = toQr(S, relay);
    const bytes = nearby.sealPacket(k.key, pkMac, pkPhone, code, nonce);
    const back = nearby.openPacket(k.key, pkMac, pkPhone, bytes);
    if (back.code !== code || back.secret.toString("hex") !== S) throw new Error("packet round trip failed");
    return {
      relay,
      code,
      plaintext: nearby.packetPlaintext(code),
      plaintext_bytes: Buffer.byteLength(nearby.packetPlaintext(code), "utf8"),
      nonce,
      bytes: hex(bytes),
      opened: { secret: back.secret.toString("hex"), relay: back.relay },
    };
  };
  const packet = packetVector(DEFAULT_RELAY, NONCE);
  const packetRelay = packetVector(LOCAL_RELAY, NONCE_RELAY);

  // A second phone key, the first of a fixed series whose code starts with 0 (leading zeros).
  let leading = null;
  for (let i = 0; !leading; i++) {
    const sk = createHash("sha256").update(`clipway-nearby-vector-${i}`).digest();
    const pk = nearby.publicFromPrivate(sk);
    const kk = nearby.deriveNearby(nearby.sharedSecret(MAC_SK, pk), pkMac, pk);
    const code4 = nearby.sasCode(kk.sas, pkMac, pk);
    if (code4.startsWith("0")) {
      leading = {
        note: `Phone private key = SHA-256("clipway-nearby-vector-${i}"), the first of that series whose code starts with 0. Same Mac key.`,
        phone_private: hex(sk),
        phone_public: hex(pk),
        shared: hex(nearby.sharedSecret(MAC_SK, pk)),
        K_sas: hex(kk.sas),
        K_key: hex(kk.key),
        sas_bytes: hex(nearby.sasBytes(kk.sas, pkMac, pk)),
        sas: code4,
        confirm: hex(nearby.confirmTag(kk.sas, pkMac, pk)),
      };
    }
  }

  const sasSamples = ["000000000000", "00000000270f", "000000002710", "0000000003e7", "ffffffffffff", "800000000000", "0123456789ab"].map((b) => ({
    bytes: b,
    integer: Buffer.from(b, "hex").readUIntBE(0, 6),
    sas: nearby.sasFromBytes(b),
  }));

  // Negative cases: every implementation must refuse them.
  const LOW_ORDER = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ];
  for (const pk of LOW_ORDER) {
    let refused = false;
    try {
      nearby.sharedSecret(MAC_SK, pk);
    } catch {
      refused = true;
    }
    if (!refused) throw new Error(`low-order key accepted: ${pk}`);
  }
  const highBit = Buffer.from(pkPhone);
  highBit[31] |= 0x80;
  const badConfirm = Buffer.from(confirm);
  badConfirm[15] ^= 0x01;
  const tampered = Buffer.from(packet.bytes, "hex");
  tampered[tampered.length - 1] ^= 0x01;
  const swappedAad = nearby.packetAad(pkPhone, pkMac);
  for (const [label, fn] of [
    ["high bit", () => nearby.checkPeerKey(highBit)],
    ["own key", () => nearby.checkPeerKey(pkMac, pkMac)],
    ["wrong commitment", () => nearby.phoneHandshake(PHONE_SK, commit, nearby.publicFromPrivate(leading.phone_private))],
    ["tampered packet", () => nearby.openPacket(k.key, pkMac, pkPhone, tampered)],
    ["swapped keys", () => nearby.openPacket(k.key, pkPhone, pkMac, Buffer.from(packet.bytes, "hex"))],
    ["short packet", () => nearby.openPacket(k.key, pkMac, pkPhone, Buffer.from(packet.bytes, "hex").subarray(0, 283))],
  ]) {
    let failed = false;
    try {
      fn();
    } catch {
      failed = true;
    }
    if (!failed) throw new Error(`negative case accepted: ${label}`);
  }
  if (nearby.checkConfirm(k.sas, pkMac, pkPhone, badConfirm)) throw new Error("negative case accepted: confirm");

  // Sessions: the Mac's answer to each request, replayed by the Mac test mode (13.11).
  const run = (name, note, steps) => {
    const mac = new nearby.NearbyMacSession({ secret: S, relay: DEFAULT_RELAY, privateKey: MAC_SK, nonce: NONCE });
    const out = steps.map((step) => {
      const value = step.value === undefined ? undefined : Buffer.from(step.value, "hex");
      const offset = step.offset ?? 0;
      let r;
      switch (step.op) {
        case "subscribe":
          r = mac.subscribe(step.by);
          break;
        case "unsubscribe":
          r = mac.unsubscribe(step.by);
          break;
        case "read":
          r = mac.read(step.by, step.char, offset);
          break;
        case "write":
          r = mac.write(step.by, step.char, value, offset);
          break;
        case "pair":
          r = mac.pair();
          break;
        case "cancel":
          r = mac.cancel();
          break;
        case "expire":
          r = mac.expire();
          break;
        case "grace_over":
          r = mac.graceOver();
          break;
        default:
          throw new Error(`unknown op ${step.op}`);
      }
      const rec = { ...step };
      if (r.value !== undefined) rec.expect = { value: hex(r.value) };
      else if (r.error !== undefined) rec.expect = { error: r.error };
      else if (r.ok) rec.expect = { ok: true };
      rec.notify = r.notify.map((b) => b.toString(16).padStart(2, "0"));
      rec.state = mac.state;
      if (mac.sas !== null) rec.mac_shows = mac.sas;
      if (mac.end) rec.end = mac.end;
      return rec;
    });
    for (const step of steps) if (step.check) step.check(mac);
    return { name, note, steps: out.map(({ check, ...rest }) => rest) };
  };

  const P = hex(pkPhone);
  const OTHER = leading.phone_public;
  const sessions = [
    run("success, phone confirms first", "The whole exchange. The packet read at the end is packet.bytes.", [
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "read", char: "commit" },
      { by: "phone", op: "read", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "read", char: "mac_key" },
      { by: "phone", op: "write", char: "confirm", value: hex(confirm) },
      { by: "mac", op: "pair" },
      { by: "phone", op: "read", char: "status" },
      { by: "phone", op: "read", char: "packet" },
      { by: "phone", op: "unsubscribe", char: "status" },
    ]),
    run("success, Mac confirms first, long read", "Pair on the Mac first: the ready status goes out with the answer to the phone's confirmation. The packet is read in parts (ATT Read Blob): the Mac answers with the bytes from the offset; the radio cuts them to the MTU. The 120 s limit does not cut a ready session; it ends 10 s after the first read of the packet.", [
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "read", char: "commit" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "read", char: "mac_key" },
      { by: "mac", op: "pair" },
      { by: "phone", op: "write", char: "confirm", value: hex(confirm) },
      { by: "phone", op: "read", char: "packet", offset: 0 },
      { by: "phone", op: "read", char: "packet", offset: 184 },
      { by: "phone", op: "read", char: "packet", offset: 284 },
      { by: "phone", op: "read", char: "packet", offset: 285 },
      { by: "mac", op: "expire" },
      { by: "mac", op: "grace_over" },
    ]),
    run("order, lengths and refused keys", "Requests out of order are refused; a malformed or refused phone key does not use up the attempt.", [
      { by: "phone", op: "read", char: "mac_key" },
      { by: "phone", op: "write", char: "confirm", value: hex(confirm) },
      { by: "phone", op: "read", char: "packet" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P, offset: 1 },
      { by: "phone", op: "write", char: "phone_key", value: P.slice(0, 62) },
      { by: "phone", op: "write", char: "phone_key", value: LOW_ORDER[0] },
      { by: "phone", op: "write", char: "phone_key", value: hex(highBit) },
      { by: "phone", op: "write", char: "phone_key", value: hex(pkMac) },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "read", char: "packet" },
      { by: "phone", op: "write", char: "confirm", value: hex(confirm).slice(0, 30) },
    ]),
    run("one attempt per advertisement", "Once a phone key is accepted, every other phone is refused and reads Status 05.", [
      { by: "other", op: "subscribe", char: "status" },
      { by: "phone", op: "subscribe", char: "status" },
      { by: "other", op: "read", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "other", op: "write", char: "phone_key", value: OTHER },
      { by: "other", op: "read", char: "status" },
      { by: "other", op: "read", char: "mac_key" },
      { by: "other", op: "write", char: "confirm", value: hex(confirm) },
      { by: "other", op: "read", char: "commit" },
      { by: "other", op: "unsubscribe", char: "status" },
      { by: "phone", op: "read", char: "status" },
    ]),
    run("wrong confirmation", "A wrong tag ends the attempt with Status 04; nothing can be read after.", [
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "mac", op: "pair" },
      { by: "phone", op: "write", char: "confirm", value: hex(badConfirm) },
      { by: "phone", op: "read", char: "packet" },
    ]),
    run("canceled on the Mac", "Cancel, closing the window or Show a code instead: Status 02.", [
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "mac", op: "cancel" },
      { by: "phone", op: "read", char: "mac_key" },
    ]),
    run("expired", "120 s after the window opened, before both confirmations: Status 03.", [
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "write", char: "confirm", value: hex(confirm) },
      { by: "mac", op: "expire" },
    ]),
    run("phone left", "The phone disconnects (Cancel on the phone, or out of range) before the end: no status, the attempt is over.", [
      { by: "phone", op: "subscribe", char: "status" },
      { by: "phone", op: "write", char: "phone_key", value: P },
      { by: "phone", op: "unsubscribe", char: "status" },
      { by: "mac", op: "pair" },
    ]),
  ];

  return {
    note: "Nearby pairing over Bluetooth (docs/PROTOCOL.md, section 13). Keys are raw X25519 (RFC 7748, 32 bytes, little-endian u-coordinate). The fixed key pair is the one of RFC 7748, section 6.1: Mac = Alice, phone = Bob. The packets use the top-level S. Never use fixed keys or nonces outside tests.",
    service: nearby.SERVICE_UUID,
    characteristics: nearby.CHARACTERISTICS,
    cccd: nearby.CCCD_UUID,
    status: nearby.STATUS,
    att_errors: nearby.ATT,
    labels: nearby.LABELS,
    der_prefixes: {
      note: "Wrap a raw key for APIs that take DER (java.security on Android, node:crypto). The raw public key is the last 32 bytes of the X.509 encoding.",
      pkcs8_private: hex(nearby.PKCS8_PREFIX),
      x509_public: hex(nearby.SPKI_PREFIX),
    },
    derivation:
      "commit = SHA-256(clipway-nearby-commit || pk_mac). T = pk_mac || pk_phone. Z = X25519. N = HKDF-SHA256(Z || T, empty salt, clipway-nearby, 32). K_sas = HKDF-SHA256(N, empty salt, clipway-nearby-sas, 32). K_key = HKDF-SHA256(N, empty salt, clipway-nearby-key, 32). sas = big-endian integer of HMAC-SHA256(K_sas, T)[0:6] mod 10000, 4 digits. confirm = HMAC-SHA256(K_sas, clipway-nearby-confirm || T)[0:16]. Packet = nonce || AES-256-GCM(K_key, aad, padded JSON) || tag.",
    mac_private: MAC_SK,
    mac_public: hex(pkMac),
    phone_private: PHONE_SK,
    phone_public: hex(pkPhone),
    commit: hex(commit),
    transcript: hex(nearby.transcript(pkMac, pkPhone)),
    shared: hex(z),
    N: hex(k.n),
    K_sas: hex(k.sas),
    K_key: hex(k.key),
    sas_bytes: hex(nearby.sasBytes(k.sas, pkMac, pkPhone)),
    sas_integer: nearby.sasBytes(k.sas, pkMac, pkPhone).readUIntBE(0, 6),
    sas,
    confirm: hex(confirm),
    aad: nearby.packetAad(pkMac, pkPhone),
    max_code_length: nearby.PACKET_PLAINTEXT_SIZE - 9 - Buffer.byteLength(JSON.stringify({ v: 1, code: "" })),
    packet,
    packet_with_relay: packetRelay,
    leading_zero: leading,
    sas_samples: sasSamples,
    negative: {
      note: "Every implementation must refuse these.",
      low_order_keys: { note: "Z would be all zeros: refused (the library may throw instead).", keys: LOW_ORDER },
      high_bit_key: { note: "phone_public with the top bit of byte 31 set: refused before X25519.", key: hex(highBit) },
      own_key: { note: "A peer key equal to our own public key: refused.", key: hex(pkMac) },
      wrong_commitment: { note: "The phone read commit, then a Mac key that does not match it: refused.", commit: hex(commit), mac_public: leading.phone_public },
      wrong_confirm: { note: "confirm with its last bit flipped: the Mac ends the attempt (Status 04).", confirm: hex(badConfirm) },
      tampered_packet: { note: "packet.bytes with its last bit flipped: authentication fails.", bytes: hex(tampered) },
      swapped_aad: { note: "The packet opened with the keys in the wrong order in the AAD: authentication fails.", aad: swappedAad },
      short_packet: { note: "Any length other than 284 bytes: refused before decryption.", length: 283 },
    },
    sessions,
  };
}
