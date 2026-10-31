// Checks relay/nearby.js against the nearby block of docs/VECTORS.json (shared with the Android and
// Mac apps), and the rules of docs/PROTOCOL.md, section 13.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import * as nearby from "../nearby.js";
import { toQr, DEFAULT_RELAY } from "../crypto.js";

const V = JSON.parse(readFileSync(new URL("../../docs/VECTORS.json", import.meta.url), "utf8"));
const N = V.nearby;
const hex = (b) => Buffer.from(b).toString("hex");
const buf = (h) => Buffer.from(h, "hex");

test("service and characteristic UUIDs", () => {
  assert.equal(nearby.SERVICE_UUID, N.service);
  assert.deepEqual({ ...nearby.CHARACTERISTICS }, N.characteristics);
  const all = [N.service, ...Object.values(N.characteristics)];
  assert.equal(new Set(all).size, 7);
  for (const u of all) assert.match(u, /^a498511[0-6]-4541-4fcc-bcac-ee9b5ce269d0$/);
  assert.equal(nearby.PACKET_SIZE, 284);
});

test("X25519: the RFC 7748 key pair", () => {
  assert.equal(hex(nearby.publicFromPrivate(N.mac_private)), N.mac_public);
  assert.equal(hex(nearby.publicFromPrivate(N.phone_private)), N.phone_public);
  assert.equal(N.mac_public, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  assert.equal(N.phone_public, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  assert.equal(hex(nearby.sharedSecret(N.mac_private, buf(N.phone_public))), N.shared);
  assert.equal(hex(nearby.sharedSecret(N.phone_private, buf(N.mac_public))), N.shared);
  assert.equal(N.shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
});

test("commitment, transcript, keys, code and confirmation", () => {
  const pkMac = buf(N.mac_public);
  const pkPhone = buf(N.phone_public);
  assert.equal(hex(nearby.commitment(pkMac)), N.commit);
  assert.equal(hex(nearby.transcript(pkMac, pkPhone)), N.transcript);
  const k = nearby.deriveNearby(buf(N.shared), pkMac, pkPhone);
  assert.equal(hex(k.n), N.N);
  assert.equal(hex(k.sas), N.K_sas);
  assert.equal(hex(k.key), N.K_key);
  assert.equal(hex(nearby.sasBytes(k.sas, pkMac, pkPhone)), N.sas_bytes);
  assert.equal(buf(N.sas_bytes).readUIntBE(0, 6), N.sas_integer);
  assert.equal(nearby.sasCode(k.sas, pkMac, pkPhone), N.sas);
  assert.match(N.sas, /^[0-9]{4}$/);
  assert.equal(hex(nearby.confirmTag(k.sas, pkMac, pkPhone)), N.confirm);
  assert.ok(nearby.checkConfirm(k.sas, pkMac, pkPhone, buf(N.confirm)));
  assert.equal(nearby.packetAad(pkMac, pkPhone), N.aad);
  assert.equal(Buffer.byteLength(N.aad), 144);
  // The order is fixed by role: swapping the keys changes everything.
  assert.notEqual(nearby.sasCode(k.sas, pkPhone, pkMac), N.sas);
});

test("the phone computes the same code, tag and key", () => {
  const p = nearby.phoneHandshake(N.phone_private, buf(N.commit), buf(N.mac_public));
  assert.equal(hex(p.pkPhone), N.phone_public);
  assert.equal(p.sas, N.sas);
  assert.equal(hex(p.confirm), N.confirm);
  assert.equal(hex(p.key), N.K_key);
});

test("code: 6 bytes, big-endian, modulo 10 000, 4 digits with leading zeros", () => {
  for (const s of N.sas_samples) {
    assert.equal(nearby.sasFromBytes(s.bytes), s.sas, s.bytes);
    assert.equal(buf(s.bytes).readUIntBE(0, 6), s.integer);
    assert.equal(s.sas, String(s.integer % 10000).padStart(4, "0"));
  }
  const L = N.leading_zero;
  const i = Number(L.note.match(/vector-(\d+)/)[1]);
  assert.equal(hex(createHash("sha256").update(`clipway-nearby-vector-${i}`).digest()), L.phone_private);
  const pk = nearby.publicFromPrivate(L.phone_private);
  assert.equal(hex(pk), L.phone_public);
  const z = nearby.sharedSecret(N.mac_private, pk);
  assert.equal(hex(z), L.shared);
  const k = nearby.deriveNearby(z, buf(N.mac_public), pk);
  assert.equal(hex(k.sas), L.K_sas);
  assert.equal(hex(k.key), L.K_key);
  assert.equal(hex(nearby.sasBytes(k.sas, buf(N.mac_public), pk)), L.sas_bytes);
  assert.equal(L.sas, nearby.sasCode(k.sas, buf(N.mac_public), pk));
  assert.match(L.sas, /^0[0-9]{3}$/);
  assert.equal(hex(nearby.confirmTag(k.sas, buf(N.mac_public), pk)), L.confirm);
});

test("packets: exact bytes with the fixed nonce, and read back", () => {
  const pkMac = buf(N.mac_public);
  const pkPhone = buf(N.phone_public);
  const key = buf(N.K_key);
  for (const p of [N.packet, N.packet_with_relay]) {
    assert.equal(toQr(V.S, p.relay), p.code);
    assert.equal(nearby.packetPlaintext(p.code), p.plaintext);
    assert.equal(Buffer.byteLength(p.plaintext), 256);
    assert.equal(p.plaintext_bytes, 256);
    const bytes = nearby.sealPacket(key, pkMac, pkPhone, p.code, p.nonce);
    assert.equal(hex(bytes), p.bytes);
    assert.equal(bytes.length, 284);
    assert.equal(hex(bytes.subarray(0, 12)), p.nonce);
    const back = nearby.openPacket(key, pkMac, pkPhone, buf(p.bytes));
    assert.equal(back.code, p.code);
    assert.equal(hex(back.secret), V.S);
    assert.equal(back.relay, p.opened.relay);
  }
  assert.equal(N.packet.relay, DEFAULT_RELAY);
  assert.equal(N.packet.opened.relay, null);
  assert.equal(N.packet_with_relay.opened.relay, "http://127.0.0.1:7710");
});

test("packets: the longest code that fits", () => {
  assert.equal(N.max_code_length, 230);
  const fits = "clipway:" + "A".repeat(N.max_code_length - 8);
  assert.equal(Buffer.byteLength(nearby.packetPlaintext(fits)), 256);
  assert.ok(nearby.fitsInPacket(fits));
  assert.ok(!nearby.fitsInPacket(fits + "A"));
  assert.throws(() => nearby.packetPlaintext(fits + "A"), /too long/);
  // A Mac whose relay address is too long does not offer nearby pairing.
  assert.throws(() => new nearby.NearbyMacSession({ secret: V.S, relay: "https://" + "a".repeat(200) + ".example" }), /too long/);
});

test("negative cases are refused", () => {
  const pkMac = buf(N.mac_public);
  const pkPhone = buf(N.phone_public);
  const key = buf(N.K_key);
  const neg = N.negative;
  for (const k of neg.low_order_keys.keys) {
    assert.throws(() => nearby.sharedSecret(N.mac_private, buf(k)), /Key refused/, k);
    assert.throws(() => nearby.sharedSecret(N.phone_private, buf(k)), /Key refused/, k);
  }
  assert.throws(() => nearby.checkPeerKey(buf(neg.high_bit_key.key)), /top bit/);
  assert.throws(() => nearby.checkPeerKey(buf(neg.own_key.key), pkMac), /own key/);
  assert.throws(() => nearby.checkPeerKey(pkPhone.subarray(0, 31)), /32 bytes/);
  assert.throws(() => nearby.phoneHandshake(N.phone_private, buf(neg.wrong_commitment.commit), buf(neg.wrong_commitment.mac_public)), /Commitment/);
  assert.throws(() => nearby.phoneHandshake(N.phone_private, buf(N.commit), buf(N.phone_public)), /Key refused|Commitment/);
  assert.ok(!nearby.checkConfirm(buf(N.K_sas), pkMac, pkPhone, buf(neg.wrong_confirm.confirm)));
  assert.ok(!nearby.checkConfirm(buf(N.K_sas), pkMac, pkPhone, buf(N.confirm).subarray(0, 15)));
  assert.throws(() => nearby.openPacket(key, pkMac, pkPhone, buf(neg.tampered_packet.bytes)), /authentication/);
  assert.equal(neg.swapped_aad.aad, nearby.packetAad(pkPhone, pkMac));
  assert.throws(() => nearby.openPacket(key, pkPhone, pkMac, buf(N.packet.bytes)), /authentication/);
  assert.throws(() => nearby.openPacket(key, pkMac, pkPhone, buf(N.packet.bytes).subarray(0, neg.short_packet.length)), /284 bytes/);
  // A packet sealed for another phone key cannot be opened with this one.
  const other = nearby.deriveNearby(buf(N.leading_zero.shared), pkMac, buf(N.leading_zero.phone_public));
  assert.throws(() => nearby.openPacket(other.key, pkMac, buf(N.leading_zero.phone_public), buf(N.packet.bytes)), /authentication/);
});

test("a man in the middle gets two different codes", () => {
  // The attacker talks to the Mac with key A and to the phone with key B (fixed keys, so this is
  // deterministic; with random keys the two codes match once in 10 000).
  const A = createHash("sha256").update("attacker-a").digest();
  const B = createHash("sha256").update("attacker-b").digest();
  const pkA = nearby.publicFromPrivate(A);
  const pkB = nearby.publicFromPrivate(B);
  const pkMac = buf(N.mac_public);
  const pkPhone = buf(N.phone_public);
  const onMac = nearby.sasCode(nearby.deriveNearby(nearby.sharedSecret(N.mac_private, pkA), pkMac, pkA).sas, pkMac, pkA);
  // To the phone the attacker plays the Mac, with key B, committed before the phone's key is known.
  const onPhone = nearby.phoneHandshake(N.phone_private, nearby.commitment(pkB), pkB).sas;
  assert.notEqual(onMac, onPhone);
  // The phone refuses a Mac key that does not match the commitment it read first.
  assert.throws(() => nearby.phoneHandshake(N.phone_private, nearby.commitment(pkB), pkA), /Commitment/);
});

test("random keys: both sides agree, every attempt has new keys", () => {
  const codes = new Set();
  for (let i = 0; i < 40; i++) {
    const mac = nearby.generateKeyPair();
    const phone = nearby.generateKeyPair();
    assert.equal(mac.publicKey.length, 32);
    assert.equal(mac.publicKey[31] & 0x80, 0);
    const k = nearby.deriveNearby(nearby.sharedSecret(mac.privateKey, phone.publicKey), mac.publicKey, phone.publicKey);
    const p = nearby.phoneHandshake(phone.privateKey, nearby.commitment(mac.publicKey), mac.publicKey);
    assert.equal(p.sas, nearby.sasCode(k.sas, mac.publicKey, phone.publicKey));
    assert.deepEqual(p.key, k.key);
    const packet = nearby.sealPacket(k.key, mac.publicKey, phone.publicKey, toQr(V.S));
    assert.equal(hex(nearby.openPacket(p.key, mac.publicKey, phone.publicKey, packet).secret), V.S);
    codes.add(hex(mac.publicKey));
  }
  assert.equal(codes.size, 40);
});

/** Replays one session of the vectors against a fresh NearbyMacSession. */
function replay(session) {
  const mac = new nearby.NearbyMacSession({ secret: V.S, relay: DEFAULT_RELAY, privateKey: N.mac_private, nonce: N.packet.nonce });
  for (const [i, step] of session.steps.entries()) {
    const where = `${session.name}, step ${i + 1}`;
    const value = step.value === undefined ? undefined : buf(step.value);
    const r = {
      subscribe: () => mac.subscribe(step.by),
      unsubscribe: () => mac.unsubscribe(step.by),
      read: () => mac.read(step.by, step.char, step.offset ?? 0),
      write: () => mac.write(step.by, step.char, value, step.offset ?? 0),
      pair: () => mac.pair(),
      cancel: () => mac.cancel(),
      expire: () => mac.expire(),
      grace_over: () => mac.graceOver(),
    }[step.op]();
    if (step.expect?.value !== undefined) assert.equal(hex(r.value), step.expect.value, where);
    if (step.expect?.error !== undefined) assert.equal(r.error, step.expect.error, where);
    if (step.expect?.ok) assert.equal(r.ok, true, where);
    assert.deepEqual(r.notify.map((b) => b.toString(16).padStart(2, "0")), step.notify, where);
    assert.equal(mac.state, step.state, where);
    assert.equal(mac.sas ?? undefined, step.mac_shows, where);
    assert.equal(mac.end ?? undefined, step.end, where);
  }
  return mac;
}

test("Mac sessions: every answer of the vectors", () => {
  assert.equal(N.sessions.length, 8);
  for (const s of N.sessions) replay(s);
});

test("Mac sessions: what the vectors must show", () => {
  const byName = Object.fromEntries(N.sessions.map((s) => [s.name, s]));
  const success = byName["success, phone confirms first"];
  const last = (name, op, char) => byName[name].steps.filter((s) => s.op === op && (!char || s.char === char)).at(-1);
  // The packet the phone reads is the vector packet, and the phone can open it.
  assert.equal(last("success, phone confirms first", "read", "packet").expect.value, N.packet.bytes);
  assert.equal(success.steps.find((s) => s.char === "mac_key").expect.value, N.mac_public);
  assert.equal(success.steps.find((s) => s.char === "commit").expect.value, N.commit);
  assert.equal(success.steps.find((s) => s.char === "phone_key").mac_shows, N.sas);
  assert.equal(success.steps.at(-1).end, "done");
  // Mac first: the ready status goes out with the confirmation; parts of a long read.
  const macFirst = byName["success, Mac confirms first, long read"].steps;
  assert.deepEqual(macFirst.find((s) => s.char === "confirm").notify, ["01"]);
  assert.equal(macFirst.find((s) => s.offset === 184).expect.value, N.packet.bytes.slice(368));
  assert.equal(macFirst.find((s) => s.offset === 285).expect.error, nearby.ATT.invalidOffset);
  // Refused keys do not use up the attempt; the second accepted write does not exist.
  const order = byName["order, lengths and refused keys"].steps;
  assert.deepEqual(order.filter((s) => s.char === "phone_key").map((s) => s.expect.ok ? "ok" : s.expect.error), [3, 7, 13, 14, 14, 14, "ok", 3]);
  // Other phones: busy.
  assert.equal(last("one attempt per advertisement", "read", "status").expect.value, "00");
  assert.equal(byName["one attempt per advertisement"].steps[5].expect.value, "05");
  assert.deepEqual(last("wrong confirmation", "write", "confirm").notify, ["04"]);
  assert.deepEqual(last("canceled on the Mac", "cancel").notify, ["02"]);
  assert.deepEqual(last("expired", "expire").notify, ["03"]);
  assert.equal(byName["phone left"].steps.at(-1).end, "left");
});

test("Mac session: fresh keys and code for every advertisement", () => {
  const a = new nearby.NearbyMacSession({ secret: V.S });
  const b = new nearby.NearbyMacSession({ secret: V.S });
  assert.notDeepEqual(a.pk, b.pk);
  assert.notDeepEqual(a.commit, b.commit);
  // Nothing secret is kept after the end.
  a.subscribe("p");
  assert.ok(a.write("p", "phone_key", buf(N.phone_public)).ok);
  assert.match(a.sas, /^[0-9]{4}$/);
  a.cancel();
  assert.equal(a.sk, null);
  assert.equal(a.keys, null);
  assert.equal(a.sas, null);
});
