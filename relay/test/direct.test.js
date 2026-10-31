// Direct transfer of images and files (docs/PROTOCOL.md, section 14): direct.js against
// docs/VECTORS.json, then a real sender and receiver on the loopback interface.

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import * as direct from "../direct.js";
import { generateSecret, deriveKeys, fingerprint, FILE_MAX } from "../crypto.js";

const V = JSON.parse(readFileSync(new URL("../../docs/VECTORS.json", import.meta.url), "utf8"));
const D = V.direct;
const sha256 = (d) => createHash("sha256").update(d).digest("hex");
const content = () => {
  const b = Buffer.alloc(D.size);
  for (let i = 0; i < D.size; i++) b[i] = i % 251;
  return b;
};

test("vectors: keys, preamble and records", () => {
  const kDirect = direct.directKey(V.S);
  assert.equal(kDirect.toString("hex"), D.K_direct);
  const kT = direct.transferKey(kDirect, D.transfer);
  assert.equal(kT.toString("hex"), D.K_t);
  assert.equal(direct.preamble(D.transfer).toString("hex"), D.preamble);
  assert.equal(direct.readPreamble(Buffer.from(D.preamble, "hex")), D.transfer);
  assert.equal(direct.readPreamble(Buffer.from("CWD2" + "00".repeat(16), "latin1")), null);
  assert.equal(D.transfer, V.offer_file_item.head.item);
  const body = sha256(content());
  assert.equal(body, D.content_sha256);

  const get0 = direct.sealRecord(kT, D.transfer, "get", 0, direct.getRequest(D.transfer), Buffer.from(D.get0.nonce, "hex"));
  assert.equal(get0.toString("hex"), D.get0.bytes);
  assert.equal(direct.openRecord(kT, D.transfer, "get", 0, get0.subarray(4)).toString(), D.get0.plaintext_utf8);
  const data = content();
  D.puts.forEach((r, i) => {
    const plain = data.subarray(i * D.record_data, Math.min(D.size, (i + 1) * D.record_data));
    const bytes = direct.sealRecord(kT, D.transfer, "put", i, plain, Buffer.from(r.nonce, "hex"));
    assert.equal(bytes.length, r.length);
    assert.equal(sha256(bytes), r.sha256);
    if (i === 0) assert.equal(bytes.subarray(0, 64).toString("hex"), D.put0_head);
  });
  assert.equal(direct.recordCount(D.size), D.puts.length);
  const last = Buffer.from(D.put_last.bytes, "hex");
  assert.equal(direct.openRecord(kT, D.transfer, "put", D.put_last.index, last.subarray(4)).length, D.puts.at(-1).plaintext_bytes);
  assert.equal(direct.openRecord(kT, D.transfer, "get", 1, Buffer.from(D.get1.bytes, "hex").subarray(4)).toString(), D.get1.plaintext_utf8);

  const g = Buffer.from(D.get0.bytes, "hex").subarray(4);
  assert.throws(() => direct.openRecord(kT, D.transfer, "put", 0, g), /authentication/);
  assert.throws(() => direct.openRecord(kT, D.transfer, "get", 1, g), /authentication/);
  const other = V.offer_item.head.item;
  assert.throws(() => direct.openRecord(direct.transferKey(kDirect, other), other, "get", 0, g), /authentication/);
  assert.throws(() => direct.openRecord(kT, D.transfer, "get", 0, Buffer.from(D.negative.tampered_get0, "hex").subarray(4)), /authentication/);
});

test("only addresses of the local network", () => {
  for (const h of D.private_hosts.allowed) assert.equal(direct.isPrivateIPv4(h), true, h);
  for (const h of D.private_hosts.refused) assert.equal(direct.isPrivateIPv4(h), false, h);
  assert.equal(direct.mayConnect("127.0.0.1"), false);
  assert.equal(direct.mayConnect("127.0.0.1", { loopback: true }), true);
  for (const h of direct.localHosts()) assert.equal(direct.isPrivateIPv4(h), true);
});

async function pair(t, size = 300_000) {
  const S = generateSecret();
  const sender = await direct.startSender({ S, host: "127.0.0.1", hosts: ["127.0.0.1"] });
  t.after(() => sender.close());
  const data = randomBytes(size);
  const item = randomBytes(16).toString("hex");
  const offered = sender.offer(item, data);
  const head = { item, size: data.length, fp: fingerprint(deriveKeys(S).mac, data), port: offered.port, hosts: offered.hosts };
  return { S, sender, data, item, offered, head };
}

test("a file goes from sender to receiver, once, and the sender hears it was saved", async (t) => {
  const { S, data, offered, head } = await pair(t, 2_000_003);
  let saved = null;
  const r = await direct.fetchOffer({ S, head, loopback: true, save: async (c) => (saved = c) });
  assert.equal(r.ok, true);
  assert.ok(saved.equals(data));
  assert.equal(await offered.outcome, "done");
  // The transfer is spent: a second fetch gets nothing.
  const again = await direct.fetchOffer({ S, head, loopback: true });
  assert.deepEqual(again, { ok: false, reason: "failed" });
});

test("an empty file, and the largest one", async (t) => {
  const small = await pair(t, 0);
  const r = await direct.fetchOffer({ S: small.S, head: small.head, loopback: true });
  assert.equal(r.ok, true);
  assert.equal(r.content.length, 0);
  const big = await pair(t, FILE_MAX);
  const b = await direct.fetchOffer({ S: big.S, head: big.head, loopback: true });
  assert.ok(b.ok && b.content.equals(big.data));
  assert.equal(await big.offered.outcome, "done");
});

test("without the chain key, a connection gets nothing; the real receiver still can", async (t) => {
  const { S, head, data, offered } = await pair(t);
  const stranger = await direct.fetchOffer({ S: generateSecret(), head, loopback: true });
  assert.deepEqual(stranger, { ok: false, reason: "failed" });
  // A raw connection that only sends garbage is closed.
  const raw = net.connect({ host: "127.0.0.1", port: head.port });
  raw.write(Buffer.concat([direct.preamble(head.item), Buffer.from([0, 0, 0, 40]), randomBytes(40)]));
  await new Promise((resolve) => raw.once("close", resolve));
  const r = await direct.fetchOffer({ S, head, loopback: true });
  assert.ok(r.ok && r.content.equals(data));
  assert.equal(await offered.outcome, "done");
});

test("a wrong fingerprint is refused before anything is saved", async (t) => {
  const { S, head, offered } = await pair(t);
  let saved = false;
  const r = await direct.fetchOffer({ S, head: { ...head, fp: "0".repeat(32) }, loopback: true, save: async () => (saved = true) });
  assert.deepEqual(r, { ok: false, reason: "failed" });
  assert.equal(saved, false);
  assert.equal(await offered.outcome, "failed");
});

test("nobody listening, or only addresses outside the local network: unreachable", async (t) => {
  const { S, head } = await pair(t);
  assert.deepEqual(await direct.fetchOffer({ S, head }), { ok: false, reason: "unreachable" });
  assert.deepEqual(await direct.fetchOffer({ S, head: { ...head, hosts: ["8.8.8.8", "203.0.113.5"] }, loopback: true }), { ok: false, reason: "unreachable" });
});

test("an offer nobody fetches expires, and a reply can stop it earlier", async (t) => {
  const S = generateSecret();
  const sender = await direct.startSender({ S, host: "127.0.0.1", hosts: ["127.0.0.1"], ttlMs: 100 });
  t.after(() => sender.close());
  const a = sender.offer(randomBytes(16).toString("hex"), Buffer.from("a"));
  assert.equal(await a.outcome, "expired");
  const item = randomBytes(16).toString("hex");
  const b = sender.offer(item, Buffer.from("b"));
  sender.cancel(item, "unreachable");
  assert.equal(await b.outcome, "unreachable");
});
