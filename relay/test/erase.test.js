// DELETE /chain (Erase everything) and the log (node --test).

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { CLOSE } from "../server.js";
import { toWords } from "../crypto.js";
import { relay, client, chainKeys, connect, device, upload, sendText, receiveItem, sleep, MIB } from "./helpers.js";

test("DELETE /chain erases the queue and closes the chain's connections with 4001", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const other = chainKeys();
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  const bystander = await connect(r, other);
  await sendText(mac, k, "one", 1);
  await sendText(mac, k, "two", 2);
  await sendText(bystander, other, "not mine to erase", 1);
  // An upload in progress is dropped too.
  mac.send({ kind: "item", ref: 3, part: 0, parts: 2, blob: { nonce: "00".repeat(12), enc: randomBytes(528).toString("base64") } });
  await sleep(30);
  assert.equal((await r.health()).items, 3);

  const res = await r.erase(k.P);
  assert.equal(res.status, 204);
  assert.equal(await res.text(), "");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.deepEqual(await mac.closed, { code: CLOSE.erased, reason: "chain erased" });
  assert.deepEqual(await phone.closed, { code: CLOSE.erased, reason: "chain erased" });
  const h = await r.health();
  assert.equal(h.items, 1, "only the other chain's item is left");
  assert.equal(h.chains, 1);
  assert.equal(bystander.ws.readyState, 1);

  // The chain can be used again from scratch: nothing is left of it.
  const again = await connect(r, k);
  assert.notEqual(again.welcome.epoch, mac.welcome.epoch);
  assert.deepEqual(again.backlogItems, []);
  assert.deepEqual(again.synced, { kind: "synced", last: 0 });
  again.ws.close();
  bystander.ws.close();
});

test("DELETE /chain answers 204 even for a chain that does not exist, 400 for a bad proof", async (t) => {
  const r = await relay(t);
  assert.equal((await r.erase(chainKeys().P)).status, 204);
  for (const bad of [undefined, "", "1234", "zz".repeat(16), chainKeys().P.toUpperCase(), chainKeys().P + "0"]) {
    const res = await r.erase(bad);
    assert.equal(res.status, 400, String(bad));
    assert.deepEqual(await res.json(), { error: "X-Clipway-Proof: 32 lowercase hex expected" });
  }
  // The proof is only accepted in its header, never in the URL.
  const k = chainKeys();
  assert.equal((await fetch(`${r.http}/chain?proof=${k.P}`, { method: "DELETE" })).status, 400);
});

test("the log has counters and errors only: no IP, no proof, no full chain id, no content", async (t) => {
  const lines = [];
  const r = await relay(t, { log: (line) => lines.push(line), statsMs: 40, maxTotalBytes: 40 * MIB });
  const k = chainKeys();
  const secretText = "my bank PIN is 4071, do not log this";
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  const sent = await sendText(mac, k, secretText, 1);
  const got = await receiveItem(phone, k);
  phone.send({ kind: "ack", seq: got.seq });
  await mac.next("delivered");
  const offer = upload(phone, k, { type: "offer", device: device("Pixel", "android"), media: "file", mime: "application/pdf", name: "passport-scan.pdf", content: randomBytes(MIB + 7), port: 40000, hosts: ["192.168.1.23"] }, 2);
  await phone.next("stored");
  // Refusals and errors: bad proof, malformed frames, an oversized frame, a rate limit, an erase.
  await assert.rejects(client(r.ws, ["clipway.v1", "clipway.p.nothex"]).opened);
  phone.send({ kind: "nope" });
  await phone.next("error");
  mac.send({ kind: "item", ref: 9, part: 0, parts: 1, blob: { nonce: "00".repeat(12), enc: "A".repeat(256 * 1024) } });
  await mac.closed;
  await r.erase(k.P);
  await phone.closed;
  await sleep(120);
  await r.stop();

  const all = lines.join("\n");
  assert.ok(lines.some((l) => / stats \{/.test(l)), "counters are logged");
  assert.ok(lines.some((l) => /error: connection [0-9a-f]{6} /.test(l)), "errors name the chain by 6 characters");
  const forbidden = {
    proof: k.P,
    "chain id (7 characters or more)": k.id.slice(0, 7),
    "secret S": Buffer.from(k.S).toString("hex"),
    "first word": ` ${toWords(k.S)[0]} `,
    text: secretText,
    "part of the text": "bank PIN",
    "file name": "passport-scan",
    "item id": sent.head.item,
    nonce: sent.envelopes[0].nonce,
    "ciphertext": sent.envelopes[0].enc.slice(0, 24),
    "offer ciphertext": offer.envelopes[0].enc.slice(0, 24),
    "local address in an offer": "192.168.1.23",
    IPv4: "127.0.0.1",
    "IPv6 loopback": "::1",
    "mapped address": "::ffff",
  };
  for (const [what, value] of Object.entries(forbidden)) assert.equal(all.includes(value), false, `the log contains the ${what}`);
  // No long hex run with letters (an id, a proof, a nonce) anywhere.
  assert.doesNotMatch(all, /(?<![0-9a-z])(?=[0-9a-f]*[a-f])[0-9a-f]{7,}(?![0-9a-z])/);
  // Every line is a timestamp, then one of a few known messages.
  for (const l of lines) assert.match(l, /^\d{4}-\d\d-\d\dT[\d:.]+Z (Clipway relay \S+ listening on port \d+|stats \{.*\}|stopping|error: connection [0-9a-f]{6} [A-Z_]+)$/, l);
});
