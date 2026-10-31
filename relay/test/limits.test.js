// Limits, quotas and protocol violations (node --test). Small limits are passed to start() so
// that each case is quick; the defaults are checked against docs/PROTOCOL.md.

import { test } from "node:test";
import assert from "node:assert/strict";
import { LIMITS, CLOSE } from "../server.js";
import { relay, client, chainKeys, connect, device, upload, sendText, fakeBlob, sleep, MIB } from "./helpers.js";

test("default limits match the protocol", () => {
  assert.equal(LIMITS.frame, 128 * 1024);
  assert.equal(LIMITS.parts, 1);
  assert.equal(LIMITS.text, 65_536);
  assert.equal(LIMITS.enc, 117_440);
  assert.equal(LIMITS.items, 50);
  assert.equal(LIMITS.bytes, 6 * MIB);
  assert.equal(LIMITS.ttl, 24 * 3_600_000);
  assert.equal(LIMITS.devices, 8);
  assert.equal(LIMITS.itemsPerMinute, 60);
  assert.equal(LIMITS.bytesPerHour, 60 * MIB);
  assert.equal(LIMITS.uploads, 4);
  assert.equal(LIMITS.uploadBytes, 1 * MIB);
  assert.equal(LIMITS.uploadTimeout, 120_000);
  assert.equal(LIMITS.requestsPerMinute, 60);
  assert.equal(LIMITS.connectionsPerIp, 20);
  assert.equal(LIMITS.connections, 10_000);
  assert.equal(LIMITS.syncTimeout, 10_000);
});

test("a chain keeps its 50 newest items: the oldest are evicted", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  for (let i = 1; i <= 52; i++) await sendText(mac, k, `item ${i}`, i);
  assert.equal((await r.health()).items, 50);
  const phone = await connect(r, k);
  assert.equal(phone.backlogItems.length, 50);
  assert.equal(phone.backlogItems[0].seq, 3);
  assert.equal(phone.backlogItems.at(-1).seq, 52);
  mac.ws.close();
  phone.ws.close();
});

test("a chain keeps 6 MiB at most (here 1500 bytes): the oldest are evicted, a larger item is too big", async (t) => {
  const r = await relay(t, { limits: { bytes: 1500 } });
  const k = chainKeys();
  const mac = await connect(r, k);
  for (let i = 1; i <= 3; i++) await sendText(mac, k, `item ${i}`, i);
  const h = await r.health();
  assert.equal(h.items, 2);
  assert.ok(h.bytes <= 1500);
  const phone = await connect(r, k);
  assert.deepEqual(phone.backlogItems.map((f) => f.seq), [2, 3]);
  upload(mac, k, { type: "text", content: Buffer.from("x".repeat(2000)) }, 9);
  const e = await mac.next("error");
  assert.deepEqual([e.ref, e.code], [9, "too_big"]);
  mac.ws.close();
  phone.ws.close();
});

test("an item in more than one part, or larger than a 64 KiB text, is too big", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const textOnly = "this relay carries texts of 64 KB at most: images and files go directly between your devices";
  for (const [ref, parts] of [[1, 2], [2, 26], [3, 27]]) {
    mac.send({ kind: "item", ref, part: 0, parts, blob: fakeBlob() });
    assert.deepEqual(await mac.next("error"), { kind: "error", ref, code: "too_big", message: textOnly });
  }
  // The largest envelope passes, one more base64 group does not.
  mac.send({ kind: "item", ref: 4, part: 0, parts: 1, blob: { nonce: "00".repeat(12), enc: "A".repeat(LIMITS.enc) } });
  assert.equal((await mac.next("stored")).ref, 4);
  mac.send({ kind: "item", ref: 5, part: 0, parts: 1, blob: { nonce: "00".repeat(12), enc: "A".repeat(LIMITS.enc + 4) } });
  assert.deepEqual(await mac.next("error"), { kind: "error", ref: 5, code: "too_big", message: textOnly });
  assert.equal((await r.health()).items, 1);
  mac.ws.close();
});

test("a frame over 128 KiB closes the connection with 1009", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  mac.send({ kind: "item", ref: 1, part: 0, parts: 1, blob: { nonce: "00".repeat(12), enc: "A".repeat(128 * 1024) } });
  assert.equal((await mac.closed).code, 1009);
});

test("8 connections per chain, then 429", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const open = [];
  for (let i = 0; i < 8; i++) {
    const c = client(r.ws, k.protocols);
    await c.opened;
    open.push(c);
  }
  await assert.rejects(client(r.ws, k.protocols).opened, (e) => e.status === 429);
  // Another chain is not affected.
  const other = client(r.ws, chainKeys().protocols);
  await other.opened;
  for (const c of [...open, other]) c.ws.close();
});

test("open WebSockets per IP, in total, and chains held are limited", async (t) => {
  const perIp = await relay(t, { limits: { connectionsPerIp: 2 } });
  const a = client(perIp.ws, chainKeys().protocols);
  const b = client(perIp.ws, chainKeys().protocols);
  await Promise.all([a.opened, b.opened]);
  await assert.rejects(client(perIp.ws, chainKeys().protocols).opened, (e) => e.status === 429);
  a.ws.close();
  await a.closed;
  await sleep(20);
  const c = client(perIp.ws, chainKeys().protocols);
  await c.opened;
  b.ws.close();
  c.ws.close();

  const total = await relay(t, { limits: { connections: 1 } });
  const d = client(total.ws, chainKeys().protocols);
  await d.opened;
  await assert.rejects(client(total.ws, chainKeys().protocols).opened, (e) => e.status === 503);
  d.ws.close();

  const chains = await relay(t, { limits: { chains: 1 } });
  const k = chainKeys();
  const e = client(chains.ws, k.protocols);
  await e.opened;
  await assert.rejects(client(chains.ws, chainKeys().protocols).opened, (x) => x.status === 503);
  const f = client(chains.ws, k.protocols);
  await f.opened;
  e.ws.close();
  f.ws.close();
});

test("60 requests per minute per IP, upgrades included", async (t) => {
  const r = await relay(t, { limits: { requestsPerMinute: 3 } });
  const k = chainKeys();
  const a = client(r.ws, k.protocols);
  await a.opened;
  assert.equal((await fetch(`${r.http}/health`)).status, 200);
  assert.equal((await fetch(`${r.http}/nothing`)).status, 404);
  const res = await fetch(`${r.http}/health`);
  assert.equal(res.status, 429);
  assert.deepEqual(await res.json(), { error: "too many requests, try again in a minute" });
  await assert.rejects(client(r.ws, k.protocols).opened, (e) => e.status === 429);
  assert.equal((await r.erase(k.P)).status, 429);
  a.ws.close();
});

test("items per minute and bytes per hour of a chain are rate limited", async (t) => {
  const r = await relay(t, { limits: { itemsPerMinute: 2 } });
  const k = chainKeys();
  const mac = await connect(r, k);
  await sendText(mac, k, "one", 1);
  await sendText(mac, k, "two", 2);
  upload(mac, k, { type: "text", content: Buffer.from("three") }, 3);
  const e = await mac.next("error");
  assert.deepEqual([e.ref, e.code], [3, "rate_limited"]);
  // The limit is per chain: another connection of the chain is limited too.
  const phone = await connect(r, k);
  upload(phone, k, { type: "text", content: Buffer.from("four") }, 1);
  assert.equal((await phone.next("error")).code, "rate_limited");
  mac.ws.close();
  phone.ws.close();

  const r2 = await relay(t, { limits: { bytesPerHour: 1000 } });
  const mac2 = await connect(r2, k);
  await sendText(mac2, k, "first", 1);
  upload(mac2, k, { type: "text", content: Buffer.from("second") }, 2);
  const e2 = await mac2.next("error");
  assert.deepEqual([e2.ref, e2.code], [2, "rate_limited"]);
  mac2.ws.close();
});

test("4 uploads in progress and 1 MiB in progress per connection (quota)", async (t) => {
  // Uploads stay in progress only for items in several parts: allowed here to check the quota.
  const r = await relay(t, { limits: { uploads: 2, parts: 2 } });
  const k = chainKeys();
  const mac = await connect(r, k);
  mac.send({ kind: "item", ref: 1, part: 0, parts: 2, blob: fakeBlob() });
  mac.send({ kind: "item", ref: 2, part: 0, parts: 2, blob: fakeBlob() });
  mac.send({ kind: "item", ref: 3, part: 0, parts: 2, blob: fakeBlob() });
  const e = await mac.next("error");
  assert.deepEqual([e.ref, e.code], [3, "quota"]);
  // Finishing one makes room.
  mac.send({ kind: "item", ref: 1, part: 1, parts: 2, blob: fakeBlob() });
  assert.deepEqual(await mac.next("stored"), { kind: "stored", ref: 1, seq: 1 });
  mac.send({ kind: "item", ref: 3, part: 0, parts: 2, blob: fakeBlob() });
  await sleep(50);
  assert.deepEqual(mac.drain("error"), []);
  mac.ws.close();

  const r2 = await relay(t, { limits: { uploadBytes: 600, parts: 2 } });
  const mac2 = await connect(r2, k);
  mac2.send({ kind: "item", ref: 1, part: 0, parts: 2, blob: fakeBlob(528) });
  mac2.send({ kind: "item", ref: 2, part: 0, parts: 2, blob: fakeBlob(528) });
  const e2 = await mac2.next("error");
  assert.deepEqual([e2.ref, e2.code], [2, "quota"]);
  mac2.ws.close();
});

test("when the relay's memory is full, new uploads are busy until room is made", async (t) => {
  const r = await relay(t, { maxTotalBytes: 1000 });
  const k = chainKeys();
  const mac = await connect(r, k);
  await sendText(mac, k, "fits", 1);
  upload(mac, k, { type: "text", content: Buffer.from("does not fit") }, 2);
  const e = await mac.next("error");
  assert.deepEqual([e.ref, e.code], [2, "busy"]);
  const phone = await connect(r, k);
  phone.send({ kind: "ack", seq: 1 });
  await mac.next("delivered");
  await sendText(mac, k, "fits now", 3);
  mac.ws.close();
  phone.ws.close();
});

test("an upload that never completes is dropped (incomplete), and its memory is freed", async (t) => {
  const r = await relay(t, { maxTotalBytes: 1000, limits: { uploadTimeout: 150, parts: 2 } });
  const k = chainKeys();
  const mac = await connect(r, k);
  mac.send({ kind: "item", ref: 5, part: 0, parts: 2, blob: fakeBlob(528) });
  const e = await mac.next("error");
  assert.deepEqual(e, { kind: "error", ref: 5, code: "incomplete", message: "upload not completed in time" });
  mac.send({ kind: "item", ref: 5, part: 1, parts: 2, blob: fakeBlob(528) });
  assert.equal((await mac.next("error")).code, "bad_request");
  // An upload in progress when its connection closes is dropped too.
  mac.send({ kind: "item", ref: 6, part: 0, parts: 2, blob: fakeBlob(528) });
  await sleep(30);
  mac.ws.close();
  await mac.closed;
  await sleep(30);
  const mac2 = await connect(r, k);
  await sendText(mac2, k, "room again");
  assert.equal((await r.health()).items, 1);
  mac2.ws.close();
});

test("malformed frames get bad_request, and the upload concerned is dropped", async (t) => {
  // More malformed frames than the default tolerance (10) are sent on purpose.
  const r = await relay(t, { limits: { badFrames: 100, parts: 4 } });
  const k = chainKeys();
  const mac = await connect(r, k);
  const expectBad = async (frame, ref = null) => {
    mac.send(frame);
    const e = await mac.next("error");
    assert.equal(e.code, "bad_request", JSON.stringify(frame).slice(0, 80));
    assert.equal(e.ref, ref);
    assert.equal(typeof e.message, "string");
  };
  await expectBad({ kind: "nope" });
  await expectBad({ kind: "ack", seq: 0 });
  await expectBad({ kind: "ack", seq: "1" });
  await expectBad({ kind: "item", ref: -1, part: 0, parts: 1, blob: fakeBlob() });
  await expectBad({ kind: "item", ref: 2 ** 31, part: 0, parts: 1, blob: fakeBlob() });
  await expectBad({ kind: "item", ref: 1, part: 0, parts: 0, blob: fakeBlob() }, 1);
  await expectBad({ kind: "item", ref: 1, part: 1, parts: 1, blob: fakeBlob() }, 1);
  await expectBad({ kind: "item", ref: 1, part: 0, parts: 1, blob: { nonce: "zz", enc: "AAAA" } }, 1);
  await expectBad({ kind: "item", ref: 1, part: 0, parts: 1, blob: { nonce: "00".repeat(12), enc: "not base64!" } }, 1);
  await expectBad({ kind: "item", ref: 1, part: 0, parts: 1 }, 1);
  await expectBad({ kind: "sync", epoch: "", after: 0 });
  // Part 1 without part 0, parts changing, parts out of order, a ref started twice.
  await expectBad({ kind: "item", ref: 1, part: 1, parts: 3, blob: fakeBlob() }, 1);
  mac.send({ kind: "item", ref: 1, part: 0, parts: 3, blob: fakeBlob() });
  await expectBad({ kind: "item", ref: 1, part: 1, parts: 4, blob: fakeBlob() }, 1);
  await expectBad({ kind: "item", ref: 1, part: 1, parts: 3, blob: fakeBlob() }, 1);
  mac.send({ kind: "item", ref: 1, part: 0, parts: 3, blob: fakeBlob() });
  await expectBad({ kind: "item", ref: 1, part: 2, parts: 3, blob: fakeBlob() }, 1);
  mac.send({ kind: "item", ref: 1, part: 0, parts: 3, blob: fakeBlob() });
  await expectBad({ kind: "item", ref: 1, part: 0, parts: 3, blob: fakeBlob() }, 1);
  // Text frames that are not JSON objects.
  mac.ws.send("[1,2]");
  assert.equal((await mac.next("error")).code, "bad_request");
  mac.send({ kind: "ping" });
  assert.deepEqual(await mac.next("pong"), { kind: "pong" });
  mac.ws.close();
});

test("protocol violations close the connection with 4002, a missing sync with 4003", async (t) => {
  const r = await relay(t, { limits: { syncTimeout: 150, badFrames: 3 } });
  const k = chainKeys();

  const first = client(r.ws, k.protocols);
  await first.opened;
  await first.next("welcome");
  first.send({ kind: "ping" });
  assert.deepEqual(await first.closed, { code: CLOSE.protocol, reason: "sync expected first" });

  const garbage = client(r.ws, k.protocols);
  await garbage.opened;
  garbage.ws.send("not json");
  assert.equal((await garbage.closed).code, CLOSE.protocol);

  const binary = await connect(r, k);
  binary.ws.send(Buffer.from([1, 2, 3]));
  assert.deepEqual(await binary.closed, { code: CLOSE.protocol, reason: "binary frames are not accepted" });

  const repeated = await connect(r, k);
  for (let i = 0; i < 3; i++) repeated.send({ kind: "nope" });
  assert.deepEqual(await repeated.closed, { code: CLOSE.protocol, reason: "too many malformed frames" });

  const silent = client(r.ws, k.protocols);
  await silent.opened;
  await silent.next("welcome");
  assert.deepEqual(await silent.closed, { code: CLOSE.syncTimeout, reason: "sync expected" });

  // A malformed sync is answered, and a correct one can follow in time.
  const fixes = client(r.ws, k.protocols);
  await fixes.opened;
  await fixes.next("welcome");
  fixes.send({ kind: "sync", epoch: "XYZ", after: 0 });
  assert.equal((await fixes.next("error")).code, "bad_request");
  fixes.send({ kind: "sync", epoch: "", after: 0 });
  assert.equal((await fixes.next("synced")).kind, "synced");
  await sleep(250);
  assert.equal(fixes.ws.readyState, 1, "still open after the sync timeout");
  fixes.ws.close();
});

test("nothing is accepted before sync: an item sent first closes the connection", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const early = client(r.ws, k.protocols);
  await early.opened;
  await early.next("welcome");
  upload(early, k, { type: "text", device: device(), content: Buffer.from("too early") });
  assert.equal((await early.closed).code, CLOSE.protocol);
  assert.equal((await r.health()).items, 0);
});
