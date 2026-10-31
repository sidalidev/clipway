// End-to-end flows through the relay (node --test): pairing, a text from the Mac to the phone,
// texts only (images, files and chunks are refused), the queue for an offline device, expiry,
// acks and epochs. The devices use the
// reference cryptography (crypto.js): the relay only ever sees envelopes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { relay, client, chainKeys, connect, device, upload, sendText, receiveItem, backlog, sleep, MIB } from "./helpers.js";

test("pairing: the phone's hello reaches the Mac, which learns its name", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  assert.equal(mac.welcome.devices, 1);
  const phone = await connect(r, k);
  assert.equal(phone.welcome.devices, 2);
  assert.deepEqual(await mac.next("presence"), { kind: "presence", devices: 2 });

  const pixel = device("Pixel 10 Pro", "android");
  upload(phone, k, { type: "hello", device: pixel }, 7);
  assert.deepEqual(await phone.next("stored"), { kind: "stored", ref: 7, seq: 1 });
  const got = await receiveItem(mac, k);
  assert.equal(got.seq, 1);
  assert.equal(got.frames[0].parts, 1);
  assert.equal(got.head.type, "hello");
  assert.deepEqual(got.head.device, pixel);
  assert.equal(got.content, null);
  mac.send({ kind: "ack", seq: 1 });
  assert.deepEqual(await phone.next("delivered"), { kind: "delivered", seq: 1 });
  assert.equal((await r.health()).items, 0);
  mac.ws.close();
  phone.ws.close();
});

test("a text goes from the Mac to the phone, end to end; the relay only sees an envelope", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  const text = "Copied on the Mac: café ☕ 👋";
  const before = Date.now();
  const sent = await sendText(mac, k, text, 42);
  assert.deepEqual(sent.stored, { kind: "stored", ref: 42, seq: 1 });
  const got = await receiveItem(phone, k);
  assert.equal(got.head.type, "text");
  assert.equal(got.content.toString("utf8"), text);
  assert.equal(got.head.item, sent.head.item);
  assert.ok(got.ts >= before && got.ts <= Date.now(), "ts is the relay's receive time");
  const frame = got.frames[0];
  assert.deepEqual(Object.keys(frame).sort(), ["blob", "kind", "part", "parts", "seq", "ts"]);
  assert.deepEqual(Object.keys(frame.blob).sort(), ["enc", "nonce"]);
  assert.equal(JSON.stringify(frame).includes("café"), false);
  // The head is padded to a multiple of 512 bytes: the relay cannot tell a short text's length.
  assert.equal((Buffer.from(frame.blob.enc, "base64").length - 16) % 512, 0);
  // The sender is not sent its own item back.
  assert.deepEqual(mac.drain("item"), []);
  phone.send({ kind: "ack", seq: 1 });
  assert.deepEqual(await mac.next("delivered"), { kind: "delivered", seq: 1 });
  // And the other way round.
  await sendText(phone, k, "From the phone", 1, device("Pixel", "android"));
  const back = await receiveItem(mac, k);
  assert.equal(back.seq, 2);
  assert.equal(back.content.toString(), "From the phone");
  mac.ws.close();
  phone.ws.close();
});

test("texts only: the largest text passes, anything in parts or larger is refused", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  const { buildItem, TEXT_MAX, ENC_MAX } = await import("../crypto.js");
  // A 64 KiB text: one envelope, under the relay's limit.
  const largest = "z".repeat(TEXT_MAX);
  const sent = await sendText(mac, k, largest, 1);
  assert.ok(sent.envelopes[0].enc.length <= ENC_MAX);
  assert.equal((await receiveItem(phone, k)).content.toString(), largest);
  // An item in two parts (how images and files used to travel): too big, and nothing reaches the phone.
  const offer = buildItem(k.S, { type: "text", device: device(), ts: Date.now(), content: Buffer.from("part") });
  mac.send({ kind: "item", ref: 2, part: 0, parts: 2, blob: offer.envelopes[0] });
  const e = await mac.next("error");
  assert.deepEqual([e.ref, e.code], [2, "too_big"]);
  assert.match(e.message, /images and files go directly/);
  // One envelope larger than a 64 KiB text: too big.
  mac.send({ kind: "item", ref: 3, part: 0, parts: 1, blob: { nonce: "00".repeat(12), enc: "A".repeat(ENC_MAX + 4) } });
  assert.deepEqual((({ ref, code }) => [ref, code])(await mac.next("error")), [3, "too_big"]);
  await sleep(50);
  assert.deepEqual(phone.drain("item"), []);
  assert.equal((await r.health()).items, 1);
  mac.ws.close();
  phone.ws.close();
});

test("an offer and its reply are ordinary items for the relay, padded like a short text", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  const content = randomBytes(5 * MIB);
  const offer = upload(phone, k, { type: "offer", device: device("Pixel", "android"), media: "image", mime: "image/jpeg", name: "IMG_0042.jpg", content, port: 41234, hosts: ["192.168.1.23"] }, 1);
  await phone.next("stored");
  const got = await receiveItem(mac, k);
  assert.equal(got.head.type, "offer");
  assert.equal(got.head.size, 5 * MIB);
  assert.equal(got.content, null);
  // 5 MiB offered, 512 bytes carried: the content never reaches the relay.
  assert.equal(Buffer.from(got.frames[0].blob.enc, "base64").length - 16, 512);
  assert.equal(JSON.stringify(got.frames[0]).includes("IMG_0042"), false);
  mac.send({ kind: "ack", seq: got.seq });
  upload(mac, k, { type: "reply", device: device(), offer: offer.head.item, status: "unreachable" }, 1);
  await mac.next("stored");
  const answer = await receiveItem(phone, k);
  assert.deepEqual([answer.head.type, answer.head.offer, answer.head.status], ["reply", offer.head.item, "unreachable"]);
  mac.ws.close();
  phone.ws.close();
});

test("an offline phone gets the queue when it comes back, then only what is new", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  for (const [i, text] of ["one", "two", "three"].entries()) await sendText(mac, k, text, i + 1);
  assert.equal((await r.health()).items, 3);

  const phone = await connect(r, k);
  assert.deepEqual(phone.synced, { kind: "synced", last: 3 });
  assert.deepEqual(phone.backlogItems.map((f) => f.seq), [1, 2, 3]);
  const epoch = phone.welcome.epoch;
  phone.send({ kind: "ack", seq: 1 });
  phone.send({ kind: "ack", seq: 2 });
  assert.deepEqual(await mac.next("delivered"), { kind: "delivered", seq: 1 });
  assert.deepEqual(await mac.next("delivered"), { kind: "delivered", seq: 2 });
  phone.ws.close();
  await phone.closed;

  // Same epoch, after = 2: only item 3, which was not acknowledged.
  const again = await connect(r, k, { epoch, after: 2 });
  assert.deepEqual(again.backlogItems.map((f) => f.seq), [3]);
  assert.deepEqual(again.synced, { kind: "synced", last: 3 });
  again.ws.close();
  await again.closed;
  // Same epoch, after = 3: nothing.
  const nothing = await connect(r, k, { epoch, after: 3 });
  assert.deepEqual(nothing.backlogItems, []);
  nothing.ws.close();
  await nothing.closed;
  // Another epoch: everything still queued, whatever after says.
  const other = await connect(r, k, { epoch: "0000000000000000", after: 99 });
  assert.deepEqual(other.backlogItems.map((f) => f.seq), [3]);
  const [frame] = other.backlogItems;
  assert.equal((await import("../crypto.js")).readItem(k.S, [frame.blob]).content.toString(), "three");
  other.send({ kind: "ack", seq: 3 });
  assert.deepEqual(await mac.next("delivered"), { kind: "delivered", seq: 3 });
  assert.equal((await r.health()).items, 0);
  mac.ws.close();
  other.ws.close();
});

test("items stored before a device syncs come once, in its backlog", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const phone = client(r.ws, k.protocols);
  await phone.opened;
  await phone.next("welcome");
  await sendText(mac, k, "before sync");
  await sleep(50);
  assert.deepEqual(phone.drain("item"), [], "nothing before sync");
  phone.send({ kind: "sync", epoch: "", after: 0 });
  const { items, synced } = await backlog(phone);
  assert.deepEqual(items.map((f) => f.seq), [1]);
  assert.equal(synced.last, 1);
  await sleep(100);
  assert.deepEqual(phone.drain("item"), [], "never twice");
  mac.ws.close();
  phone.ws.close();
});

test("an item expires after the retention time, and the queue is emptied", async (t) => {
  const r = await relay(t, { ttlMs: 300, sweepMs: 50 });
  const k = chainKeys();
  const mac = await connect(r, k);
  assert.equal(mac.welcome.limits.ttl, 300);
  await sendText(mac, k, "short lived");
  assert.equal((await r.health()).items, 1);
  await sleep(500);
  const h = await r.health();
  assert.equal(h.items, 0);
  assert.equal(h.bytes, 0);
  const phone = await connect(r, k);
  assert.deepEqual(phone.backlogItems, []);
  assert.equal(phone.synced.last, 1, "seq keeps counting");
  mac.ws.close();
  phone.ws.close();
  await phone.closed;
  await mac.closed;
  await sleep(100);
  assert.equal((await r.health()).chains, 0, "an empty chain is forgotten");
});

test("the uploader's own ack does not delete its item; another connection's ack does", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  await sendText(mac, k, "mine");
  mac.send({ kind: "ack", seq: 1 });
  mac.send({ kind: "ack", seq: 999 });
  await sleep(50);
  assert.equal((await r.health()).items, 1);
  assert.deepEqual(mac.drain("delivered"), []);
  assert.deepEqual(mac.drain("error"), []);
  const phone = await connect(r, k);
  assert.deepEqual(phone.backlogItems.map((f) => f.seq), [1]);
  phone.send({ kind: "ack", seq: 1 });
  phone.send({ kind: "ack", seq: 1 });
  assert.deepEqual(await mac.next("delivered"), { kind: "delivered", seq: 1 });
  await sleep(50);
  assert.deepEqual(mac.drain("delivered"), [], "delivered once");
  assert.equal((await r.health()).items, 0);
  mac.ws.close();
  phone.ws.close();
});

test("a reconnected sender gets no delivered for an item of its previous connection, but the item is still delivered", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  await sendText(mac, k, "sent, then the Mac slept");
  mac.ws.close();
  await mac.closed;
  const mac2 = await connect(r, k, { epoch: mac.welcome.epoch, after: 1 });
  const phone = await connect(r, k);
  assert.deepEqual(phone.backlogItems.map((f) => f.seq), [1]);
  phone.send({ kind: "ack", seq: 1 });
  await sleep(50);
  assert.deepEqual(mac2.drain("delivered"), []);
  assert.equal((await r.health()).items, 0);
  mac2.ws.close();
  phone.ws.close();
});

test("a chain the relay forgot comes back with a new epoch, so no device skips new items", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  await sendText(mac, k, "first");
  await receiveItem(phone, k);
  phone.send({ kind: "ack", seq: 1 });
  await mac.next("delivered");
  const old = { epoch: phone.welcome.epoch, after: 1 };
  mac.ws.close();
  phone.ws.close();
  await Promise.all([mac.closed, phone.closed]);
  await sleep(50);
  assert.equal((await r.health()).chains, 0);

  // Numbering starts over for this chain: the epoch changes with it.
  const mac2 = await connect(r, k);
  assert.notEqual(mac2.welcome.epoch, old.epoch);
  const sent = await sendText(mac2, k, "after the relay forgot");
  assert.equal(sent.stored.seq, 1);
  // The phone still holds (old epoch, after = 1): it gets the new item 1 all the same.
  const phone2 = await connect(r, k, old);
  assert.deepEqual(phone2.backlogItems.map((f) => f.seq), [1]);
  mac2.ws.close();
  phone2.ws.close();
});

test("an item goes to every other synced connection of the chain", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const mac = await connect(r, k);
  const phone = await connect(r, k);
  const tablet = await connect(r, k);
  await sendText(mac, k, "to everyone");
  assert.equal((await receiveItem(phone, k)).content.toString(), "to everyone");
  assert.equal((await receiveItem(tablet, k)).content.toString(), "to everyone");
  mac.ws.close();
  phone.ws.close();
  tablet.ws.close();
});
