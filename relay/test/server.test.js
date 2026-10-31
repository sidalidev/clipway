// Relay basics (node --test): HTTP routes, the handshake authenticated by the proof, welcome,
// sync, presence, ping and the per-IP key. Each test starts its own relay on a free port.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import WebSocket from "ws";
import { start, ipKey, identify, idFromHexProof, SUBPROTOCOL, LIMITS, CLOSE } from "../server.js";
import { relay, client, chainKeys } from "./helpers.js";

const V = JSON.parse(readFileSync(new URL("../../docs/VECTORS.json", import.meta.url), "utf8"));

test("health, well-known files, security headers and 404", async (t) => {
  const r = await relay(t);
  const res = await fetch(`${r.http}/health`);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
  assert.match(res.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal(res.headers.get("access-control-allow-origin"), null);
  const h = await res.json();
  assert.deepEqual(Object.keys(h).sort(), ["bytes", "chains", "connections", "items", "ok", "uptime", "version"]);
  assert.equal(h.ok, true);
  assert.equal(h.connections, 0);
  const wk = await fetch(`${r.http}/.well-known/clipway-relay.json`);
  assert.match(wk.headers.get("cache-control"), /max-age=300/);
  const w = await wk.json();
  assert.equal(w.protocol, 1);
  assert.equal(w.status, "ok");
  assert.deepEqual(w.minClient, { android: "0.3.0", mac: "0.3.0" });
  assert.deepEqual(w.limits, { frame: 131072, parts: 1, text: 65536, enc: 117440, items: 50, bytes: 6291456, ttl: 86400000 });
  const sec = await (await fetch(`${r.http}/.well-known/security.txt`)).text();
  assert.match(sec, /^Contact: mailto:/);
  assert.match(sec, /\nExpires: \d{4}-/);
  for (const [method, p] of [["GET", "/nothing"], ["POST", "/health"], ["GET", "/chain"], ["PUT", "/chain"]]) {
    const x = await fetch(`${r.http}${p}`, { method });
    assert.equal(x.status, 404, `${method} ${p}`);
    assert.deepEqual(await x.json(), { error: "not found" });
  }
  assert.equal((await fetch(`${r.http}/ws`)).status, 426);
});

test("a device without a valid proof or subprotocol is refused with 400", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  await assert.rejects(client(r.ws, [SUBPROTOCOL]).opened, (e) => e.status === 400);
  await assert.rejects(client(r.ws, [SUBPROTOCOL, "clipway.p.1234"]).opened, (e) => e.status === 400);
  await assert.rejects(client(r.ws, [SUBPROTOCOL, `clipway.p.${k.P.toUpperCase()}`]).opened, (e) => e.status === 400);
  await assert.rejects(client(r.ws, ["sonne.v2", `clipway.p.${k.P}`]).opened, (e) => e.status === 400);
  await assert.rejects(client(r.ws, [`clipway.p.${k.P}`]).opened, (e) => e.status === 400);
  await assert.rejects(client(`ws://127.0.0.1:${r.port}/other`, k.protocols).opened, (e) => e.status === 404);
  assert.equal((await r.health()).connections, 0);
});

test("a wrong proof opens another, empty chain: it never sees the items of the real one", async (t) => {
  const r = await relay(t);
  const real = chainKeys();
  const wrong = chainKeys();
  const a = client(r.ws, real.protocols);
  await a.opened;
  await a.next("welcome");
  a.send({ kind: "sync", epoch: "", after: 0 });
  await a.next("synced");
  const b = client(r.ws, wrong.protocols);
  await b.opened;
  const w = await b.next("welcome");
  assert.equal(w.devices, 1);
  b.send({ kind: "sync", epoch: "", after: 0 });
  assert.deepEqual(await b.next("synced"), { kind: "synced", last: 0 });
  // The chain id is not a credential: presented as a proof, it leads to yet another chain.
  const c = client(r.ws, [SUBPROTOCOL, `clipway.p.${real.id}`]);
  await c.opened;
  assert.equal((await c.next("welcome")).devices, 1);
  assert.equal((await r.health()).chains, 3);
  a.ws.close();
  b.ws.close();
  c.ws.close();
});

test("welcome, sync, presence and ping", async (t) => {
  const r = await relay(t);
  const a = client(r.ws, [SUBPROTOCOL, `clipway.p.${V.P}`]);
  await a.opened;
  assert.equal(a.ws.protocol, SUBPROTOCOL);
  const w = await a.next("welcome");
  assert.equal(w.v, 1);
  assert.equal(w.epoch, r.epoch);
  assert.match(w.epoch, /^[0-9a-f]{16}$/);
  assert.equal(w.devices, 1);
  assert.equal(w.limits.frame, LIMITS.frame);
  a.send({ kind: "sync", epoch: "", after: 0 });
  assert.deepEqual(await a.next("synced"), { kind: "synced", last: 0 });
  a.send({ kind: "ping" });
  assert.deepEqual(await a.next("pong"), { kind: "pong" });

  const b = client(r.ws, [SUBPROTOCOL, `clipway.p.${V.P}`]);
  await b.opened;
  assert.equal((await b.next("welcome")).devices, 2);
  assert.deepEqual(await a.next("presence"), { kind: "presence", devices: 1 });
  assert.deepEqual(await a.next("presence"), { kind: "presence", devices: 2 });
  b.ws.close();
  assert.deepEqual(await a.next("presence"), { kind: "presence", devices: 1 });
  a.ws.close();
});

test("protocol pings, and a silent connection is cut", async (t) => {
  const r = await relay(t, { pingMs: 50, deadMs: 400 });
  const k = chainKeys();
  // A device that answers pings stays connected.
  const a = client(r.ws, k.protocols);
  let pings = 0;
  a.ws.on("ping", () => (pings += 1));
  await a.opened;
  await a.next("welcome");
  a.send({ kind: "sync", epoch: "", after: 0 });
  await a.next("synced");
  // A device that never answers (no pong, no frame) is cut after deadMs.
  const mute = new WebSocket(r.ws, k.protocols, { autoPong: false });
  const cut = new Promise((done) => mute.once("close", (code) => done(code)));
  await new Promise((done) => mute.once("open", done));
  mute.send(JSON.stringify({ kind: "sync", epoch: "", after: 0 }));
  const began = Date.now();
  assert.equal(await cut, 1006);
  assert.ok(Date.now() - began >= 300, "not cut before deadMs");
  assert.ok(pings >= 2, `pings: ${pings}`);
  assert.equal(a.ws.readyState, WebSocket.OPEN);
  a.ws.close();
});

test("identify reads the proof from the subprotocol only", () => {
  const req = (h) => ({ headers: { "sec-websocket-protocol": h } });
  assert.deepEqual(identify(req(`clipway.v1, clipway.p.${V.P}`)), { id: V.id });
  assert.deepEqual(identify(req(`clipway.p.${V.P},clipway.v1`)), { id: V.id });
  assert.equal(identify(req(`clipway.p.${V.P}`)).status, 400);
  assert.equal(identify({ headers: {} }).status, 400);
  assert.equal(idFromHexProof(V.P), V.id);
  assert.equal(idFromHexProof(V.P.toUpperCase()), null);
  assert.equal(idFromHexProof(V.P + "00"), null);
  assert.equal(idFromHexProof(undefined), null);
});

test("IP keys: IPv6 reduced to its /64, mapped IPv4 unwrapped", () => {
  assert.equal(ipKey("::ffff:192.0.2.7"), "192.0.2.7");
  assert.equal(ipKey("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
  assert.equal(ipKey("2001:db8:1:2:ffff:4:5:6"), "2001:db8:1:2::/64");
  assert.equal(ipKey("2001:db8::1"), "2001:db8:0:0::/64");
  assert.equal(ipKey("fe80::1%en0"), "fe80:0:0:0::/64");
  assert.equal(ipKey("203.0.113.9"), "203.0.113.9");
  assert.equal(ipKey(""), "?");
});

test("behind a trusted proxy, the last X-Forwarded-For entry is the address", async (t) => {
  const r = await relay(t, { trustProxy: true, limits: { requestsPerMinute: 2 } });
  const get = (xff) => fetch(`${r.http}/health`, { headers: { "X-Forwarded-For": xff } });
  assert.equal((await get("198.51.100.1, 203.0.113.1")).status, 200);
  assert.equal((await get("198.51.100.2, 203.0.113.1")).status, 200);
  assert.equal((await get("198.51.100.3, 203.0.113.1")).status, 429);
  assert.equal((await get("203.0.113.2")).status, 200);
});

test("start() reads its options and stops cleanly", async () => {
  const r = await start({ port: 0, host: "127.0.0.1", quiet: true, ttlMs: 48 * 3_600_000 });
  const w = await (await fetch(`http://127.0.0.1:${r.port}/.well-known/clipway-relay.json`)).json();
  assert.equal(w.limits.ttl, 24 * 3_600_000, "the retention is capped at 24 h");
  assert.equal(CLOSE.erased, 4001);
  assert.equal(CLOSE.protocol, 4002);
  assert.equal(CLOSE.syncTimeout, 4003);
  await r.stop();
  await r.stop();
});
