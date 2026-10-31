// Shared helpers for the relay tests: a relay on a free port, chain keys, and a device client
// that queues every frame so a test can wait for the next one of a given kind.

import { randomBytes } from "node:crypto";
import WebSocket from "ws";
import { start, SUBPROTOCOL } from "../server.js";
import { generateSecret, deriveProof, deriveId, buildItem, readItem } from "../crypto.js";

export const MIB = 1_048_576;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Starts a relay on 127.0.0.1 and a free port; stopped after the test. */
export async function relay(t, options = {}) {
  const r = await start({ port: 0, host: "127.0.0.1", quiet: true, ...options });
  t.after(() => r.stop());
  const base = `http://127.0.0.1:${r.port}`;
  return {
    ...r,
    http: base,
    ws: `ws://127.0.0.1:${r.port}/ws`,
    health: async () => (await fetch(`${base}/health`)).json(),
    erase: (proofHex) => fetch(`${base}/chain`, { method: "DELETE", headers: proofHex === undefined ? {} : { "X-Clipway-Proof": proofHex } }),
  };
}

/** A fresh chain: S, the proof P (hex), the chain id and the WebSocket subprotocols. */
export function chainKeys(S = generateSecret()) {
  const P = deriveProof(S).toString("hex");
  return { S, P, id: deriveId(S), protocols: [SUBPROTOCOL, `clipway.p.${P}`] };
}

/** A device identity as it appears inside heads. */
export function device(name = "MacBook Air", kind = "mac") {
  return { id: randomBytes(16).toString("hex"), name, kind };
}

/**
 * Opens a WebSocket and queues every JSON frame in arrival order.
 * next(kind) resolves with the next frame of that kind (any kind when omitted), or rejects after
 * a timeout. closed resolves with { code, reason }.
 */
export function client(url, protocols, { timeout = 5000 } = {}) {
  const ws = new WebSocket(url, protocols, { maxPayload: 8 * MIB });
  const received = [];
  const waiting = [];
  ws.on("message", (d) => {
    const msg = JSON.parse(d.toString());
    const i = waiting.findIndex((w) => !w.kind || w.kind === msg.kind);
    if (i >= 0) {
      const [w] = waiting.splice(i, 1);
      clearTimeout(w.timer);
      w.resolve(msg);
    } else received.push(msg);
  });
  const opened = new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
    ws.once("unexpected-response", (_req, res) => reject(Object.assign(new Error("refused"), { status: res.statusCode })));
  });
  opened.catch(() => {});
  const closed = new Promise((resolve) => ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() })));
  const next = (kind) =>
    new Promise((resolve, reject) => {
      const i = received.findIndex((m) => !kind || m.kind === kind);
      if (i >= 0) return resolve(received.splice(i, 1)[0]);
      const w = { kind, resolve };
      w.timer = setTimeout(() => {
        waiting.splice(waiting.indexOf(w), 1);
        reject(new Error(`no ${kind ?? "frame"} within ${timeout} ms`));
      }, timeout);
      waiting.push(w);
    });
  /** Frames of that kind already received, removed from the queue. */
  const drain = (kind) => {
    const out = received.filter((m) => !kind || m.kind === kind);
    for (const m of out) received.splice(received.indexOf(m), 1);
    return out;
  };
  return { ws, opened, closed, next, drain, send: (o) => ws.send(JSON.stringify(o)) };
}

/** Collects item frames until synced; returns { items: [frames], synced }. Presence frames are skipped. */
export async function backlog(c) {
  const items = [];
  for (;;) {
    const m = await c.next();
    if (m.kind === "presence") continue;
    if (m.kind === "synced") return { items, synced: m };
    if (m.kind !== "item") throw new Error(`unexpected ${m.kind} in the backlog`);
    items.push(m);
  }
}

/** Connects a device of a chain, reads welcome, syncs and reads the backlog. */
export async function connect(r, keys, { epoch = "", after = 0 } = {}) {
  const c = client(r.ws, keys.protocols);
  await c.opened;
  const welcome = await c.next("welcome");
  c.send({ kind: "sync", epoch, after });
  const { items, synced } = await backlog(c);
  return { ...c, welcome, backlogItems: items, synced };
}

/** Builds an item and sends its parts under `ref`. Returns what buildItem returned. */
export function upload(c, keys, input, ref = 1) {
  const built = buildItem(keys.S, { device: device(), ts: Date.now(), ...input });
  built.envelopes.forEach((blob, part) => c.send({ kind: "item", ref, part, parts: built.envelopes.length, blob }));
  return built;
}

/** Sends a text and waits for stored. */
export async function sendText(c, keys, text, ref = 1, dev = device()) {
  const built = upload(c, keys, { type: "text", device: dev, content: Buffer.from(text, "utf8") }, ref);
  const stored = await c.next("stored");
  return { ...built, stored };
}

/** Reads `parts` item frames of one seq from a client and decrypts the item. */
export async function receiveItem(c, keys) {
  const first = await c.next("item");
  const frames = [first];
  while (frames.length < first.parts) frames.push(await c.next("item"));
  for (const [i, f] of frames.entries()) {
    if (f.seq !== first.seq || f.part !== i || f.parts !== first.parts) throw new Error("parts out of order");
  }
  return { seq: first.seq, ts: first.ts, frames, ...readItem(keys.S, frames.map((f) => f.blob)) };
}

/** A well-formed envelope that the relay accepts (it cannot check what is inside). */
export function fakeBlob(bytes = 528) {
  return { nonce: randomBytes(12).toString("hex"), enc: randomBytes(bytes).toString("base64") };
}
