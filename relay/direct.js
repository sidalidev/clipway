// Clipway direct transfer (see docs/PROTOCOL.md, section 14).
//
// Images and files never go through the relay. The sender listens on its local network and sends
// an offer through the relay (an ordinary encrypted item: the relay cannot tell it from a text).
// The receiver connects to one of the addresses in the offer, proves it holds the chain's key, and
// the sender streams the content, encrypted with a key that only exists for this transfer:
//
//   K_direct = HKDF(S, "clipway-direct")                      32 bytes
//   K_t      = HKDF(K_direct, "clipway-direct|" + transfer)   32 bytes, transfer = the offer's item id
//
// On the wire, after the TCP connection is open (receiver first):
//   receiver -> sender   "CWD1" || transfer (16 bytes)        the preamble, 20 bytes
//   then records, both ways: length (4 bytes, big-endian) || nonce (12) || ciphertext || tag (16)
//   AAD of a record: "clipway-direct|<transfer>|<get or put>|<index>", index from 0 per direction
//   get 0  receiver -> sender  {"v":1,"get":"<transfer>"}
//   put i  sender -> receiver  the content, 65 536 bytes per record (the last one shorter)
//   get 1  receiver -> sender  {"v":1,"status":"done"} once the content is checked and written
//
// This module is the reference: derivations and records (used by tools/gen-vectors.mjs), and a
// small sender and receiver on node:net (used by the tests and by tools/client.mjs).

import net from "node:net";
import os from "node:os";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { hkdf, fingerprint, deriveKeys, isIPv4, isValidId, NONCE_SIZE, TAG_SIZE, FILE_MAX, SECRET_SIZE } from "./crypto.js";

export const MAGIC = "CWD1";
export const PREAMBLE_SIZE = 4 + 16;
/** Content bytes per put record. */
export const RECORD_DATA = 65_536;
/** Largest record body (after the length field): nonce, a full put record, tag. */
export const RECORD_MAX = NONCE_SIZE + RECORD_DATA + TAG_SIZE;
/** Largest get record body: get 0 and get 1 are short JSON objects. */
export const GET_MAX = 1024;
/** An offer is valid this long after its ts; the sender stops listening for it then. */
export const OFFER_TTL = 120_000;
/** Receiver: each address is tried this long, all of them together at most CONNECT_TOTAL. */
export const CONNECT_EACH = 3_000;
export const CONNECT_TOTAL = 12_000;
/** Both sides: a connection silent this long is closed. */
export const IDLE = 15_000;
/** Sender: a new connection must send its preamble and get 0 within this time. */
export const HANDSHAKE = 5_000;
/** Sender: connections waiting for their first record, at most. */
export const UNPROVEN_MAX = 8;

const enc = new TextEncoder();

/** K_direct = HKDF-SHA256(S, empty salt, "clipway-direct", 32). */
export function directKey(S) {
  const s = Buffer.isBuffer(S) ? S : typeof S === "string" ? Buffer.from(S, "hex") : Buffer.from(S);
  if (s.length !== SECRET_SIZE) throw new Error("Invalid secret");
  return hkdf(s, "clipway-direct");
}

/** K_t = HKDF-SHA256(K_direct, empty salt, "clipway-direct|" + transfer, 32). */
export function transferKey(kDirect, transfer) {
  if (!isValidId(transfer)) throw new Error("Invalid transfer id");
  return hkdf(Buffer.from(kDirect), `clipway-direct|${transfer}`);
}

/** AAD of record `index` in direction `dir` ("get": receiver to sender, "put": sender to receiver). */
export function recordAad(transfer, dir, index) {
  return `clipway-direct|${transfer}|${dir}|${index}`;
}

/** The 20 bytes the receiver writes first: "CWD1" and the transfer id. */
export function preamble(transfer) {
  if (!isValidId(transfer)) throw new Error("Invalid transfer id");
  return Buffer.concat([Buffer.from(MAGIC, "ascii"), Buffer.from(transfer, "hex")]);
}

/** Reads a preamble: the transfer id, or null. */
export function readPreamble(bytes) {
  if (bytes.length !== PREAMBLE_SIZE || bytes.subarray(0, 4).toString("latin1") !== MAGIC) return null;
  return bytes.subarray(4).toString("hex");
}

/** A record on the wire: length (4 bytes, big-endian) || nonce || ciphertext || tag. */
export function sealRecord(kT, transfer, dir, index, plaintext, nonce = randomBytes(NONCE_SIZE)) {
  const iv = Buffer.from(nonce);
  if (iv.length !== NONCE_SIZE) throw new Error("Invalid nonce");
  const c = createCipheriv("aes-256-gcm", Buffer.from(kT), iv);
  c.setAAD(enc.encode(recordAad(transfer, dir, index)));
  const body = Buffer.concat([iv, c.update(Buffer.from(plaintext)), c.final(), c.getAuthTag()]);
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length);
  return Buffer.concat([head, body]);
}

/** Opens a record body (without its length field). Throws if anything does not match. */
export function openRecord(kT, transfer, dir, index, body) {
  const b = Buffer.from(body);
  if (b.length < NONCE_SIZE + TAG_SIZE || b.length > RECORD_MAX) throw new Error("Invalid record size");
  const d = createDecipheriv("aes-256-gcm", Buffer.from(kT), b.subarray(0, NONCE_SIZE));
  d.setAAD(enc.encode(recordAad(transfer, dir, index)));
  d.setAuthTag(b.subarray(b.length - TAG_SIZE));
  try {
    return Buffer.concat([d.update(b.subarray(NONCE_SIZE, b.length - TAG_SIZE)), d.final()]);
  } catch {
    throw new Error("Unreadable record: authentication failed");
  }
}

/** Number of put records for a content of `size` bytes (0 for an empty file). */
export function recordCount(size) {
  return Math.ceil(size / RECORD_DATA);
}

export const getRequest = (transfer) => JSON.stringify({ v: 1, get: transfer });
export const getStatus = (status) => JSON.stringify({ v: 1, status });

// ---------------------------------------------------------------------------
// Which addresses: private IPv4 only (the local network), loopback only for tests
// ---------------------------------------------------------------------------

/** 10/8, 172.16/12, 192.168/16 and link-local 169.254/16: the addresses of a local network. */
export function isPrivateIPv4(host) {
  if (!isIPv4(host)) return false;
  const [a, b] = host.split(".").map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

/** Addresses a receiver may connect to: private ones, and loopback when testing. */
export function mayConnect(host, { loopback = false } = {}) {
  return isPrivateIPv4(host) || (loopback && host === "127.0.0.1");
}

/** This computer's private IPv4 addresses, the ones an offer lists. */
export function localHosts() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list ?? []) if (a.family === "IPv4" && !a.internal && isPrivateIPv4(a.address)) out.push(a.address);
  }
  return [...new Set(out)].slice(0, 8);
}

// ---------------------------------------------------------------------------
// Sockets: read exactly n bytes, with a deadline
// ---------------------------------------------------------------------------

function reader(socket) {
  let buffered = Buffer.alloc(0);
  let wanted = null;
  let failure = null;
  const wake = () => {
    if (!wanted) return;
    if (failure) {
      const w = wanted;
      wanted = null;
      clearTimeout(w.timer);
      return w.reject(failure);
    }
    if (buffered.length >= wanted.n) {
      const w = wanted;
      wanted = null;
      clearTimeout(w.timer);
      const out = buffered.subarray(0, w.n);
      buffered = buffered.subarray(w.n);
      w.resolve(out);
    }
  };
  socket.on("data", (d) => {
    buffered = Buffer.concat([buffered, d]);
    wake();
  });
  socket.on("end", () => {
    failure ??= new Error("closed");
    wake();
  });
  socket.on("close", () => {
    failure ??= new Error("closed");
    wake();
  });
  socket.on("error", (e) => {
    failure ??= e;
    wake();
  });
  return (n, ms) =>
    new Promise((resolve, reject) => {
      wanted = { n, resolve, reject, timer: setTimeout(() => {
        wanted = null;
        socket.destroy();
        reject(new Error("timeout"));
      }, ms) };
      wake();
    });
}

async function readRecord(read, max, ms) {
  const len = (await read(4, ms)).readUInt32BE(0);
  if (len < NONCE_SIZE + TAG_SIZE || len > max) throw new Error("Invalid record size");
  return read(len, ms);
}

function write(socket, bytes) {
  return new Promise((resolve, reject) => socket.write(bytes, (e) => (e ? reject(e) : resolve())));
}

// ---------------------------------------------------------------------------
// Sender: listens, serves each offered content once
// ---------------------------------------------------------------------------

/**
 * Starts a sender. offer(transfer, content) registers a content and returns { port, hosts, outcome },
 * where the promise outcome resolves with "done", "failed", "expired" or the result given to cancel.
 * Options: S (the chain secret), host (bind address, default all), port (0: any), hosts (addresses
 * to list; default localHosts()), ttlMs (OFFER_TTL).
 */
export async function startSender({ S, host, port = 0, hosts, ttlMs = OFFER_TTL }) {
  const kDirect = directKey(S);
  const pending = new Map();
  let unproven = 0;
  const server = net.createServer((socket) => {
    if (unproven >= UNPROVEN_MAX) return socket.destroy();
    unproven += 1;
    let proven = false;
    const settle = () => {
      if (!proven) {
        proven = true;
        unproven -= 1;
      }
    };
    socket.once("close", settle);
    const read = reader(socket);
    (async () => {
      const transfer = readPreamble(await read(PREAMBLE_SIZE, HANDSHAKE));
      const p = transfer && pending.get(transfer);
      if (!p || p.taken) throw new Error("unknown transfer");
      const request = JSON.parse(openRecord(p.key, transfer, "get", 0, await readRecord(read, GET_MAX, HANDSHAKE)).toString("utf8"));
      if (request.v !== 1 || request.get !== transfer) throw new Error("bad request");
      // Proven: this connection holds the chain key. One per transfer.
      p.taken = true;
      p.socket = socket;
      settle();
      const count = recordCount(p.content.length);
      for (let i = 0; i < count; i++) {
        const chunk = p.content.subarray(i * RECORD_DATA, Math.min(p.content.length, (i + 1) * RECORD_DATA));
        await write(socket, sealRecord(p.key, transfer, "put", i, chunk));
      }
      const answer = JSON.parse(openRecord(p.key, transfer, "get", 1, await readRecord(read, GET_MAX, IDLE)).toString("utf8"));
      finish(transfer, answer.v === 1 && answer.status === "done" ? "done" : "failed");
      socket.end();
    })().catch(() => {
      socket.destroy();
      for (const [t, p] of pending) if (p.taken && p.socket === socket) finish(t, "failed");
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, resolve);
  });
  const bound = server.address().port;

  function finish(transfer, result) {
    const p = pending.get(transfer);
    if (!p) return;
    pending.delete(transfer);
    clearTimeout(p.timer);
    p.resolve(result);
  }

  return {
    port: bound,
    offer(transfer, content) {
      if (!isValidId(transfer) || content.length > FILE_MAX) throw new Error("Invalid offer");
      let resolve;
      const done = new Promise((r) => (resolve = r));
      const p = { key: transferKey(kDirect, transfer), content: Buffer.from(content), taken: false, resolve, done };
      p.timer = setTimeout(() => finish(transfer, "expired"), ttlMs);
      p.timer.unref?.();
      pending.set(transfer, p);
      return { port: bound, hosts: hosts ?? localHosts(), outcome: done };
    },
    /** The receiver said it cannot connect (a reply through the relay): stop waiting. */
    cancel: (transfer, result = "unreachable") => finish(transfer, result),
    close: () => new Promise((r) => server.close(() => r())),
  };
}

// ---------------------------------------------------------------------------
// Receiver: connects to an offer and fetches its content
// ---------------------------------------------------------------------------

/**
 * Fetches the content of an offer head. Tries each allowed address in order. Calls save(content)
 * once the size and fingerprint are checked; when it resolves, sends get 1 "done".
 * Returns { ok: true, content } or { ok: false, reason: "unreachable" | "failed" }.
 */
export async function fetchOffer({ S, head, save = async () => {}, loopback = false, extraHosts = [] }) {
  const kT = transferKey(directKey(S), head.item);
  const kMac = deriveKeys(S).mac;
  const started = Date.now();
  const hosts = [...head.hosts, ...extraHosts].filter((h) => mayConnect(h, { loopback }));
  let reached = false;
  for (const host of [...new Set(hosts)]) {
    const left = CONNECT_TOTAL - (Date.now() - started);
    if (left <= 0) break;
    let socket;
    try {
      socket = await new Promise((resolve, reject) => {
        const s = net.connect({ host, port: head.port });
        const timer = setTimeout(() => {
          s.destroy();
          reject(new Error("timeout"));
        }, Math.min(CONNECT_EACH, left));
        s.once("connect", () => {
          clearTimeout(timer);
          resolve(s);
        });
        s.once("error", (e) => {
          clearTimeout(timer);
          reject(e);
        });
      });
    } catch {
      continue;
    }
    reached = true;
    const read = reader(socket);
    try {
      await write(socket, Buffer.concat([preamble(head.item), sealRecord(kT, head.item, "get", 0, getRequest(head.item))]));
      const parts = [];
      let got = 0;
      for (let i = 0; i < recordCount(head.size); i++) {
        const chunk = openRecord(kT, head.item, "put", i, await readRecord(read, RECORD_MAX, IDLE));
        got += chunk.length;
        if (got > head.size || (chunk.length !== RECORD_DATA && got !== head.size)) throw new Error("size");
        parts.push(chunk);
      }
      const content = Buffer.concat(parts);
      if (content.length !== head.size || fingerprint(kMac, content) !== head.fp) throw new Error("fingerprint");
      await save(content);
      await write(socket, sealRecord(kT, head.item, "get", 1, getStatus("done")));
      socket.end();
      return { ok: true, content };
    } catch {
      socket.destroy();
      return { ok: false, reason: "failed" };
    }
  }
  return { ok: false, reason: reached ? "failed" : "unreachable" };
}
