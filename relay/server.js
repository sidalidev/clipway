// Clipway relay (see docs/PROTOCOL.md, section 4).
//
// Role: pass encrypted texts between the devices of a chain, and keep them for a device that
// is offline (24 h at most, in memory only, never on disk). The relay only knows the chain id,
// which it computes from the proof P each device presents. It cannot read anything: items are
// AES-256-GCM envelopes sealed with a key it never sees.
//
// Texts only. Nobody can moderate what travels end to end encrypted without an account, so this
// relay refuses to carry images and files at all: an item is one envelope of at most the size of
// a 64 KiB text, and anything larger or in several parts is refused. Images and files go directly
// between the devices on their local network (docs/PROTOCOL.md, section 14).
//
// The chain id never travels, and P never travels in a URL (proxy access logs would write it):
//   WebSocket: Sec-WebSocket-Protocol "clipway.v1, clipway.p.<hex P>"
//   HTTP:      X-Clipway-Proof: <hex P>
//
// Routes:
//   GET    /ws                              WebSocket of a device (authenticated by P)
//   DELETE /chain                           erase what the relay holds for the chain (Erase everything)
//   GET    /health                          { ok, chains, connections, items, bytes, uptime, version }
//   GET    /.well-known/clipway-relay.json  protocol version, minimum clients, status, limits
//   GET    /.well-known/security.txt        how to report a vulnerability
//
// Environment: PORT (7710), HOST (all interfaces), CLIPWAY_TRUST_PROXY (0), CLIPWAY_TTL_H (24, at most 24),
// CLIPWAY_MAX_TOTAL_MB (256), CLIPWAY_PING_S (240), CLIPWAY_DEAD_S (600).
//
// Log: counters every hour and errors. Never an IP address, never a full chain id (6 characters),
// never a proof, a nonce, the size of a given item or any content.

import http from "node:http";
import { isIP } from "node:net";
import { readFileSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer, WebSocket } from "ws";
import { idFromProof, PROTOCOL_VERSION, TEXT_MAX, ENC_MAX } from "./crypto.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const VERSION = JSON.parse(readFileSync(path.join(HERE, "package.json"), "utf8")).version;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const MIB = 1_048_576;

/** WebSocket subprotocol, echoed by the relay when the connection is accepted. */
export const SUBPROTOCOL = "clipway.v1";
const PROOF_PREFIX = "clipway.p.";
const RE_PROOF = /^[0-9a-f]{32}$/;
const RE_NONCE = /^[0-9a-f]{24}$/;
const RE_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const RE_EPOCH = /^(?:[0-9a-f]{16})?$/;
/** Largest upload number a device may use. */
const REF_MAX = 2 ** 31 - 1;
/** Room kept in a frame for the fields the relay adds when it forwards a part (seq, ts). */
const FRAME_SLACK = 256;
/** Why an item larger than a text, or in several parts, is refused. */
const TEXT_ONLY = "this relay carries texts of 64 KB at most: images and files go directly between your devices";

/** Limits. Clients read the first seven from welcome and from /.well-known/clipway-relay.json. */
export const LIMITS = Object.freeze({
  /** Largest WebSocket frame, both ways: one envelope of the largest text, and the frame around it. */
  frame: 128 * 1024,
  /** Parts of one item: one. Nothing is cut in chunks any more (images and files travel directly). */
  parts: 1,
  /** Largest text (UTF-8 bytes) the apps send. */
  text: TEXT_MAX,
  /** Largest enc string of an envelope: the head of a 64 KiB text, padded, encrypted, in base64. */
  enc: ENC_MAX,
  /** Queue of a chain: items and stored bytes (sum of the enc strings). Oldest evicted first. */
  items: 50,
  bytes: 6 * MIB,
  /** How long an item waits for an offline device. */
  ttl: 24 * HOUR,
  /** Open connections of one chain. */
  devices: 8,
  /** Items uploaded per chain per minute, and bytes (enc) per chain per hour. */
  itemsPerMinute: 60,
  bytesPerHour: 60 * MIB,
  /** Uploads in progress per connection, and their bytes (decoded ciphertext). */
  uploads: 4,
  uploadBytes: 1 * MIB,
  /** An upload that is not complete after this long is dropped. */
  uploadTimeout: 2 * MINUTE,
  /** Requests per IP per minute (WebSocket upgrades, DELETE /chain, other HTTP). */
  requestsPerMinute: 60,
  /** Open WebSocket connections per IP, and in total. */
  connectionsPerIp: 20,
  connections: 10_000,
  /** Chains the relay holds at once (connected or with items waiting). */
  chains: 20_000,
  /** A device must send sync this soon after welcome. */
  syncTimeout: 10_000,
  /** Malformed frames tolerated on one connection before it is closed with 4002. */
  badFrames: 10,
});

/** WebSocket close codes. 1009 (frame too big) comes from the WebSocket library. */
export const CLOSE = Object.freeze({
  erased: 4001,
  protocol: 4002,
  syncTimeout: 4003,
});

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
};

/**
 * Key of an address for the per-IP limits: IPv4 as is (an IPv4-mapped IPv6 address becomes IPv4),
 * IPv6 reduced to its /64 prefix (a client owns a whole /64). Kept in memory only, never logged.
 */
export function ipKey(address) {
  if (typeof address !== "string" || !address) return "?";
  let a = address.trim();
  const zone = a.indexOf("%");
  if (zone >= 0) a = a.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(a);
  if (mapped) return mapped[1];
  if (isIP(a) !== 6) return a;
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
  if (v4) {
    const [x, y, z, w] = v4.slice(1).map(Number);
    a = a.slice(0, v4.index) + ((x << 8) | y).toString(16) + ":" + ((z << 8) | w).toString(16);
  }
  const [head, tail] = a.split("::");
  const start = head ? head.split(":") : [];
  const end = tail === undefined ? null : tail ? tail.split(":") : [];
  const groups = end === null ? start : [...start, ...Array(8 - start.length - end.length).fill("0"), ...end];
  return groups.slice(0, 4).map((g) => Number.parseInt(g, 16).toString(16)).join(":") + "::/64";
}

/** Tokens of the Sec-WebSocket-Protocol header. */
function subprotocols(req) {
  const raw = req.headers["sec-websocket-protocol"];
  if (typeof raw !== "string") return [];
  return raw.split(",").map((t) => t.trim()).filter(Boolean);
}

/** Chain id from a hex proof (32 lowercase hex), or null. */
export function idFromHexProof(hex) {
  if (typeof hex !== "string" || !RE_PROOF.test(hex)) return null;
  return idFromProof(Buffer.from(hex, "hex"));
}

/** Identifies a WebSocket client from its subprotocols. Returns { id } or { status, error }. */
export function identify(req) {
  const tokens = subprotocols(req);
  if (!tokens.includes(SUBPROTOCOL)) return { status: 400, error: `subprotocol ${SUBPROTOCOL} expected` };
  const token = tokens.find((t) => t.startsWith(PROOF_PREFIX));
  const id = idFromHexProof(token?.slice(PROOF_PREFIX.length));
  if (!id) return { status: 400, error: "invalid proof: clipway.p.<32 hex> expected" };
  return { id };
}

/** First 6 characters of a chain id: the only part allowed in the log. */
const short = (id) => (typeof id === "string" ? id.slice(0, 6) : "?");

/** Bytes of ciphertext behind a standard base64 string (its length is a multiple of 4). */
const rawSize = (enc) => (enc.length / 4) * 3 - (enc.endsWith("==") ? 2 : enc.endsWith("=") ? 1 : 0);

/** Shape of an envelope: { nonce: 24 hex, enc: base64 of at least the 16-byte tag }. */
function isBlob(b) {
  return (
    b !== null &&
    typeof b === "object" &&
    !Array.isArray(b) &&
    typeof b.nonce === "string" &&
    RE_NONCE.test(b.nonce) &&
    typeof b.enc === "string" &&
    b.enc.length >= 24 &&
    b.enc.length % 4 === 0 &&
    RE_BASE64.test(b.enc)
  );
}

const isInt = (v, min, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && v >= min && v <= max;

/** Fixed window counter per key. allow(key) returns false once the limit is reached. */
function limiter(max, window = MINUTE) {
  const counters = new Map();
  return {
    allow(key, now = Date.now()) {
      let c = counters.get(key);
      if (!c || now - c.start >= window) {
        c = { start: now, n: 0 };
        counters.set(key, c);
      }
      c.n += 1;
      return c.n <= max;
    },
    sweep(now = Date.now()) {
      for (const [key, c] of counters) if (now - c.start >= window) counters.delete(key);
    },
  };
}

/** Reads a positive number from the environment, or returns the default. */
function envNumber(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

/**
 * Starts a relay. Resolves to { server, port, epoch, stop() }.
 * Options (all optional): port, host, ttlMs, maxTotalBytes, pingMs, deadMs, trustProxy, quiet,
 * log (function receiving each log line instead of the console), sweepMs, statsMs, and limits
 * (overrides of LIMITS, for tests and small hosts).
 *
 * epoch is drawn at start. A chain's numbering (seq) lives as long as the relay holds the chain:
 * the first chain record uses the start epoch, and a chain the relay forgot (nothing queued, nobody
 * connected) and sees again gets a fresh epoch, so that a device never skips items because of an
 * old `after`.
 */
export function start(options = {}) {
  const o = {
    port: 7710,
    host: undefined,
    ttlMs: LIMITS.ttl,
    maxTotalBytes: 256 * MIB,
    pingMs: 4 * MINUTE,
    deadMs: 10 * MINUTE,
    trustProxy: false,
    quiet: false,
    log: null,
    sweepMs: 30_000,
    statsMs: HOUR,
    ...options,
  };
  const ttl = Math.max(1, Math.min(o.ttlMs, LIMITS.ttl));
  const L = Object.freeze({ ...LIMITS, ...(o.limits ?? {}), ttl });
  const began = Date.now();
  /** Changes at every start: nothing is persisted, so sequence numbers restart from 1. */
  const epoch = randomBytes(8).toString("hex");

  // Log: counters and errors only. Never an IP address, never a full chain id, never content.
  const stats = {
    opened: 0,
    itemsIn: 0,
    bytesIn: 0,
    delivered: 0,
    expired: 0,
    evicted: 0,
    erased: 0,
    incomplete: 0,
    refusedRate: 0,
    refusedShape: 0,
    refusedBusy: 0,
    refusedSize: 0,
  };
  const write = (fallback, parts) => {
    const line = [new Date().toISOString(), ...parts].join(" ");
    if (typeof o.log === "function") o.log(line);
    else if (!o.quiet) fallback(line);
  };
  const log = (...t) => write(console.log, t);
  const logError = (...t) => write(console.error, ["error:", ...t]);

  /** id -> { id, epoch, sockets: Set<WebSocket>, queue: Item[] (seq order), seq, bytes } */
  const chains = new Map();
  /** Chain ids the relay held and forgot since it started: they get a fresh epoch when they come back. */
  const forgotten = new Set();
  let forgottenFull = false;
  /** id -> { minute, items, hour, bytes }: upload rates per chain, kept after the chain is forgotten. */
  const rates = new Map();
  /** connection number -> WebSocket, to tell an uploader its item was delivered. */
  const byNumber = new Map();
  let nextNumber = 1;
  /** Bytes queued (sum of enc lengths) and bytes of uploads in progress, all chains. */
  let stored = 0;
  let pending = 0;
  const perIp = limiter(L.requestsPerMinute);
  const openPerIp = new Map();
  let openTotal = 0;

  /** The chain record of an id, compared again in constant time after the map lookup. */
  function findChain(id) {
    const c = chains.get(id);
    if (!c) return null;
    return timingSafeEqual(Buffer.from(c.id, "latin1"), Buffer.from(id, "latin1")) ? c : null;
  }

  function chain(id) {
    let c = findChain(id);
    if (!c) {
      const seen = forgottenFull || forgotten.has(id);
      c = { id, epoch: seen ? randomBytes(8).toString("hex") : epoch, sockets: new Set(), queue: [], seq: 0, bytes: 0 };
      chains.set(id, c);
    }
    return c;
  }

  function forgetIfEmpty(c) {
    if (c.sockets.size > 0 || c.queue.length > 0 || chains.get(c.id) !== c) return;
    chains.delete(c.id);
    remember(c.id);
  }

  function remember(id) {
    if (forgottenFull) return;
    forgotten.add(id);
    // Bounded memory: past this, every chain that comes back simply gets a fresh epoch.
    if (forgotten.size >= 100_000) {
      forgotten.clear();
      forgottenFull = true;
    }
  }

  function rate(id, now) {
    let r = rates.get(id);
    if (!r) {
      r = { minute: now, items: 0, hour: now, bytes: 0 };
      rates.set(id, r);
    }
    if (now - r.minute >= MINUTE) {
      r.minute = now;
      r.items = 0;
    }
    if (now - r.hour >= HOUR) {
      r.hour = now;
      r.bytes = 0;
    }
    return r;
  }

  function dropItem(c, index, counter) {
    const [it] = c.queue.splice(index, 1);
    c.bytes -= it.bytes;
    stored -= it.bytes;
    if (counter) stats[counter] += 1;
    return it;
  }

  function purgeExpired(c, now = Date.now()) {
    for (let i = c.queue.length - 1; i >= 0; i--) if (c.queue[i].expires <= now) dropItem(c, i, "expired");
  }

  function send(ws, obj) {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  }

  function broadcastPresence(c) {
    const msg = { kind: "presence", devices: c.sockets.size };
    for (const ws of c.sockets) send(ws, msg);
  }

  /** Sends every part of an item, in order. */
  function deliver(ws, item) {
    const parts = item.blobs.length;
    for (let part = 0; part < parts; part++) {
      send(ws, { kind: "item", seq: item.seq, part, parts, ts: item.ts, blob: item.blobs[part] });
    }
  }

  function addressOf(req) {
    if (o.trustProxy) {
      const xff = req.headers["x-forwarded-for"];
      if (typeof xff === "string" && xff.trim()) {
        const list = xff.split(",").map((s) => s.trim()).filter(Boolean);
        if (list.length) return ipKey(list[list.length - 1]);
      }
    }
    return ipKey(req.socket.remoteAddress);
  }

  function json(res, status, obj, headers = {}) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Length": Buffer.byteLength(body),
      ...SECURITY_HEADERS,
      ...headers,
    });
    res.end(body);
  }

  function counts() {
    let connections = 0;
    let items = 0;
    for (const c of chains.values()) {
      connections += c.sockets.size;
      items += c.queue.length;
    }
    return { chains: chains.size, connections, items, bytes: stored };
  }

  const publicLimits = () => ({
    frame: L.frame,
    parts: L.parts,
    text: L.text,
    enc: L.enc,
    items: L.items,
    bytes: L.bytes,
    ttl: L.ttl,
  });

  const wellKnown = () => ({
    protocol: PROTOCOL_VERSION,
    version: VERSION,
    status: "ok",
    // 0.3.0: older apps sent images and files through the relay, which refuses them now.
    minClient: { android: "0.3.0", mac: "0.3.0" },
    limits: publicLimits(),
  });

  /** Erases what the relay holds for a chain and closes its connections with 4001. */
  function erase(id) {
    const c = findChain(id);
    if (!c) return;
    chains.delete(id);
    remember(id);
    while (c.queue.length) dropItem(c, 0, null);
    for (const ws of c.sockets) {
      const s = ws.clipway;
      s.closing = true;
      dropUploads(s);
      ws.close(CLOSE.erased, "chain erased");
    }
    stats.erased += 1;
  }

  // ---------------------------------------------------------------------------
  // HTTP
  // ---------------------------------------------------------------------------

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://relay");
    if (!perIp.allow(addressOf(req))) {
      stats.refusedRate += 1;
      return json(res, 429, { error: "too many requests, try again in a minute" });
    }
    if (req.method === "GET" && url.pathname === "/health") {
      return json(res, 200, { ok: true, ...counts(), uptime: Math.round((Date.now() - began) / 1000), version: VERSION });
    }
    if (req.method === "GET" && url.pathname === "/.well-known/clipway-relay.json") {
      return json(res, 200, wellKnown(), { "Cache-Control": "public, max-age=300" });
    }
    if (req.method === "GET" && url.pathname === "/.well-known/security.txt") {
      const expires = new Date(Date.now() + 180 * 24 * HOUR).toISOString();
      const body = `Contact: mailto:contact@sidali.dev\nExpires: ${expires}\nPreferred-Languages: en, fr\n`;
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600", ...SECURITY_HEADERS });
      return res.end(body);
    }
    if (req.method === "DELETE" && url.pathname === "/chain") {
      const id = idFromHexProof(req.headers["x-clipway-proof"]);
      if (!id) {
        stats.refusedShape += 1;
        return json(res, 400, { error: "X-Clipway-Proof: 32 lowercase hex expected" });
      }
      erase(id);
      // 204 whether or not something was there: the answer does not reveal if a chain existed.
      res.writeHead(204, { "Cache-Control": "no-store", ...SECURITY_HEADERS });
      return res.end();
    }
    if (url.pathname === "/ws") return json(res, 426, { error: "WebSocket expected" }, { Upgrade: "websocket" });
    return json(res, 404, { error: "not found" });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;
  server.on("clientError", (_err, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    else socket.destroy();
  });

  // ---------------------------------------------------------------------------
  // WebSocket
  // ---------------------------------------------------------------------------

  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: L.frame,
    perMessageDeflate: false,
    handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
  });

  function refuseUpgrade(socket, status, message) {
    const body = JSON.stringify({ error: message });
    socket.end(
      `HTTP/1.1 ${status} ${http.STATUS_CODES[status] ?? ""}\r\n` +
        "Content-Type: application/json; charset=utf-8\r\n" +
        `Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
    );
  }

  server.on("upgrade", (req, socket, head) => {
    socket.on("error", () => {});
    const url = new URL(req.url ?? "/", "http://relay");
    if (url.pathname !== "/ws") return refuseUpgrade(socket, 404, "not found");
    const ip = addressOf(req);
    if (!perIp.allow(ip)) {
      stats.refusedRate += 1;
      return refuseUpgrade(socket, 429, "too many requests, try again in a minute");
    }
    const who = identify(req);
    if (!who.id) {
      stats.refusedShape += 1;
      return refuseUpgrade(socket, who.status, who.error);
    }
    if (openTotal >= L.connections) {
      stats.refusedBusy += 1;
      return refuseUpgrade(socket, 503, "relay busy, try again later");
    }
    if ((openPerIp.get(ip) ?? 0) >= L.connectionsPerIp) {
      stats.refusedRate += 1;
      return refuseUpgrade(socket, 429, "too many connections from this address");
    }
    const existing = findChain(who.id);
    if ((existing?.sockets.size ?? 0) >= L.devices) {
      stats.refusedRate += 1;
      return refuseUpgrade(socket, 429, "too many devices connected to this chain");
    }
    if (!existing && chains.size >= L.chains) {
      stats.refusedBusy += 1;
      return refuseUpgrade(socket, 503, "relay busy, try again later");
    }
    openTotal += 1;
    openPerIp.set(ip, (openPerIp.get(ip) ?? 0) + 1);
    socket.once("close", () => {
      openTotal -= 1;
      const n = (openPerIp.get(ip) ?? 1) - 1;
      if (n > 0) openPerIp.set(ip, n);
      else openPerIp.delete(ip);
    });
    wss.handleUpgrade(req, socket, head, (ws) => {
      stats.opened += 1;
      welcome(ws, who.id);
    });
  });

  /** Drops one upload in progress and frees its bytes. */
  function dropUpload(s, up) {
    clearTimeout(up.timer);
    s.uploads.delete(up.ref);
    pending -= up.bytes;
    s.pendingRaw -= up.raw;
  }

  function dropUploads(s) {
    for (const up of [...s.uploads.values()]) dropUpload(s, up);
  }

  /** Closes a connection that broke the protocol (4002). */
  function violation(ws, reason) {
    const s = ws.clipway;
    if (s.closing) return;
    stats.refusedShape += 1;
    s.closing = true;
    dropUploads(s);
    ws.close(CLOSE.protocol, reason);
  }

  /** Answers an error; an upload in progress with this ref is dropped. */
  function refuse(ws, ref, code, message) {
    const s = ws.clipway;
    const up = ref === null ? undefined : s.uploads.get(ref);
    if (up) dropUpload(s, up);
    if (code === "rate_limited" || code === "quota") stats.refusedRate += 1;
    else if (code === "busy") stats.refusedBusy += 1;
    else if (code === "too_big") stats.refusedSize += 1;
    else stats.refusedShape += 1;
    send(ws, { kind: "error", ref, code, message });
    if (code === "bad_request") {
      s.bad += 1;
      if (s.bad >= L.badFrames) violation(ws, "too many malformed frames");
    }
  }

  function welcome(ws, id) {
    const c = chain(id);
    const now = Date.now();
    const number = nextNumber++;
    c.sockets.add(ws);
    byNumber.set(number, ws);
    ws.clipway = {
      number,
      id,
      chain: c,
      synced: false,
      closing: false,
      bad: 0,
      lastHeard: now,
      lastPing: now,
      uploads: new Map(),
      pendingRaw: 0,
      syncTimer: null,
    };
    const s = ws.clipway;
    send(ws, { kind: "welcome", v: PROTOCOL_VERSION, epoch: c.epoch, devices: c.sockets.size, limits: publicLimits() });
    broadcastPresence(c);
    s.syncTimer = setTimeout(() => {
      if (!s.synced && !s.closing) {
        s.closing = true;
        ws.close(CLOSE.syncTimeout, "sync expected");
      }
    }, L.syncTimeout);
    s.syncTimer.unref?.();

    ws.on("pong", () => {
      s.lastHeard = Date.now();
    });
    ws.on("message", (data, isBinary) => {
      s.lastHeard = Date.now();
      if (s.closing) return;
      if (isBinary) return violation(ws, "binary frames are not accepted");
      let msg = null;
      try {
        msg = JSON.parse(data.toString("utf8"));
      } catch {
        msg = null;
      }
      const shaped = msg !== null && typeof msg === "object" && !Array.isArray(msg) && typeof msg.kind === "string";
      if (!s.synced && (!shaped || msg.kind !== "sync")) return violation(ws, "sync expected first");
      if (!shaped) return refuse(ws, null, "bad_request", "JSON object with kind expected");
      switch (msg.kind) {
        case "sync":
          return onSync(ws, msg);
        case "item":
          return onItem(ws, msg);
        case "ack":
          return onAck(ws, msg);
        case "ping":
          return send(ws, { kind: "pong" });
        default:
          return refuse(ws, null, "bad_request", "unknown kind");
      }
    });
    ws.on("close", () => {
      clearTimeout(s.syncTimer);
      dropUploads(s);
      byNumber.delete(s.number);
      c.sockets.delete(ws);
      if (chains.get(c.id) === c) broadcastPresence(c);
      forgetIfEmpty(c);
    });
    ws.on("error", (e) => logError("connection", short(id), e?.code ?? "error"));
  }

  /** sync: the backlog (items after `after`, or all of them for another epoch), then synced. */
  function onSync(ws, msg) {
    const s = ws.clipway;
    const c = s.chain;
    if (s.synced) return refuse(ws, null, "bad_request", "already synced");
    if (typeof msg.epoch !== "string" || !RE_EPOCH.test(msg.epoch) || !isInt(msg.after, 0)) {
      return refuse(ws, null, "bad_request", "sync: epoch (16 hex or empty) and after (integer) expected");
    }
    clearTimeout(s.syncTimer);
    s.synced = true;
    const after = msg.epoch === c.epoch ? msg.after : 0;
    purgeExpired(c);
    for (const item of c.queue) if (item.seq > after) deliver(ws, item);
    send(ws, { kind: "synced", last: c.seq });
  }

  /** item: one part of an upload. The last part queues the item and sends it to the others. */
  function onItem(ws, msg) {
    const s = ws.clipway;
    const c = s.chain;
    const { ref, part, parts, blob } = msg;
    if (!isInt(ref, 0, REF_MAX)) return refuse(ws, null, "bad_request", "ref: integer from 0 to 2^31 - 1 expected");
    if (!isInt(parts, 1)) return refuse(ws, ref, "bad_request", "parts: integer from 1 expected");
    if (parts > L.parts) return refuse(ws, ref, "too_big", TEXT_ONLY);
    if (!isInt(part, 0, parts - 1)) return refuse(ws, ref, "bad_request", "part: integer from 0 to parts - 1 expected");
    if (!isBlob(blob)) return refuse(ws, ref, "bad_request", "blob: { nonce: 24 hex, enc: base64 } expected");
    if (blob.enc.length > L.enc || blob.enc.length + FRAME_SLACK > L.frame) return refuse(ws, ref, "too_big", TEXT_ONLY);

    const now = Date.now();
    let up = s.uploads.get(ref);
    if (part === 0) {
      if (up) return refuse(ws, ref, "bad_request", "this ref is already in progress");
      if (s.uploads.size >= L.uploads) return refuse(ws, ref, "quota", `${L.uploads} uploads at most in progress`);
      if (rate(c.id, now).items >= L.itemsPerMinute) return refuse(ws, ref, "rate_limited", "too many items, try again in a minute");
    } else {
      if (!up) return refuse(ws, ref, "bad_request", "part 0 expected first");
      if (up.parts !== parts) return refuse(ws, ref, "bad_request", "parts changed during the upload");
      if (part !== up.blobs.length) return refuse(ws, ref, "bad_request", "parts must come in order");
    }

    const size = blob.enc.length;
    const raw = rawSize(blob.enc);
    const r = rate(c.id, now);
    if (s.pendingRaw + raw > L.uploadBytes) return refuse(ws, ref, "quota", "too much in progress on this connection");
    if ((up?.bytes ?? 0) + size > L.bytes) return refuse(ws, ref, "too_big", "item larger than the queue of a chain");
    if (r.bytes + size > L.bytesPerHour) return refuse(ws, ref, "rate_limited", "too much data this hour, try again later");
    if (stored + pending + size > o.maxTotalBytes) return refuse(ws, ref, "busy", "relay full, try again later");

    if (!up) {
      up = { ref, parts, blobs: [], bytes: 0, raw: 0, timer: null };
      up.timer = setTimeout(() => {
        if (s.uploads.get(ref) !== up) return;
        stats.incomplete += 1;
        dropUpload(s, up);
        send(ws, { kind: "error", ref, code: "incomplete", message: "upload not completed in time" });
      }, L.uploadTimeout);
      up.timer.unref?.();
      s.uploads.set(ref, up);
      r.items += 1;
    }
    up.blobs.push({ nonce: blob.nonce, enc: blob.enc });
    up.bytes += size;
    up.raw += raw;
    s.pendingRaw += raw;
    pending += size;
    r.bytes += size;
    stats.bytesIn += size;
    if (up.blobs.length === up.parts) complete(ws, up);
  }

  function complete(ws, up) {
    const s = ws.clipway;
    const c = s.chain;
    dropUpload(s, up);
    const now = Date.now();
    purgeExpired(c, now);
    // A clipboard is "latest wins": the oldest items make room for the new one.
    while (c.queue.length && (c.queue.length + 1 > L.items || c.bytes + up.bytes > L.bytes)) dropItem(c, 0, "evicted");
    const item = { seq: ++c.seq, blobs: up.blobs, bytes: up.bytes, ts: now, expires: now + L.ttl, from: s.number };
    c.queue.push(item);
    c.bytes += item.bytes;
    stored += item.bytes;
    stats.itemsIn += 1;
    send(ws, { kind: "stored", ref: up.ref, seq: item.seq });
    for (const other of c.sockets) if (other !== ws && other.clipway.synced && !other.clipway.closing) deliver(other, item);
  }

  /** ack: the first ack from another connection than the uploader's deletes the item. */
  function onAck(ws, msg) {
    const s = ws.clipway;
    const c = s.chain;
    if (!isInt(msg.seq, 1)) return refuse(ws, null, "bad_request", "seq: integer from 1 expected");
    const i = c.queue.findIndex((it) => it.seq === msg.seq);
    if (i < 0 || c.queue[i].from === s.number) return;
    const item = dropItem(c, i, "delivered");
    send(byNumber.get(item.from), { kind: "delivered", seq: item.seq });
  }

  // ---------------------------------------------------------------------------
  // Timers: protocol pings, expiry, counters
  // ---------------------------------------------------------------------------

  // Protocol pings: every 4 min (a ping wakes the phone's radio), cut after 10 min of silence.
  const pingTimer = setInterval(() => {
    const now = Date.now();
    for (const ws of wss.clients) {
      const s = ws.clipway;
      if (!s) continue;
      if (now - s.lastHeard > o.deadMs) {
        ws.terminate();
        continue;
      }
      if (now - s.lastPing < o.pingMs) continue;
      s.lastPing = now;
      try {
        ws.ping();
      } catch {
        // The close handler cleans up.
      }
    }
  }, Math.max(10, Math.min(o.pingMs, 5_000)));
  pingTimer.unref();

  const sweepTimer = setInterval(() => {
    const now = Date.now();
    for (const c of [...chains.values()]) {
      purgeExpired(c, now);
      forgetIfEmpty(c);
    }
    for (const [id, r] of rates) if (now - r.hour >= HOUR && now - r.minute >= MINUTE) rates.delete(id);
    perIp.sweep(now);
  }, Math.max(10, Math.min(o.sweepMs, ttl)));
  sweepTimer.unref();

  const logStats = () => log("stats", JSON.stringify({ ...counts(), pending, ...stats }));
  const statsTimer = setInterval(logStats, Math.max(10, o.statsMs));
  statsTimer.unref();

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(o.port, o.host, () => {
      const port = server.address().port;
      log(`Clipway relay ${VERSION} listening on port ${port}`);
      let stopping = null;
      resolve({
        server,
        port,
        epoch,
        stop: () =>
          (stopping ??= new Promise((done) => {
            clearInterval(pingTimer);
            clearInterval(sweepTimer);
            clearInterval(statsTimer);
            logStats();
            log("stopping");
            for (const ws of wss.clients) ws.terminate();
            wss.close();
            server.close(() => done());
            server.closeAllConnections?.();
          })),
      });
    });
  });
}

// Started directly (node server.js): read the environment.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let relay;
  try {
    relay = await start({
      port: envNumber("PORT", 7710),
      host: process.env.HOST || undefined,
      trustProxy: process.env.CLIPWAY_TRUST_PROXY === "1",
      ttlMs: Math.min(envNumber("CLIPWAY_TTL_H", 24), 24) * HOUR,
      maxTotalBytes: envNumber("CLIPWAY_MAX_TOTAL_MB", 256) * MIB,
      pingMs: envNumber("CLIPWAY_PING_S", 240) * 1000,
      deadMs: envNumber("CLIPWAY_DEAD_S", 600) * 1000,
    });
  } catch (e) {
    console.error(new Date().toISOString(), "error: cannot start:", e?.code ?? e?.message);
    process.exit(1);
  }
  const quit = () => relay.stop().then(() => process.exit(0));
  process.on("SIGTERM", quit);
  process.on("SIGINT", quit);
}
