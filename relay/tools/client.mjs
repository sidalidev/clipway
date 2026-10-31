#!/usr/bin/env node
// Clipway test client: a small command line device for the relay (see docs/PROTOCOL.md).
// It speaks the real protocol with the reference cryptography in ../crypto.js, so it can stand in
// for the Mac or the phone while the other side is tested.
//
//   node tools/client.mjs new                              draw a chain: 12 words and the QR text
//   node tools/client.mjs send   --key K "some text"       send a text (or --stdin; --file PATH goes directly)
//   node tools/client.mjs hello  --key K --name "Test Mac" announce a device name
//   node tools/client.mjs listen --key K [--once] [--out DIR]
//   node tools/client.mjs erase  --key K                   DELETE /chain (Erase everything)
//
// K is the QR text (clipway:...), the 12 words in quotes, or S as 32 hex characters. It can also
// come from CLIPWAY_KEY. The relay is --relay, else CLIPWAY_RELAY, else the relay named in the QR
// text, else http://127.0.0.1:7710. --json prints one JSON object per line, for scripts.
// This is a test tool: it prints what it receives, including texts.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";
import WebSocket from "ws";
import { startSender, fetchOffer, OFFER_TTL } from "../direct.js";
import {
  generateSecret,
  deriveProof,
  deriveId,
  buildItem,
  readItem,
  toWords,
  fromWords,
  toQr,
  fromQr,
  DEFAULT_RELAY,
  TEXT_MAX,
  FILE_MAX,
} from "../crypto.js";

const LOCAL_RELAY = "http://127.0.0.1:7710";
const FRESH_PAST = 24 * 3_600_000 + 10 * 60_000;
const FRESH_FUTURE = 10 * 60_000;

const USAGE = `Clipway test client

  node tools/client.mjs new    [--relay URL]
  node tools/client.mjs send   [--key K] [--relay URL] [--name N] [--kind mac|android] [--device HEX]
                               [--wait] [--timeout S] (TEXT | --text TEXT | --stdin | --file PATH [--type image|file] [--mime M]
                               [--port P] [--hosts A,B] [--loopback])
  node tools/client.mjs hello  [--key K] [--relay URL] [--name N] [--kind mac|android] [--device HEX]
  node tools/client.mjs listen [--key K] [--relay URL] [--device HEX] [--once | --count N] [--timeout S]
                               [--out DIR] [--no-ack] [--epoch E --after N] [--loopback] [--extra-hosts A,B]
  node tools/client.mjs erase  [--key K] [--relay URL]

  --key       QR text (clipway:...), the 12 words in quotes, or 32 hex characters (or CLIPWAY_KEY)
  --relay     relay URL (or CLIPWAY_RELAY, or the relay in the QR text; default ${LOCAL_RELAY})
  --device    this device's id (32 hex), so that its own items are recognized; random otherwise
  --wait      send: wait until another device acknowledges the item ("Delivered")
  --file      send: an image or a file, directly: this computer listens (--port, any by default) and the
              relay only passes the encrypted offer; waits until the other device fetched it
  --hosts     send --file: the addresses listed in the offer (default: this computer's private IPv4 ones)
  --loopback  send --file: also list 127.0.0.1; listen: also connect to 127.0.0.1 (tests on one computer)
  --json      one JSON object per line on stdout
Exit codes: 0 done, 1 error, 2 timeout.`;

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const FLAGS = new Set(["wait", "json", "once", "stdin", "no-ack", "help", "loopback"]);

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h") args.help = true;
    else if (a.startsWith("--")) {
      const name = a.slice(2);
      if (FLAGS.has(name)) args[name] = true;
      else if (i + 1 < argv.length) args[name] = argv[++i];
      else fail(`missing value for --${name}`);
    } else args._.push(a);
  }
  return args;
}

let args = { _: [] };
args = parseArgs(process.argv.slice(2));
const command = args._.shift();

function out(event, fields = {}, human = null) {
  if (args.json) process.stdout.write(JSON.stringify({ event, ...fields }) + "\n");
  else if (human !== null) process.stdout.write(human + "\n");
}

function fail(message, code = 1) {
  if (args.json) process.stdout.write(JSON.stringify({ event: "error", message }) + "\n");
  else process.stderr.write(`clipway: ${message}\n`);
  process.exit(code);
}

/** { S, relay } from --key (QR text, 12 words or 32 hex) and --relay. */
function chainFromArgs() {
  const key = String(args.key ?? process.env.CLIPWAY_KEY ?? "").trim();
  if (!key) fail("a key is needed: --key or CLIPWAY_KEY (run `new` to draw one)");
  let S;
  let qrRelay = null;
  try {
    if (key.startsWith("clipway:")) {
      const q = fromQr(key);
      S = q.secret;
      qrRelay = q.relay;
    } else if (/^[0-9a-fA-F]{32}$/.test(key)) S = Buffer.from(key, "hex");
    else S = fromWords(key);
  } catch (e) {
    fail(`invalid key: ${e.message}`);
  }
  const relay = String(args.relay ?? process.env.CLIPWAY_RELAY ?? qrRelay ?? LOCAL_RELAY).replace(/\/+$/, "");
  return { S, relay };
}

function deviceFromArgs() {
  const id = String(args.device ?? randomBytes(16).toString("hex")).toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(id)) fail("--device: 32 hex characters expected");
  const kind = String(args.kind ?? "mac");
  if (kind !== "mac" && kind !== "android") fail("--kind: mac or android");
  const name = String(args.name ?? (kind === "mac" ? "Test Mac" : "Test phone"));
  if (name.length < 1 || name.length > 64) fail("--name: 1 to 64 characters");
  return { id, name, kind };
}

/** https://h gives wss://h/ws, http://h gives ws://h/ws. */
function wsUrl(relay) {
  let u;
  try {
    u = new URL(relay);
  } catch {
    fail(`invalid relay URL: ${relay}`);
  }
  if (u.protocol === "https:") u.protocol = "wss:";
  else if (u.protocol === "http:") u.protocol = "ws:";
  else fail("the relay URL must start with https:// or http://");
  u.pathname = u.pathname.replace(/\/+$/, "") + "/ws";
  u.search = "";
  u.hash = "";
  return u.toString();
}

const timeoutMs = () => {
  const s = Number(args.timeout ?? 30);
  return Number.isFinite(s) && s > 0 ? s * 1000 : 30_000;
};

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/** Opens the WebSocket of a chain and calls handlers.onMessage for every frame. */
function connect(S, relay, handlers) {
  const P = deriveProof(S).toString("hex");
  const ws = new WebSocket(wsUrl(relay), ["clipway.v1", `clipway.p.${P}`], { maxPayload: 4 * 1_048_576 });
  ws.on("unexpected-response", (_req, res) => fail(`relay refused the connection: HTTP ${res.statusCode}`));
  ws.on("error", (e) => fail(`cannot reach the relay: ${e.code ?? e.message}`));
  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString("utf8"));
    } catch {
      return;
    }
    handlers.onMessage(msg);
  });
  ws.on("close", (code, reason) => handlers.onClose?.(code, reason.toString()));
  const send = (obj) => ws.send(JSON.stringify(obj));
  return { ws, send };
}

function guessMime(file) {
  const ext = path.extname(file).toLowerCase().slice(1);
  const types = {
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    heic: "image/heic",
    tif: "image/tiff",
    tiff: "image/tiff",
    pdf: "application/pdf",
    txt: "text/plain",
    md: "text/markdown",
    json: "application/json",
    zip: "application/zip",
  };
  return types[ext] ?? "application/octet-stream";
}

/** Same rule as the apps (PROTOCOL.md 3.5): no separators, controls or leading dot; 120 characters. */
function sanitize(name) {
  let n = String(name ?? "")
    .replace(/[/\\:\u0000-\u001f\u007f]/g, "")
    .replace(/^\.+/, "")
    .trim();
  if (n.length > 120) {
    const ext = path.extname(n).slice(0, 20);
    n = n.slice(0, 120 - ext.length) + ext;
  }
  return n || "file";
}

function freeName(dir, name) {
  const ext = path.extname(name);
  const base = name.slice(0, name.length - ext.length);
  let candidate = name;
  for (let i = 2; existsSync(path.join(dir, candidate)); i++) candidate = `${base} ${i}${ext}`;
  return path.join(dir, candidate);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdNew() {
  const S = generateSecret();
  const relay = String(args.relay ?? process.env.CLIPWAY_RELAY ?? DEFAULT_RELAY).replace(/\/+$/, "");
  const words = toWords(S);
  const qr = toQr(S, relay);
  if (args.json) return out("new", { words, qr, key: S.toString("hex"), chain: deriveId(S).slice(0, 6) });
  console.log("12 words:");
  words.forEach((w, i) => console.log(`  ${String(i + 1).padStart(2)}. ${w}`));
  console.log(`QR text:  ${qr}`);
  console.log(`Use it:   export CLIPWAY_KEY='${qr}'`);
}

/** send and hello: connect, sync without asking for the backlog, upload, wait for stored. */
async function cmdSend(type) {
  const { S, relay } = chainFromArgs();
  const device = deviceFromArgs();
  let input;
  let direct = null;
  if (type === "hello") input = { type: "hello", device, ts: Date.now() };
  else if (args.file) {
    let content;
    try {
      content = readFileSync(args.file);
    } catch (e) {
      fail(`cannot read ${args.file}: ${e.code ?? e.message}`);
    }
    const mime = String(args.mime ?? guessMime(args.file));
    const media = args.type ?? (mime.startsWith("image/") ? "image" : "file");
    if (content.length > FILE_MAX) fail("too large: Clipway sends up to 25 MB");
    // Images and files never go through the relay: listen here, and send only the offer.
    let hosts = args.hosts ? String(args.hosts).split(",").map((h) => h.trim()).filter(Boolean) : undefined;
    if (args.loopback) hosts = [...(hosts ?? []), "127.0.0.1"];
    let sender;
    try {
      sender = await startSender({ S, port: Number(args.port ?? 0), hosts, ttlMs: timeoutMs() });
    } catch (e) {
      fail(`cannot listen: ${e.code ?? e.message}`);
    }
    const item = randomBytes(16).toString("hex");
    const offered = sender.offer(item, content);
    if (!offered.hosts.length) fail("no local network address: connect this computer to a network, or use --hosts or --loopback");
    direct = { sender, item, outcome: offered.outcome };
    input = { type: "offer", item, device, ts: Date.now(), media, mime, name: path.basename(args.file), content, port: offered.port, hosts: offered.hosts };
  } else {
    const text = args.stdin ? readFileSync(0, "utf8") : (args.text ?? args._.join(" "));
    if (!text) fail("nothing to send: give a text, --text, --stdin or --file");
    const content = Buffer.from(text, "utf8");
    if (content.length > TEXT_MAX) fail("text too large: 64 KB at most");
    input = { type: "text", device, ts: Date.now(), content };
  }
  let built;
  try {
    built = buildItem(S, input);
  } catch (e) {
    fail(`cannot build the item: ${e.message}`);
  }
  const ref = 1;
  let devices = 1;
  let seq = null;
  const timer = setTimeout(() => fail(seq === null ? "no answer from the relay" : "not delivered in time", 2), timeoutMs() + 1000);

  if (direct) {
    direct.outcome.then((result) => {
      out("direct", { item: direct.item, result }, result === "done" ? "Fetched directly by the other device" : `Not fetched: ${result}`);
      finish(result === "done" ? 0 : 1);
    });
  }

  const conn = connect(S, relay, {
    onMessage(msg) {
      switch (msg.kind) {
        case "welcome":
          devices = msg.devices;
          // A sender that does not want the backlog: an after beyond any seq.
          conn.send({ kind: "sync", epoch: msg.epoch, after: Number.MAX_SAFE_INTEGER });
          break;
        case "presence":
          devices = msg.devices;
          break;
        case "synced":
          built.envelopes.forEach((blob, part) => conn.send({ kind: "item", ref, part, parts: built.envelopes.length, blob }));
          break;
        case "stored": {
          if (msg.ref !== ref) break;
          seq = msg.seq;
          const state = devices > 1 ? "Sent" : "Waiting for your other device";
          out("stored", { seq, item: built.head.item, type: built.head.type, parts: built.envelopes.length, devices, state }, `${state} (seq ${seq})`);
          if (!args.wait && !direct) finish();
          break;
        }
        case "item": {
          // While a direct transfer waits: the other device may answer that it cannot connect.
          let read = null;
          try {
            read = readItem(S, [msg.blob]);
          } catch {
            read = null;
          }
          if (read?.head.device.id === device.id) break;
          conn.send({ kind: "ack", seq: msg.seq });
          if (direct && read?.head.type === "reply" && read.head.offer === direct.item) direct.sender.cancel(direct.item, read.head.status);
          break;
        }
        case "delivered":
          if (msg.seq !== seq || direct) break;
          out("delivered", { seq }, "Delivered");
          finish();
          break;
        case "error":
          fail(`relay error ${msg.code}: ${msg.message}`);
          break;
        default:
          break;
      }
    },
    onClose(code, reason) {
      fail(`connection closed: ${code} ${reason}`);
    },
  });

  function finish(code = 0) {
    clearTimeout(timer);
    conn.ws.removeAllListeners("close");
    conn.ws.close(1000);
    direct?.sender.close();
    process.exitCode = code;
    setTimeout(() => process.exit(code), 50).unref();
  }
}

/** listen: sync, print every item (texts in full), fetch offered images and files (saved with --out), acknowledge. */
function cmdListen() {
  const { S, relay } = chainFromArgs();
  const ownId = args.device ? String(args.device).toLowerCase() : null;
  const want = args.once ? 1 : args.count ? Number(args.count) : Infinity;
  const outDir = args.out ? path.resolve(String(args.out)) : null;
  if (outDir) mkdirSync(outDir, { recursive: true });
  const seen = new Set();
  const parts = new Map();
  const me = deviceFromArgs();
  let handled = 0;
  let nextRef = 1;
  const timer = Number.isFinite(want) || args.timeout ? setTimeout(() => fail("timeout", 2), timeoutMs()) : null;

  const conn = connect(S, relay, {
    onMessage(msg) {
      switch (msg.kind) {
        case "welcome":
          out("welcome", { epoch: msg.epoch, devices: msg.devices }, `Connected (${msg.devices} device${msg.devices > 1 ? "s" : ""} on the chain)`);
          conn.send({ kind: "sync", epoch: String(args.epoch ?? ""), after: Number(args.after ?? 0) });
          break;
        case "presence":
          out("presence", { devices: msg.devices }, `${msg.devices} device${msg.devices > 1 ? "s" : ""} connected`);
          break;
        case "synced":
          out("synced", { last: msg.last }, `Listening (last seq ${msg.last})`);
          break;
        case "item":
          onPart(msg);
          break;
        case "error":
          out("relay-error", { code: msg.code, message: msg.message }, `Relay error ${msg.code}: ${msg.message}`);
          break;
        default:
          break;
      }
    },
    onClose(code, reason) {
      if (code === 4001) fail("the chain was erased from another device");
      fail(`connection closed: ${code} ${reason}`);
    },
  });

  function onPart(msg) {
    const list = parts.get(msg.seq) ?? [];
    list[msg.part] = msg.blob;
    parts.set(msg.seq, list);
    if (list.filter(Boolean).length < msg.parts) return;
    parts.delete(msg.seq);
    handle(msg.seq, msg.ts, list);
  }

  function handle(seq, relayTs, blobs) {
    let item;
    try {
      item = readItem(S, blobs);
    } catch (e) {
      out("dropped", { seq, reason: e.message }, `Dropped seq ${seq}: ${e.message}`);
      return ack(seq);
    }
    const { head, content } = item;
    if (ownId && head.device.id === ownId) {
      out("own", { seq, item: head.item }, `Own item seq ${seq}, not acknowledged`);
      return;
    }
    const age = Date.now() - head.ts;
    const fresh = age <= FRESH_PAST && age >= -FRESH_FUTURE;
    if (seen.has(head.item) || !fresh) {
      out("dropped", { seq, reason: seen.has(head.item) ? "duplicate" : "stale" }, `Dropped seq ${seq}: ${seen.has(head.item) ? "duplicate" : "stale"}`);
      return ack(seq);
    }
    if (head.type === "offer" && Date.now() - head.ts > OFFER_TTL) {
      out("dropped", { seq, reason: "expired offer" }, `Dropped seq ${seq}: an offer older than 2 minutes`);
      return ack(seq);
    }
    seen.add(head.item);
    const from = head.device;
    const fields = { seq, type: head.type, item: head.item, from, ts: head.ts, relayTs };
    if (head.type === "hello") {
      out("item", fields, `Hello from ${from.name} (${from.kind})`);
    } else if (head.type === "text") {
      const text = content.toString("utf8");
      out("item", { ...fields, mime: head.mime, size: head.size, fp: head.fp, text }, `Text from ${from.name}: ${text}`);
    } else if (head.type === "reply") {
      out("item", { ...fields, offer: head.offer, status: head.status }, `Reply from ${from.name}: ${head.status}`);
    } else {
      // An offer: fetch it directly from the device that offers it, then answer through the relay if it failed.
      ack(seq);
      const label = head.media === "image" ? "Image" : "File";
      fetchOffer({
        S,
        head,
        loopback: !!args.loopback,
        extraHosts: args["extra-hosts"] ? String(args["extra-hosts"]).split(",") : [],
        save: async (content) => {
          let saved = null;
          if (outDir) {
            saved = freeName(outDir, sanitize(head.name ?? `${head.item}.${(head.mime.split("/")[1] ?? "bin").replace(/[^a-z0-9]/g, "")}`));
            writeFileSync(saved, content);
          }
          out(
            "item",
            { ...fields, type: head.media, mime: head.mime, name: head.name ?? null, size: head.size, fp: head.fp, saved, direct: true },
            `${label} from ${from.name}, directly: ${head.name ?? head.mime}, ${head.size} bytes${saved ? `, saved to ${saved}` : ""}`,
          );
        },
      }).then((r) => {
        if (!r.ok) {
          out("direct-failed", { ...fields, reason: r.reason }, `${label} from ${from.name} not received: ${r.reason === "unreachable" ? "not on the same network" : "the transfer failed"}`);
          const reply = buildItem(S, { type: "reply", device: me, ts: Date.now(), offer: head.item, status: r.reason });
          conn.send({ kind: "item", ref: nextRef++, part: 0, parts: 1, blob: reply.envelopes[0] });
        }
        done();
      });
      return;
    }
    ack(seq);
    done();
  }

  function done() {
    handled += 1;
    if (handled >= want) {
      clearTimeout(timer);
      conn.ws.removeAllListeners("close");
      conn.ws.close(1000);
      setTimeout(() => process.exit(0), 50).unref();
    }
  }

  function ack(seq) {
    if (!args["no-ack"]) conn.send({ kind: "ack", seq });
  }
}

async function cmdErase() {
  const { S, relay } = chainFromArgs();
  let res;
  try {
    res = await fetch(`${relay}/chain`, { method: "DELETE", headers: { "X-Clipway-Proof": deriveProof(S).toString("hex") } });
  } catch (e) {
    fail(`cannot reach the relay: ${e.cause?.code ?? e.message}`);
  }
  if (res.status !== 204) fail(`relay answered HTTP ${res.status}`);
  out("erased", { status: res.status }, "Erased on the relay");
}

if (args.help || !command) {
  console.log(USAGE);
  process.exit(command || args.help ? 0 : 1);
}
switch (command) {
  case "new":
    cmdNew();
    break;
  case "send":
    await cmdSend("content");
    break;
  case "hello":
    await cmdSend("hello");
    break;
  case "listen":
    cmdListen();
    break;
  case "erase":
    await cmdErase();
    break;
  default:
    fail(`unknown command ${command}\n\n${USAGE}`);
}
