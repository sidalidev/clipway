// Clipway cryptography (see docs/PROTOCOL.md).
// Pure, stateless functions shared by the relay, its tests and tools/gen-vectors.mjs.
// Same construction as the Sonne sync chain (HKDF-SHA256, AES-256-GCM, BIP39), with
// Clipway labels so that a Sonne chain can never be used here by mistake.
// Everything relies on node:crypto, no external dependency.

import { createHash, createHmac, createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { WORDS } from "./bip39-english.js";

/** Size of the chain secret S in bytes (128 bits). */
export const SECRET_SIZE = 16;
/** Size of the proof P in bytes. */
export const PROOF_SIZE = 16;
/** Size of a GCM nonce in bytes. */
export const NONCE_SIZE = 12;
/** Size of a GCM tag in bytes. */
export const TAG_SIZE = 16;

/** Reference relay. Any relay can be set in the apps. */
export const DEFAULT_RELAY = "https://clip.sidali.dev";
/** Pairing QR code: clipway:<base64url(S)>, optionally followed by ?relay=<url>. */
export const QR_PREFIX = "clipway:";

/** Protocol version, in every message and in the WebSocket subprotocol. */
export const PROTOCOL_VERSION = 1;
/** Largest text (UTF-8 bytes): 64 KiB, in one envelope (section 3.1). */
export const TEXT_MAX = 65_536;
/** Largest image or file, sent directly between devices on their local network (section 14). */
export const FILE_MAX = 26_214_400;
/** Content bytes in each chunk of an image or a file sent through the relay (section 15), the last one shorter. */
export const CHUNK_SIZE = 65_536;
/**
 * Largest image or file sent through the relay, cut in chunks (section 15): 4 MiB, 64 chunks. Its
 * envelopes take 64 x 87 404 base64 characters plus the head, under the 6 MiB queue of a chain.
 */
export const RELAY_FILE_MAX = 4_194_304;
/** Most chunks of one item, and most parts (the head, then the chunks). */
export const CHUNKS_MAX = RELAY_FILE_MAX / CHUNK_SIZE;
export const PARTS_MAX = CHUNKS_MAX + 1;
/** The head plaintext is padded with spaces to a multiple of this many bytes. */
export const PAD_BLOCK = 512;
/**
 * Largest head plaintext: a 64 KiB text in base64 (87 384 bytes), the other fields of the largest
 * head (under 700 bytes, a 64-character device name of escaped control characters included) and
 * the padding, rounded up to a multiple of 512: 172 x 512.
 */
export const HEAD_MAX = 88_064;
/** Largest enc string of an envelope the relay accepts: base64 of HEAD_MAX + the 16-byte tag. */
export const ENC_MAX = Math.ceil((HEAD_MAX + 16) / 3) * 4;
/** Content fingerprint size in bytes. */
export const FP_SIZE = 16;

/**
 * What a head can be. An image or a file travels directly (an offer stands for it), or through
 * the relay in chunks (a chunked head, followed by its chunks).
 */
export const TYPES = Object.freeze(["text", "hello", "offer", "reply", "chunked"]);
/** What an offer or a chunked item carries. */
export const MEDIA = Object.freeze(["image", "file"]);
/** Answers to an offer, sent through the relay (only "done" also travels on the direct connection). */
export const REPLY_STATUS = Object.freeze(["done", "unreachable", "declined", "failed"]);
/** Addresses an offer lists at most. */
export const HOSTS_MAX = 8;
export const KINDS = Object.freeze(["mac", "android"]);
export const TEXT_MIME = "text/plain";
export const NAME_MAX = 255;
export const DEVICE_NAME_MAX = 64;

const RE_HEX = /^[0-9a-f]*$/i;
const RE_ID = /^[0-9a-f]{32}$/;
const RE_NONCE = /^[0-9a-f]{24}$/;
const RE_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const RE_MIME = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/;
const RE_IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Normalizes S: a Buffer, a Uint8Array or 32 hex characters. Always returns a new 16-byte Buffer. */
function secret(S) {
  let bytes;
  if (typeof S === "string") {
    if (S.length !== SECRET_SIZE * 2 || !RE_HEX.test(S)) throw new Error("Invalid secret: 32 hex characters expected");
    bytes = Buffer.from(S, "hex");
  } else if (S instanceof Uint8Array) {
    bytes = Buffer.from(S);
  } else {
    throw new Error("Invalid secret: Buffer, Uint8Array or hex string expected");
  }
  if (bytes.length !== SECRET_SIZE) throw new Error(`Invalid secret: ${SECRET_SIZE} bytes expected`);
  return bytes;
}

/** A nonce given as hex or bytes, of the expected size. */
function nonceBytes(nonce) {
  const bytes =
    typeof nonce === "string" && RE_HEX.test(nonce) && nonce.length % 2 === 0
      ? Buffer.from(nonce, "hex")
      : nonce instanceof Uint8Array
        ? Buffer.from(nonce)
        : null;
  if (!bytes || bytes.length !== NONCE_SIZE) throw new Error(`Invalid nonce: ${NONCE_SIZE} bytes expected`);
  return bytes;
}

/** HKDF-SHA256 with an empty salt (RFC 5869: same as 32 zero bytes). */
export function hkdf(S, info, length = 32) {
  return Buffer.from(hkdfSync("sha256", S, Buffer.alloc(0), Buffer.from(info, "utf8"), length));
}

function key32(k) {
  const b = k instanceof Uint8Array ? Buffer.from(k) : null;
  if (!b || b.length !== 32) throw new Error("Invalid key: 32 bytes expected");
  return b;
}

// ---------------------------------------------------------------------------
// Secret, proof, chain id and keys
// ---------------------------------------------------------------------------

/** Draws a new secret S (16 bytes from the system CSPRNG). */
export function generateSecret() {
  return randomBytes(SECRET_SIZE);
}

/**
 * Proof P = HKDF-SHA256(S, empty salt, "clipway-proof", 16 bytes).
 * Every device shows it to the relay when it connects: it proves that the device holds S
 * without revealing S or the keys.
 */
export function deriveProof(S) {
  return hkdf(secret(S), "clipway-proof", PROOF_SIZE);
}

/** Chain id = hex(SHA-256("clipway-id" || P))[0:32]. The relay computes it from P. */
export function idFromProof(P) {
  const p = P instanceof Uint8Array ? Buffer.from(P) : null;
  if (!p || p.length !== PROOF_SIZE) throw new Error(`Invalid proof: ${PROOF_SIZE} bytes expected`);
  return createHash("sha256").update(Buffer.from("clipway-id", "utf8")).update(p).digest("hex").slice(0, 32);
}

/** Chain id from S. */
export function deriveId(S) {
  return idFromProof(deriveProof(S));
}

/** True if the value looks like a chain id, an item id or a device id (32 lowercase hex). */
export function isValidId(id) {
  return typeof id === "string" && RE_ID.test(id);
}

/**
 * K_enc = HKDF-SHA256(S, empty salt, "clipway-enc", 32): AES-256-GCM key of every envelope.
 * K_mac = HKDF-SHA256(S, empty salt, "clipway-mac", 32): HMAC key of the content fingerprint.
 */
export function deriveKeys(S) {
  const s = secret(S);
  return { enc: hkdf(s, "clipway-enc"), mac: hkdf(s, "clipway-mac") };
}

/** fp = hex(HMAC-SHA256(K_mac, content)[0:16]). Checked after reassembly; used for echo and duplicates. */
export function fingerprint(kMac, content) {
  return createHmac("sha256", key32(kMac)).update(Buffer.from(content)).digest().subarray(0, FP_SIZE).toString("hex");
}

// ---------------------------------------------------------------------------
// Envelope: AES-256-GCM, same format as Sonne's encrypted state
// ---------------------------------------------------------------------------

/**
 * Seals bytes: { nonce: hex(12 bytes), enc: base64(ciphertext || 16-byte tag) }.
 * aad is a string, authenticated as UTF-8. A random nonce is drawn when none is given.
 */
export function seal(kEnc, aad, plaintext, nonce = randomBytes(NONCE_SIZE)) {
  const iv = nonceBytes(nonce);
  const c = createCipheriv("aes-256-gcm", key32(kEnc), iv);
  c.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  return { nonce: iv.toString("hex"), enc: Buffer.concat([body, c.getAuthTag()]).toString("base64") };
}

/** True if the value has the shape of an envelope (does not decrypt). */
export function isEnvelope(e) {
  return (
    !!e &&
    typeof e === "object" &&
    !Array.isArray(e) &&
    typeof e.nonce === "string" &&
    RE_NONCE.test(e.nonce) &&
    typeof e.enc === "string" &&
    e.enc.length >= 24 &&
    e.enc.length % 4 === 0 &&
    RE_BASE64.test(e.enc)
  );
}

/** Opens an envelope and returns the plaintext bytes. Throws if the key, the aad or the bytes do not match. */
export function open(kEnc, aad, envelope) {
  if (!isEnvelope(envelope)) throw new Error("Invalid envelope");
  const data = Buffer.from(envelope.enc, "base64");
  if (data.length < TAG_SIZE) throw new Error("Invalid envelope: too short");
  const d = createDecipheriv("aes-256-gcm", key32(kEnc), Buffer.from(envelope.nonce, "hex"));
  d.setAAD(Buffer.from(aad, "utf8"));
  d.setAuthTag(data.subarray(data.length - TAG_SIZE));
  try {
    return Buffer.concat([d.update(data.subarray(0, data.length - TAG_SIZE)), d.final()]);
  } catch {
    throw new Error("Unreadable envelope: authentication failed");
  }
}

// ---------------------------------------------------------------------------
// Head (the JSON message) and chunks
// ---------------------------------------------------------------------------

/**
 * Pads a serialized head: the "pad" field (spaces) is added before the final "}" so that the
 * UTF-8 length is the smallest multiple of PAD_BLOCK that is at least the length + 9
 * (9 = length of ,"pad":"" ). Input: JSON without a pad field, ending with "}".
 */
export function padHead(json) {
  if (typeof json !== "string" || !json.endsWith("}") || json.length < 2) throw new Error("Invalid head JSON");
  const length = Buffer.byteLength(json, "utf8");
  const total = Math.ceil((length + 9) / PAD_BLOCK) * PAD_BLOCK;
  return `${json.slice(0, -1)},"pad":"${" ".repeat(total - length - 9)}"}`;
}

/** True for a dotted IPv4 address (0.0.0.0 to 255.255.255.255, no leading zeros). */
export function isIPv4(host) {
  return typeof host === "string" && RE_IPV4.test(host);
}

/**
 * Serializes a head in the reference order, without spaces, then pads it. Readers accept any order.
 *   all:   v, type, item, device{id,name,kind}, ts
 *   text:  mime, size, fp, data
 *   offer: media, mime, name (optional for an image), size, fp, port, hosts
 *   reply: offer, status
 *   chunked: media, mime, name (optional for an image), size, fp, chunks
 */
export function serializeHead(head) {
  const o = { v: head.v, type: head.type, item: head.item, device: { id: head.device.id, name: head.device.name, kind: head.device.kind }, ts: head.ts };
  if (head.type === "text") {
    o.mime = head.mime;
    o.size = head.size;
    o.fp = head.fp;
    o.data = head.data;
  } else if (head.type === "offer") {
    o.media = head.media;
    o.mime = head.mime;
    if (head.name !== undefined) o.name = head.name;
    o.size = head.size;
    o.fp = head.fp;
    o.port = head.port;
    o.hosts = [...head.hosts];
  } else if (head.type === "reply") {
    o.offer = head.offer;
    o.status = head.status;
  } else if (head.type === "chunked") {
    o.media = head.media;
    o.mime = head.mime;
    if (head.name !== undefined) o.name = head.name;
    o.size = head.size;
    o.fp = head.fp;
    o.chunks = head.chunks;
  }
  return padHead(JSON.stringify(o));
}

/**
 * Checks a decrypted head and returns a clean copy (protocol fields only, pad dropped).
 * Throws with a short reason when a rule is broken. Unknown fields are ignored.
 * A head of type image or file (Clipway 0.2 and earlier) is refused: an image or a file travels
 * directly (offer) or in chunks (chunked), and a chunks field is only valid in a chunked head.
 */
export function validateHead(h) {
  const fail = (why) => {
    throw new Error(`Invalid head: ${why}`);
  };
  if (!h || typeof h !== "object" || Array.isArray(h)) fail("not an object");
  if (h.v !== PROTOCOL_VERSION) fail("unknown version");
  if (!TYPES.includes(h.type)) fail(MEDIA.includes(h.type) ? "images and files travel directly or in chunks" : "unknown type");
  if (h.type !== "chunked" && h.chunks !== undefined) fail("chunks");
  if (!isValidId(h.item)) fail("item");
  const d = h.device;
  if (!d || typeof d !== "object" || !isValidId(d.id)) fail("device.id");
  if (typeof d.name !== "string" || d.name.length < 1 || [...d.name].length > DEVICE_NAME_MAX) fail("device.name");
  if (!KINDS.includes(d.kind)) fail("device.kind");
  if (!Number.isSafeInteger(h.ts) || h.ts < 0) fail("ts");
  const clean = { v: h.v, type: h.type, item: h.item, device: { id: d.id, name: d.name, kind: d.kind }, ts: h.ts };
  if (h.type === "hello") return clean;

  if (h.type === "reply") {
    if (!isValidId(h.offer)) fail("offer");
    if (!REPLY_STATUS.includes(h.status)) fail("status");
    return Object.assign(clean, { offer: h.offer, status: h.status });
  }

  if (typeof h.mime !== "string" || !RE_MIME.test(h.mime)) fail("mime");
  if (!Number.isSafeInteger(h.size) || h.size < 0) fail("size");
  if (typeof h.fp !== "string" || !/^[0-9a-f]{32}$/.test(h.fp)) fail("fp");

  if (h.type === "text") {
    if (h.mime !== TEXT_MIME) fail("text mime");
    if (h.size > TEXT_MAX) fail("too big");
    if (h.name !== undefined) fail("text with name");
    if (typeof h.data !== "string" || h.data.length % 4 !== 0 || !RE_BASE64.test(h.data)) fail("data");
    if (Buffer.from(h.data, "base64").length !== h.size) fail("data length");
    return Object.assign(clean, { mime: h.mime, size: h.size, fp: h.fp, data: h.data });
  }

  // offer and chunked
  if (!MEDIA.includes(h.media)) fail("media");
  if (h.media === "image" && !h.mime.startsWith("image/")) fail("image mime");
  if (h.size > (h.type === "chunked" ? RELAY_FILE_MAX : FILE_MAX)) fail("too big");
  if (h.media === "file" && h.name === undefined) fail("file without name");
  if (h.name !== undefined && (typeof h.name !== "string" || h.name.length < 1 || [...h.name].length > NAME_MAX)) fail("name");
  if (h.data !== undefined) fail(h.type === "chunked" ? "the content is in the chunks" : "an offer carries no content");
  if (h.type === "chunked") {
    if (h.chunks !== chunkCount(h.size)) fail("chunks");
    Object.assign(clean, { media: h.media, mime: h.mime });
    if (h.name !== undefined) clean.name = h.name;
    return Object.assign(clean, { size: h.size, fp: h.fp, chunks: h.chunks });
  }
  if (!Number.isSafeInteger(h.port) || h.port < 1 || h.port > 65_535) fail("port");
  if (!Array.isArray(h.hosts) || h.hosts.length < 1 || h.hosts.length > HOSTS_MAX || !h.hosts.every(isIPv4)) fail("hosts");
  Object.assign(clean, { media: h.media, mime: h.mime });
  if (h.name !== undefined) clean.name = h.name;
  return Object.assign(clean, { size: h.size, fp: h.fp, port: h.port, hosts: [...h.hosts] });
}

/** Encrypts a serialized (padded) head: AAD = chain id. */
export function encryptHead(S, headJson, nonce) {
  const { enc } = deriveKeys(S);
  return seal(enc, deriveId(S), Buffer.from(headJson, "utf8"), nonce);
}

/** Decrypts and validates a head envelope. */
export function decryptHead(S, envelope) {
  const { enc } = deriveKeys(S);
  const text = open(enc, deriveId(S), envelope).toString("utf8");
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error("Invalid head: not JSON");
  }
  return validateHead(obj);
}

/** Number of chunks of a content of `size` bytes sent through the relay: ceil(size / 64 KiB). */
export function chunkCount(size) {
  return Math.ceil(size / CHUNK_SIZE);
}

/** AAD of chunk `index` (from 0) of an item: binds the chain, the item, the position and the count. */
export function chunkAad(chainId, item, index, chunks) {
  return `clipway-chunk|${chainId}|${item}|${index}|${chunks}`;
}

/**
 * Builds the envelopes of an item, ready to be sent to the relay.
 * input: { type, item?, device: { id, name, kind }, ts, ...fields }
 *   text:    content (Buffer, UTF-8, at most 64 KiB)
 *   offer:   media, mime, name?, content (Buffer: only its size and fingerprint go in the offer), port, hosts
 *   reply:   offer, status
 *   chunked: media, mime, name?, content (Buffer, at most 4 MiB): the head, then one envelope per chunk
 * options.nonce: a fixed nonce for the head; options.nonces: fixed nonces for every part, the head
 * first (tests and vectors only).
 * Returns { head, headJson, envelopes } (one envelope, or 1 + chunks for a chunked item).
 */
export function buildItem(S, input, options = {}) {
  const { mac } = deriveKeys(S);
  const head = {
    v: PROTOCOL_VERSION,
    type: input.type,
    item: input.item ?? randomBytes(16).toString("hex"),
    device: input.device,
    ts: input.ts,
  };
  if (input.type === "text") {
    const content = Buffer.from(input.content ?? Buffer.alloc(0));
    Object.assign(head, { mime: TEXT_MIME, size: content.length, fp: fingerprint(mac, content), data: content.toString("base64") });
  } else if (input.type === "offer") {
    const content = Buffer.from(input.content ?? Buffer.alloc(0));
    Object.assign(head, { media: input.media, mime: input.mime });
    if (input.name !== undefined) head.name = input.name;
    Object.assign(head, { size: content.length, fp: fingerprint(mac, content), port: input.port, hosts: input.hosts });
  } else if (input.type === "reply") {
    Object.assign(head, { offer: input.offer, status: input.status });
  }
  let content = null;
  if (input.type === "chunked") {
    content = Buffer.from(input.content ?? Buffer.alloc(0));
    Object.assign(head, { media: input.media, mime: input.mime });
    if (input.name !== undefined) head.name = input.name;
    Object.assign(head, { size: content.length, fp: fingerprint(mac, content), chunks: chunkCount(content.length) });
  }
  validateHead(head);
  const headJson = serializeHead(head);
  if (Buffer.byteLength(headJson, "utf8") > HEAD_MAX) throw new Error("Invalid head: too large");
  const envelopes = [encryptHead(S, headJson, options.nonce ?? options.nonces?.[0])];
  if (content) {
    const { enc } = deriveKeys(S);
    const id = deriveId(S);
    for (let i = 0; i < head.chunks; i++) {
      const slice = content.subarray(i * CHUNK_SIZE, Math.min(content.length, (i + 1) * CHUNK_SIZE));
      envelopes.push(seal(enc, chunkAad(id, head.item, i, head.chunks), slice, options.nonces?.[i + 1]));
    }
  }
  return { head, headJson, envelopes };
}

/**
 * Reads one item from its envelopes: one, or the head and its chunks for a chunked item. Checks
 * the size and fingerprint of a text or of the content put back together from the chunks.
 * Returns { head, content } (content null for hello, offer and reply).
 */
export function readItem(S, envelopes) {
  if (!Array.isArray(envelopes) || envelopes.length < 1 || envelopes.length > PARTS_MAX) throw new Error("Invalid item: wrong number of parts");
  const head = decryptHead(S, envelopes[0]);
  const parts = head.type === "chunked" ? 1 + head.chunks : 1;
  if (envelopes.length !== parts) throw new Error("Invalid item: wrong number of parts");
  if (head.type !== "text" && head.type !== "chunked") return { head, content: null };
  let content;
  if (head.type === "chunked") {
    const { enc } = deriveKeys(S);
    const id = deriveId(S);
    const chunks = [];
    for (let i = 0; i < head.chunks; i++) {
      const chunk = open(enc, chunkAad(id, head.item, i, head.chunks), envelopes[i + 1]);
      // Every chunk is full but the last, which is not empty.
      const expected = i < head.chunks - 1 ? CHUNK_SIZE : head.size - i * CHUNK_SIZE;
      if (chunk.length !== expected) throw new Error("Invalid item: size mismatch");
      chunks.push(chunk);
    }
    content = Buffer.concat(chunks);
  } else {
    content = Buffer.from(head.data, "base64");
  }
  if (content.length !== head.size) throw new Error("Invalid item: size mismatch");
  if (fingerprint(deriveKeys(S).mac, content) !== head.fp) throw new Error("Invalid item: fingerprint mismatch");
  return { head, content };
}

// ---------------------------------------------------------------------------
// 12 BIP39 words (128 bits + 4 checksum bits)
// ---------------------------------------------------------------------------

/** S to 12 English BIP39 words, exactly like a Bitcoin wallet. */
export function toWords(S) {
  const s = secret(S);
  const checksum = createHash("sha256").update(s).digest()[0] >> 4;
  let bits = 0n;
  for (const byte of s) bits = (bits << 8n) | BigInt(byte);
  bits = (bits << 4n) | BigInt(checksum);
  const words = [];
  for (let i = 11; i >= 0; i--) words.push(WORDS[Number((bits >> BigInt(i * 11)) & 0x7ffn)]);
  return words;
}

/**
 * 12 words (array or space separated string) to S. Case and extra spaces are ignored.
 * Throws if a word is unknown, if there are not 12 words, or if the checksum is wrong.
 */
export function fromWords(words) {
  const list = (Array.isArray(words) ? words.join(" ") : String(words ?? ""))
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (list.length !== 12) throw new Error("Exactly 12 words expected");
  let bits = 0n;
  for (const word of list) {
    const index = WORDS.indexOf(word);
    if (index < 0) throw new Error(`Unknown word: ${word}`);
    bits = (bits << 11n) | BigInt(index);
  }
  const checksum = Number(bits & 0xfn);
  let entropy = bits >> 4n;
  const s = Buffer.alloc(SECRET_SIZE);
  for (let i = SECRET_SIZE - 1; i >= 0; i--) {
    s[i] = Number(entropy & 0xffn);
    entropy >>= 8n;
  }
  if (checksum !== createHash("sha256").update(s).digest()[0] >> 4) throw new Error("Wrong checksum: check the words");
  return s;
}

// ---------------------------------------------------------------------------
// Pairing QR code: clipway:<base64url(S)>[?relay=<percent-encoded https URL>]
// ---------------------------------------------------------------------------

/** S to QR text. The relay is added only when it is not the default one. */
export function toQr(S, relay = DEFAULT_RELAY) {
  const base = `${QR_PREFIX}${secret(S).toString("base64url")}`;
  const r = String(relay ?? "").replace(/\/+$/, "");
  return r && r !== DEFAULT_RELAY ? `${base}?relay=${encodeURIComponent(r)}` : base;
}

/** QR text to { secret, relay } (relay null when absent). Throws if malformed. */
export function fromQr(text) {
  const t = String(text ?? "").trim();
  if (!t.startsWith(QR_PREFIX)) throw new Error("Invalid code: clipway: expected");
  const rest = t.slice(QR_PREFIX.length);
  const q = rest.indexOf("?");
  const value = (q < 0 ? rest : rest.slice(0, q)).replace(/=+$/, "");
  if (!/^[A-Za-z0-9_-]{22}$/.test(value)) throw new Error("Invalid code: malformed key");
  const s = Buffer.from(value, "base64url");
  if (s.length !== SECRET_SIZE) throw new Error("Invalid code: key of the wrong size");
  let relay = null;
  if (q >= 0) {
    const r = new URLSearchParams(rest.slice(q + 1)).get("relay");
    if (r) {
      let u;
      try {
        u = new URL(r);
      } catch {
        throw new Error("Invalid code: malformed relay");
      }
      if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("Invalid code: relay must be http(s)");
      relay = r.replace(/\/+$/, "");
    }
  }
  return { secret: s, relay };
}
