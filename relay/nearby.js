// Nearby pairing over Bluetooth (docs/PROTOCOL.md, section 13): the reference for the Mac and
// Android apps. Pure derivations, plus the Mac's session state machine without any radio, so that
// tools/gen-vectors.mjs can write the exact answers the Mac gives to each Bluetooth request.
// Not used by the relay server (the Docker image does not include this file).
// node:crypto only: X25519, HKDF-SHA256, HMAC-SHA256, SHA-256, AES-256-GCM.

import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  timingSafeEqual,
} from "node:crypto";
import { seal, open, toQr, fromQr, DEFAULT_RELAY, NONCE_SIZE, TAG_SIZE } from "./crypto.js";

/** GATT service of nearby pairing, version 1. A new incompatible version uses a new UUID. */
export const SERVICE_UUID = "a4985110-4541-4fcc-bcac-ee9b5ce269d0";

/** Characteristics of the service (13.2). */
export const CHARACTERISTICS = Object.freeze({
  commit: "a4985111-4541-4fcc-bcac-ee9b5ce269d0",
  phone_key: "a4985112-4541-4fcc-bcac-ee9b5ce269d0",
  mac_key: "a4985113-4541-4fcc-bcac-ee9b5ce269d0",
  confirm: "a4985114-4541-4fcc-bcac-ee9b5ce269d0",
  status: "a4985115-4541-4fcc-bcac-ee9b5ce269d0",
  packet: "a4985116-4541-4fcc-bcac-ee9b5ce269d0",
});

/** Standard descriptor that turns notifications on (CCCD). */
export const CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb";

/** Raw X25519 public or private key (RFC 7748). */
export const KEY_SIZE = 32;
/** Phone confirmation tag. */
export const CONFIRM_SIZE = 16;
/** Packet plaintext: padded JSON, always this many bytes. */
export const PACKET_PLAINTEXT_SIZE = 256;
/** Packet on the air: nonce, ciphertext, tag. */
export const PACKET_SIZE = NONCE_SIZE + PACKET_PLAINTEXT_SIZE + TAG_SIZE;
/** A session (advertising, exchange and both confirmations) lasts this long at most, on each side. */
export const SESSION_MS = 120_000;
/** After the first read of the packet, the Mac waits this long for the phone to finish, then stops. */
export const DELIVERY_GRACE_MS = 10_000;
/** The phone requests this ATT MTU and gives up below MIN_MTU (a 32-byte write plus 3 bytes of header). */
export const REQUEST_MTU = 517;
export const MIN_MTU = 35;

/** Values of the Status characteristic (one byte). */
export const STATUS = Object.freeze({ waiting: 0x00, ready: 0x01, canceled: 0x02, expired: 0x03, failed: 0x04, busy: 0x05 });

/** ATT error codes the Mac answers with (CBATTError raw values). */
export const ATT = Object.freeze({
  readNotPermitted: 0x02,
  writeNotPermitted: 0x03,
  invalidOffset: 0x07,
  invalidAttributeValueLength: 0x0d,
  unlikelyError: 0x0e,
});

/** Labels (UTF-8). */
export const LABELS = Object.freeze({
  commit: "clipway-nearby-commit",
  secret: "clipway-nearby",
  sas: "clipway-nearby-sas",
  key: "clipway-nearby-key",
  confirm: "clipway-nearby-confirm",
  aad: "clipway-nearby",
});

// DER prefixes that wrap a raw X25519 key (the same bytes java.security uses on Android).
export const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
export const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

const utf8 = (s) => Buffer.from(s, "utf8");

function bytes(value, size, what) {
  const b =
    typeof value === "string" && /^[0-9a-f]*$/i.test(value) && value.length % 2 === 0
      ? Buffer.from(value, "hex")
      : value instanceof Uint8Array
        ? Buffer.from(value)
        : null;
  if (!b || b.length !== size) throw new Error(`Invalid ${what}: ${size} bytes expected`);
  return b;
}

/** HKDF-SHA256 with an empty salt, 32 bytes (section 1). */
function hkdf32(ikm, info) {
  return Buffer.from(hkdfSync("sha256", ikm, Buffer.alloc(0), utf8(info), 32));
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

/** A new ephemeral key pair, raw 32-byte keys. */
export function generateKeyPair() {
  const { privateKey } = generateKeyPairSync("x25519");
  const sk = privateKey.export({ format: "der", type: "pkcs8" }).subarray(PKCS8_PREFIX.length);
  return { privateKey: Buffer.from(sk), publicKey: publicFromPrivate(sk) };
}

/** Raw public key of a raw private key. */
export function publicFromPrivate(sk) {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, bytes(sk, KEY_SIZE, "private key")]), format: "der", type: "pkcs8" });
  return Buffer.from(createPublicKey(key).export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length));
}

/**
 * Checks a peer public key before use (13.4): 32 bytes, top bit of the last byte clear, and not
 * our own key sent back. Throws "Key refused".
 */
export function checkPeerKey(pk, ownPk) {
  const p = pk instanceof Uint8Array ? Buffer.from(pk) : null;
  if (!p || p.length !== KEY_SIZE) throw new Error("Key refused: 32 bytes expected");
  if (p[31] & 0x80) throw new Error("Key refused: top bit set");
  if (ownPk && p.equals(Buffer.from(ownPk))) throw new Error("Key refused: our own key");
  return p;
}

/** Z = X25519(own private key, peer public key). Throws "Key refused" for a low-order point (Z all zeros). */
export function sharedSecret(sk, pkPeer) {
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, bytes(sk, KEY_SIZE, "private key")]), format: "der", type: "pkcs8" });
  let z;
  try {
    const pub = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, bytes(pkPeer, KEY_SIZE, "public key")]), format: "der", type: "spki" });
    z = diffieHellman({ privateKey: priv, publicKey: pub });
  } catch {
    throw new Error("Key refused: low-order point");
  }
  if (z.every((b) => b === 0)) throw new Error("Key refused: low-order point");
  return z;
}

// ---------------------------------------------------------------------------
// Derivations (13.4)
// ---------------------------------------------------------------------------

/** commit = SHA-256("clipway-nearby-commit" || pk_mac). */
export function commitment(pkMac) {
  return createHash("sha256").update(utf8(LABELS.commit)).update(bytes(pkMac, KEY_SIZE, "Mac key")).digest();
}

/** T = pk_mac || pk_phone (64 bytes, the Mac first). */
export function transcript(pkMac, pkPhone) {
  return Buffer.concat([bytes(pkMac, KEY_SIZE, "Mac key"), bytes(pkPhone, KEY_SIZE, "phone key")]);
}

/**
 * N = HKDF(Z || T, "clipway-nearby"), K_sas = HKDF(N, "clipway-nearby-sas"),
 * K_key = HKDF(N, "clipway-nearby-key"). All 32 bytes, empty salt.
 */
export function deriveNearby(z, pkMac, pkPhone) {
  const n = hkdf32(Buffer.concat([bytes(z, KEY_SIZE, "shared secret"), transcript(pkMac, pkPhone)]), LABELS.secret);
  return { n, sas: hkdf32(n, LABELS.sas), key: hkdf32(n, LABELS.key) };
}

/** First 6 bytes of HMAC-SHA256(K_sas, T). */
export function sasBytes(kSas, pkMac, pkPhone) {
  return createHmac("sha256", bytes(kSas, 32, "K_sas")).update(transcript(pkMac, pkPhone)).digest().subarray(0, 6);
}

/** 6 bytes, read as an unsigned big-endian integer, modulo 10 000, as 4 digits with leading zeros. */
export function sasFromBytes(six) {
  const b = bytes(six, 6, "SAS bytes");
  return String(b.readUIntBE(0, 6) % 10_000).padStart(4, "0");
}

/** The 4-digit code both screens show. */
export function sasCode(kSas, pkMac, pkPhone) {
  return sasFromBytes(sasBytes(kSas, pkMac, pkPhone));
}

/** confirm = HMAC-SHA256(K_sas, "clipway-nearby-confirm" || T)[0:16], written by the phone after Pair. */
export function confirmTag(kSas, pkMac, pkPhone) {
  return createHmac("sha256", bytes(kSas, 32, "K_sas")).update(utf8(LABELS.confirm)).update(transcript(pkMac, pkPhone)).digest().subarray(0, CONFIRM_SIZE);
}

/** Constant-time comparison of a received confirmation tag. */
export function checkConfirm(kSas, pkMac, pkPhone, tag) {
  const t = tag instanceof Uint8Array ? Buffer.from(tag) : null;
  return !!t && t.length === CONFIRM_SIZE && timingSafeEqual(t, confirmTag(kSas, pkMac, pkPhone));
}

/** AAD of the packet: "clipway-nearby|<hex pk_mac>|<hex pk_phone>" (UTF-8, lowercase hex, 144 bytes). */
export function packetAad(pkMac, pkPhone) {
  return `${LABELS.aad}|${bytes(pkMac, KEY_SIZE, "Mac key").toString("hex")}|${bytes(pkPhone, KEY_SIZE, "phone key").toString("hex")}`;
}

// ---------------------------------------------------------------------------
// Packet (13.5)
// ---------------------------------------------------------------------------

/**
 * {"v":1,"code":"<pairing code>"} padded like a head (3.3), but to exactly 256 bytes:
 * ,"pad":"<spaces>" before the final brace. Throws when the code is too long to fit
 * (the Mac then offers only the QR code).
 */
export function packetPlaintext(code) {
  if (typeof code !== "string" || !code.startsWith("clipway:")) throw new Error("Invalid pairing code");
  const json = JSON.stringify({ v: 1, code });
  const length = Buffer.byteLength(json, "utf8");
  if (length + 9 > PACKET_PLAINTEXT_SIZE) throw new Error("Pairing code too long for nearby pairing");
  return `${json.slice(0, -1)},"pad":"${" ".repeat(PACKET_PLAINTEXT_SIZE - length - 9)}"}`;
}

/** True if the code fits in a packet (the Mac offers Pair nearby only then). */
export function fitsInPacket(code) {
  try {
    packetPlaintext(code);
    return true;
  } catch {
    return false;
  }
}

/** Packet bytes: nonce (12) || AES-256-GCM ciphertext (256) || tag (16) = 284 bytes. */
export function sealPacket(kKey, pkMac, pkPhone, code, nonce) {
  const e = seal(bytes(kKey, 32, "K_key"), packetAad(pkMac, pkPhone), utf8(packetPlaintext(code)), nonce);
  return Buffer.concat([Buffer.from(e.nonce, "hex"), Buffer.from(e.enc, "base64")]);
}

/**
 * Opens a packet and reads it: { code, secret, relay } (relay null for the default relay).
 * Throws on a wrong length, a failed authentication, an unknown version or a malformed code.
 */
export function openPacket(kKey, pkMac, pkPhone, packet) {
  const p = packet instanceof Uint8Array ? Buffer.from(packet) : null;
  if (!p || p.length !== PACKET_SIZE) throw new Error(`Invalid packet: ${PACKET_SIZE} bytes expected`);
  const envelope = { nonce: p.subarray(0, NONCE_SIZE).toString("hex"), enc: p.subarray(NONCE_SIZE).toString("base64") };
  const text = open(bytes(kKey, 32, "K_key"), packetAad(pkMac, pkPhone), envelope).toString("utf8");
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error("Invalid packet: not JSON");
  }
  if (!obj || typeof obj !== "object" || obj.v !== 1) throw new Error("Invalid packet: unknown version");
  if (typeof obj.code !== "string") throw new Error("Invalid packet: code");
  const { secret, relay } = fromQr(obj.code);
  return { code: obj.code, secret, relay };
}

// ---------------------------------------------------------------------------
// Phone side, without radio
// ---------------------------------------------------------------------------

/**
 * What the phone computes once it has read Commit and Mac key and written its key:
 * checks the commitment and the Mac key, then returns { sas, confirm, key }. Throws on any failure.
 */
export function phoneHandshake(skPhone, commit, pkMac) {
  const pkPhone = publicFromPrivate(skPhone);
  const pk = checkPeerKey(pkMac, pkPhone);
  if (!commitment(pk).equals(bytes(commit, 32, "commitment"))) throw new Error("Commitment does not match the Mac key");
  const k = deriveNearby(sharedSecret(skPhone, pk), pk, pkPhone);
  return { pkPhone, sas: sasCode(k.sas, pk, pkPhone), confirm: confirmTag(k.sas, pk, pkPhone), key: k.key };
}

// ---------------------------------------------------------------------------
// Mac side: the session state machine (13.7), without radio
// ---------------------------------------------------------------------------

/**
 * One advertisement of the Pair nearby window. Centrals are named by any string (CoreBluetooth:
 * CBCentral.identifier). Every radio event returns { value } (reads), { ok: true } (writes and
 * subscriptions) or { error: <ATT code> }, and `notify`: the Status bytes sent to the locked
 * phone as a result. Person events (pair, cancel, expire) return { notify }.
 * Options privateKey and nonce are for tests and vectors only.
 */
export class NearbyMacSession {
  constructor({ secret, relay = DEFAULT_RELAY, privateKey, nonce } = {}) {
    this.code = toQr(secret, relay);
    packetPlaintext(this.code); // throws when the relay address is too long: offer the QR code only
    const pair = privateKey ? { privateKey: bytes(privateKey, KEY_SIZE, "private key"), publicKey: publicFromPrivate(privateKey) } : generateKeyPair();
    this.sk = pair.privateKey;
    this.pk = pair.publicKey;
    this.commit = commitment(this.pk);
    this.nonce = nonce;
    this.state = "open"; // open, locked, ready, ended
    this.status = STATUS.waiting;
    this.end = null; // why the session ended: canceled, expired, failed, left, done
    this.central = null;
    this.subscribed = new Set();
    this.macConfirmed = false;
    this.phoneConfirmed = false;
    this.delivered = false;
    this.sas = null;
  }

  /** Subscription to Status (CCCD 0x0001). */
  subscribe(central) {
    if (this.state === "ended") return { error: ATT.writeNotPermitted, notify: [] };
    this.subscribed.add(central);
    return { ok: true, notify: [] };
  }

  /** Unsubscription, which is also how CoreBluetooth tells a peripheral that a central left. */
  unsubscribe(central) {
    this.subscribed.delete(central);
    if (central === this.central && this.state !== "ended") this.#finish(this.delivered ? "done" : "left");
    return { ok: true, notify: [] };
  }

  read(central, characteristic, offset = 0) {
    const value = this.#readValue(central, characteristic);
    if (value.error !== undefined) return { error: value.error, notify: [] };
    if (offset > value.bytes.length) return { error: ATT.invalidOffset, notify: [] };
    if (characteristic === "packet") this.delivered = true;
    return { value: value.bytes.subarray(offset), notify: [] };
  }

  #readValue(central, characteristic) {
    if (this.state === "ended") return { error: ATT.readNotPermitted };
    const locked = this.central !== null;
    const mine = central === this.central;
    switch (characteristic) {
      case "commit":
        return { bytes: this.commit };
      case "status":
        return { bytes: Buffer.from([locked && !mine ? STATUS.busy : this.status]) };
      case "mac_key":
        return mine ? { bytes: this.pk } : { error: ATT.readNotPermitted };
      case "packet":
        return mine && this.state === "ready" ? { bytes: this.packet } : { error: ATT.readNotPermitted };
      default:
        return { error: ATT.readNotPermitted };
    }
  }

  write(central, characteristic, value, offset = 0) {
    const v = Buffer.from(value);
    const notify = [];
    const answer = (r) => ({ ...r, notify });
    if (characteristic === "phone_key") {
      if (offset !== 0) return answer({ error: ATT.invalidOffset });
      if (v.length !== KEY_SIZE) return answer({ error: ATT.invalidAttributeValueLength });
      if (this.state !== "open" || !this.subscribed.has(central)) return answer({ error: ATT.writeNotPermitted });
      let keys;
      try {
        const pkPhone = checkPeerKey(v, this.pk);
        keys = deriveNearby(sharedSecret(this.sk, pkPhone), this.pk, pkPhone);
      } catch {
        return answer({ error: ATT.unlikelyError }); // nothing changes: the advertisement stays open
      }
      this.central = central;
      this.pkPhone = v;
      this.keys = keys;
      this.sas = sasCode(keys.sas, this.pk, v);
      this.state = "locked";
      return answer({ ok: true });
    }
    if (characteristic === "confirm") {
      if (offset !== 0) return answer({ error: ATT.invalidOffset });
      if (v.length !== CONFIRM_SIZE) return answer({ error: ATT.invalidAttributeValueLength });
      if (central !== this.central || this.state !== "locked" || this.phoneConfirmed) return answer({ error: ATT.writeNotPermitted });
      if (!checkConfirm(this.keys.sas, this.pk, this.pkPhone, v)) {
        notify.push(...this.#finish("failed"));
        return answer({ error: ATT.unlikelyError });
      }
      this.phoneConfirmed = true;
      notify.push(...this.#maybeReady());
      return answer({ ok: true });
    }
    return answer({ error: ATT.writeNotPermitted });
  }

  /** The person presses Pair on the Mac (only once the code is shown). */
  pair() {
    if (this.state !== "locked" || this.macConfirmed) return { notify: [] };
    this.macConfirmed = true;
    return { notify: this.#maybeReady() };
  }

  /** Cancel, the window closed, or Show a code instead. */
  cancel() {
    return { notify: this.state === "ended" ? [] : this.#finish("canceled") };
  }

  /** SESSION_MS passed. A ready session is not cut: it ends when the phone leaves or after DELIVERY_GRACE_MS. */
  expire() {
    return { notify: this.state === "ended" || this.state === "ready" ? [] : this.#finish("expired") };
  }

  /** DELIVERY_GRACE_MS after the first read of the packet. */
  graceOver() {
    return { notify: this.state === "ready" && this.delivered ? this.#finish("done") : [] };
  }

  #maybeReady() {
    if (!this.macConfirmed || !this.phoneConfirmed) return [];
    this.packet = sealPacket(this.keys.key, this.pk, this.pkPhone, this.code, this.nonce);
    this.state = "ready";
    this.status = STATUS.ready;
    return this.#notifyStatus();
  }

  #finish(reason) {
    const statusOf = { canceled: STATUS.canceled, expired: STATUS.expired, failed: STATUS.failed };
    this.end = reason;
    let out = [];
    if (statusOf[reason] !== undefined) {
      this.status = statusOf[reason];
      out = this.#notifyStatus();
    }
    this.state = "ended";
    this.sas = null;
    this.sk = null;
    this.keys = null;
    this.packet = null;
    return out;
  }

  #notifyStatus() {
    return this.central !== null && this.subscribed.has(this.central) ? [this.status] : [];
  }
}
