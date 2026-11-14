#!/usr/bin/env node
// Writes update.json, the update manifest of a release (docs/UPDATES.md), read by both apps:
//   android   version, versionCode, url, SHA-256, size, SHA-256 of the signing certificate
//   mac       version, build, url, SHA-256, size, Ed25519 signature of the zip, minimum macOS
//
//   node tools/update-manifest.mjs --version 0.4.1 --out <dir> --notes <notes.md>
//        --apk <clipway-0.4.1.apk> --version-code 7 --cert-sha256 <hex>
//        --zip <clipway-mac-0.4.1.zip> --mac-build 7 --min-macos 14.0
//        --key <Ed25519 private key, PEM> --public-key <base64, Update.publicKey of mac/ClipwayCore>
//        [--base https://clip.sidali.dev]
//
// The private key only signs here, on the computer that publishes; it is never in the repository or
// on the server. The signature is checked again with --public-key (Update.publicKey of
// mac/ClipwayCore) before anything is written, so a release signed with another key fails here
// rather than on every Mac.

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync, statSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const DEFAULT_BASE = "https://clip.sidali.dev";
const RE_VERSION = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const RE_HEX64 = /^[0-9a-f]{64}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const sha256File = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

/** The public key of an Ed25519 private key (PEM): base64 of the 32 raw bytes, as the Mac app holds it. */
export function publicKeyBase64(privatePem) {
  const der = createPublicKey(createPrivateKey(privatePem)).export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32).toString("base64");
}

/** Ed25519 signature of a file's bytes, base64: what the Mac app and its installer check. */
export function signFile(file, privatePem) {
  return sign(null, readFileSync(file), createPrivateKey(privatePem)).toString("base64");
}

/** Checks an Ed25519 signature against a raw public key in base64. */
export function verifyFile(file, signatureB64, publicB64) {
  const raw = Buffer.from(publicB64, "base64");
  if (raw.length !== 32) return false;
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
  return verify(null, readFileSync(file), key, Buffer.from(signatureB64, "base64"));
}

/** update.json: one entry per platform, the newest version on top. */
export function manifest({ version, android, mac, notes, published = new Date() }) {
  return {
    version,
    android: {
      version: android.version,
      versionCode: android.versionCode,
      url: android.url,
      sha256: android.sha256,
      size: android.size,
      certSha256: android.certSha256,
    },
    mac: {
      version: mac.version,
      build: mac.build,
      url: mac.url,
      sha256: mac.sha256,
      size: mac.size,
      ed25519: mac.ed25519,
      minimumSystemVersion: mac.minimumSystemVersion,
    },
    notes,
    published: published.toISOString(),
  };
}

function main(argv) {
  const opt = (name, fallback) => {
    const i = argv.indexOf("--" + name);
    if (i >= 0 && i + 1 < argv.length) return argv[i + 1];
    if (fallback !== undefined) return fallback;
    throw new Error(`--${name} is required`);
  };
  const version = opt("version");
  const base = opt("base", DEFAULT_BASE).replace(/\/+$/, "");
  const apk = opt("apk");
  const zip = opt("zip");
  const versionCode = Number(opt("version-code"));
  const build = Number(opt("mac-build"));
  const certSha256 = opt("cert-sha256").toLowerCase().replaceAll(":", "");
  const minimumSystemVersion = opt("min-macos", "14.0");
  const out = opt("out");
  const notes = readFileSync(opt("notes"), "utf8").trim();
  const keyPem = readFileSync(opt("key"), "utf8");
  const expectedPublic = opt("public-key");

  if (!RE_VERSION.test(version)) throw new Error("--version: x.y.z expected");
  if (!/^https:\/\/[a-z0-9.-]+$/.test(base)) throw new Error("--base: https://host expected");
  if (!Number.isInteger(versionCode) || versionCode <= 0) throw new Error("--version-code: a positive integer expected");
  if (!Number.isInteger(build) || build <= 0) throw new Error("--mac-build: a positive integer expected");
  if (!RE_HEX64.test(certSha256)) throw new Error("--cert-sha256: 64 hex characters expected");
  if (path.basename(apk) !== `clipway-${version}.apk`) throw new Error(`the APK must be named clipway-${version}.apk`);
  if (path.basename(zip) !== `clipway-mac-${version}.zip`) throw new Error(`the zip must be named clipway-mac-${version}.zip`);
  if (publicKeyBase64(keyPem) !== expectedPublic) throw new Error("this private key does not match Update.publicKey of the Mac app");

  const ed25519 = signFile(zip, keyPem);
  if (!verifyFile(zip, ed25519, expectedPublic)) throw new Error("the Ed25519 signature does not verify");

  const published = new Date();
  const androidEntry = { version, versionCode, url: `${base}/download/${path.basename(apk)}`, sha256: sha256File(apk), size: statSync(apk).size, certSha256 };
  const macEntry = { version, build, url: `${base}/download/${path.basename(zip)}`, sha256: sha256File(zip), size: statSync(zip).size, ed25519, minimumSystemVersion };
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, "update.json"), JSON.stringify(manifest({ version, android: androidEntry, mac: macEntry, notes, published }), null, 2) + "\n");
  console.log(`update.json written in ${out} (zip signed, signature checked)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (e) {
    console.error("update-manifest: " + e.message);
    process.exit(1);
  }
}
