// tools/update-manifest.mjs: update.json of a release, and the Ed25519 signature of the Mac zip.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { publicKeyBase64, signFile, verifyFile, sha256File } from "../../tools/update-manifest.mjs";

const TOOL = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../tools/update-manifest.mjs");

function folder(t) {
  const d = mkdtempSync(path.join(tmpdir(), "clipway-manifest-"));
  t.after(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

const keyPem = () => generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" });

test("Ed25519: a signed zip verifies, a changed byte or another key does not", (t) => {
  const dir = folder(t);
  const zip = path.join(dir, "clipway-mac-0.4.1.zip");
  writeFileSync(zip, Buffer.alloc(4096, 7));
  const key = keyPem();
  const pub = publicKeyBase64(key);
  assert.equal(Buffer.from(pub, "base64").length, 32);
  const sig = signFile(zip, key);
  assert.equal(Buffer.from(sig, "base64").length, 64);
  assert.equal(verifyFile(zip, sig, pub), true);
  assert.equal(verifyFile(zip, sig, publicKeyBase64(keyPem())), false);
  const changed = Buffer.alloc(4096, 7);
  changed[100] = 8;
  writeFileSync(zip, changed);
  assert.equal(verifyFile(zip, sig, pub), false);
  assert.equal(verifyFile(zip, sig, "short"), false);
});

test("RFC 8032 test 1: the public key and the signature of the empty message", (t) => {
  const dir = folder(t);
  // Secret key of RFC 8032, section 7.1, test 1, in PKCS#8.
  const seed = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
  const pem = `-----BEGIN PRIVATE KEY-----\n${Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]).toString("base64")}\n-----END PRIVATE KEY-----\n`;
  assert.equal(Buffer.from(publicKeyBase64(pem), "base64").toString("hex"), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  const empty = path.join(dir, "empty");
  writeFileSync(empty, "");
  assert.equal(
    Buffer.from(signFile(empty, pem), "base64").toString("hex"),
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  );
});

test("command line: writes update.json, refuses another key", (t) => {
  const dir = folder(t);
  const apk = path.join(dir, "clipway-0.4.1.apk");
  const zip = path.join(dir, "clipway-mac-0.4.1.zip");
  const notes = path.join(dir, "notes.md");
  const key = path.join(dir, "key.pem");
  writeFileSync(apk, "apk bytes");
  writeFileSync(zip, "zip bytes");
  writeFileSync(notes, "**New**\n\n- Automatic updates.\n");
  const pem = keyPem();
  writeFileSync(key, pem);
  const run = ({ version = "0.4.1", out = "out", pub = publicKeyBase64(pem) } = {}) =>
    execFileSync(process.execPath, [
      TOOL, "--version", version, "--out", path.join(dir, out), "--notes", notes,
      "--apk", apk, "--version-code", "7", "--cert-sha256", "0B:48:" + "ab".repeat(30),
      "--zip", zip, "--mac-build", "7", "--key", key, "--public-key", pub,
    ], { stdio: "pipe" });
  run();
  const m = JSON.parse(readFileSync(path.join(dir, "out/update.json"), "utf8"));
  assert.equal(m.version, "0.4.1");
  assert.deepEqual(m.android, {
    version: "0.4.1", versionCode: 7, url: "https://clip.sidali.dev/download/clipway-0.4.1.apk",
    sha256: sha256File(apk), size: 9, certSha256: "0b48" + "ab".repeat(30),
  });
  assert.equal(m.mac.build, 7);
  assert.equal(m.mac.sha256, sha256File(zip));
  assert.equal(verifyFile(zip, m.mac.ed25519, publicKeyBase64(pem)), true);
  assert.equal(m.notes, "**New**\n\n- Automatic updates.");
  assert.equal(m.mac.minimumSystemVersion, "14.0");
  assert.equal(m.mac.url, "https://clip.sidali.dev/download/clipway-mac-0.4.1.zip");

  // Signed with a key the Mac app does not know: nothing is written.
  assert.throws(() => run({ out: "other", pub: publicKeyBase64(keyPem()) }));
  assert.throws(() => readFileSync(path.join(dir, "other/update.json")));
  // Files not named after the version.
  assert.throws(() => run({ version: "0.4.2", out: "other" }));
});
