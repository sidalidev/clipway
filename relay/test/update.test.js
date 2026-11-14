// Updates: /update.json and /download/<file>, served read only from the releases folder.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import http from "node:http";
import { relay } from "./helpers.js";
import { downloadName } from "../server.js";

function folder(t) {
  const d = mkdtempSync(path.join(tmpdir(), "clipway-releases-"));
  t.after(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

/** A raw request: the path goes out as is, without the normalization fetch applies (../, %2e). */
function raw(port, target, method = "GET") {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: target, method }, (res) => {
      const parts = [];
      res.on("data", (p) => parts.push(p));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts) }));
    });
    req.on("error", reject);
    req.end();
  });
}

const MANIFEST = {
  version: "0.4.1",
  android: { version: "0.4.1", versionCode: 7, url: "https://clip.sidali.dev/download/clipway-0.4.1.apk", sha256: "a".repeat(64), size: 3, certSha256: "b".repeat(64) },
  mac: { version: "0.4.1", build: 7, url: "https://clip.sidali.dev/download/clipway-mac-0.4.1.zip", sha256: "c".repeat(64), size: 3, ed25519: "AAAA" },
  notes: "Automatic updates",
};

test("download names: two exact forms only", () => {
  for (const ok of ["clipway-0.4.1.apk", "clipway-mac-0.4.1.zip", "clipway-10.20.300.apk"]) assert.equal(downloadName(ok), true, ok);
  for (const bad of [
    "", "update.json", "clipway-0.4.1.zip", "clipway-mac-0.4.1.apk", "clipway-0.4.apk",
    "../clipway-0.4.1.apk", "clipway-0.4.1.apk/", "clipway-0.4.1.apk.sha256", "Clipway-0.4.1.apk",
    "clipway-0.4.1-beta.apk", "clipway-%30.4.1.apk", "clipway-0..4.1.apk", "clipway-12345.0.0.apk", null, 42,
  ]) assert.equal(downloadName(bad), false, String(bad));
});

test("without a releases folder: 404 everywhere", async (t) => {
  const r = await relay(t);
  for (const p of ["/update.json", "/download/clipway-0.4.1.apk"]) {
    assert.equal((await fetch(r.http + p)).status, 404, p);
  }
});

test("manifest and files are served as published", async (t) => {
  const dir = folder(t);
  writeFileSync(path.join(dir, "update.json"), JSON.stringify(MANIFEST));
  writeFileSync(path.join(dir, "clipway-0.4.1.apk"), "apk");
  writeFileSync(path.join(dir, "clipway-mac-0.4.1.zip"), "zip");
  const r = await relay(t, { releasesDir: dir });

  const m = await fetch(r.http + "/update.json");
  assert.equal(m.status, 200);
  assert.match(m.headers.get("content-type"), /^application\/json/);
  assert.equal(m.headers.get("cache-control"), "public, max-age=300");
  assert.equal(m.headers.get("x-content-type-options"), "nosniff");
  assert.deepEqual(await m.json(), MANIFEST);

  const apk = await fetch(r.http + "/download/clipway-0.4.1.apk");
  assert.equal(apk.status, 200);
  assert.equal(apk.headers.get("content-type"), "application/vnd.android.package-archive");
  assert.equal(apk.headers.get("content-disposition"), 'attachment; filename="clipway-0.4.1.apk"');
  assert.equal(await apk.text(), "apk");

  const zip = await fetch(r.http + "/download/clipway-mac-0.4.1.zip");
  assert.equal(zip.headers.get("content-type"), "application/zip");
  assert.equal(await zip.text(), "zip");

  const head = await raw(r.port, "/download/clipway-0.4.1.apk", "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.headers["content-length"], "3");
  assert.equal(head.body.length, 0);
});

test("nothing else of the folder can be reached", async (t) => {
  const dir = folder(t);
  writeFileSync(path.join(dir, "update.json"), JSON.stringify(MANIFEST));
  writeFileSync(path.join(dir, "secret.txt"), "secret-content");
  writeFileSync(path.join(dir, "clipway-0.4.1.apk.sha256"), "secret-content");
  mkdirSync(path.join(dir, "clipway-0.4.2.apk"));
  writeFileSync(path.join(path.dirname(dir), "clipway-0.4.3.apk"), "outside");
  t.after(() => rmSync(path.join(path.dirname(dir), "clipway-0.4.3.apk"), { force: true }));
  symlinkSync(path.join(path.dirname(dir), "clipway-0.4.3.apk"), path.join(dir, "clipway-0.4.4.apk"));
  const r = await relay(t, { releasesDir: dir });
  for (const p of [
    "/download/secret.txt",
    "/download/clipway-0.4.1.apk.sha256",
    "/download/clipway-0.4.2.apk", // a folder
    "/download/clipway-0.4.4.apk", // a link to a file outside
    "/download/../clipway-0.4.3.apk",
    "/download/%2e%2e/clipway-0.4.3.apk",
    "/download/..%2fclipway-0.4.3.apk",
    "/download/update.json",
    "/download/",
    "/update.json/",
  ]) {
    const res = await raw(r.port, p);
    assert.equal(res.status, 404, p);
    assert.doesNotMatch(res.body.toString(), /outside|secret-content/, p);
  }
  assert.equal((await fetch(r.http + "/update.json", { method: "POST" })).status, 404);
});

test("a broken or oversized manifest is not served", async (t) => {
  const dir = folder(t);
  writeFileSync(path.join(dir, "update.json"), "{ not json");
  const lines = [];
  const r = await relay(t, { releasesDir: dir, log: (l) => lines.push(l) });
  assert.equal((await fetch(r.http + "/update.json")).status, 404);
  writeFileSync(path.join(dir, "update.json"), "[1]");
  assert.equal((await fetch(r.http + "/update.json")).status, 404);
  writeFileSync(path.join(dir, "update.json"), JSON.stringify({ notes: "x".repeat(70 * 1024) }));
  assert.equal((await fetch(r.http + "/update.json")).status, 404);
  // The error is logged without any address.
  assert.ok(lines.some((l) => l.includes("error: manifest")));
  assert.ok(lines.every((l) => !l.includes("127.0.0.1")));
});
