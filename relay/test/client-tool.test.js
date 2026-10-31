// tools/client.mjs, the command line device used for integration tests (node --test).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { relay, chainKeys, connect } from "./helpers.js";
import { toQr, toWords } from "../crypto.js";

const TOOL = fileURLToPath(new URL("../tools/client.mjs", import.meta.url));

/** Runs the tool; resolves { code, events, stdout, stderr }. onEvent sees each JSON line as it comes. */
function run(args, { onEvent = () => {}, input = null } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [TOOL, ...args], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let buffer = "";
    const events = [];
    child.stdout.on("data", (d) => {
      stdout += d;
      buffer += d;
      let i;
      while ((i = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, i);
        buffer = buffer.slice(i + 1);
        try {
          const e = JSON.parse(line);
          events.push(e);
          onEvent(e);
        } catch {
          // Human output.
        }
      }
    });
    child.stderr.on("data", (d) => (stderr += d));
    if (input !== null) child.stdin.end(input);
    else child.stdin.end();
    child.on("close", (code) => resolve({ code, events, stdout, stderr }));
  });
}

test("new prints 12 words and the QR text; the QR names the relay when it is not the default one", async () => {
  const a = await run(["new", "--json"]);
  assert.equal(a.code, 0);
  const [e] = a.events;
  assert.equal(e.words.length, 12);
  assert.match(e.qr, /^clipway:[A-Za-z0-9_-]{22}$/);
  const b = await run(["new", "--json", "--relay", "http://127.0.0.1:7710"]);
  assert.match(b.events[0].qr, /\?relay=http%3A%2F%2F127\.0\.0\.1%3A7710$/);
});

test("listen and send: a text through the relay, then a file directly, between two command line devices", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const key = toQr(k.S, r.http);
  let ready;
  const listening = new Promise((resolve) => (ready = resolve));
  const dir = mkdtempSync(path.join(tmpdir(), "clipway-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const listener = run(["listen", "--key", key, "--count", "2", "--json", "--timeout", "20", "--out", dir, "--loopback"], {
    onEvent: (e) => e.event === "synced" && ready(),
  });
  await listening;

  const words = toWords(k.S).join(" ");
  const sent = await run(["send", "--key", words, "--relay", r.http, "--name", "Test Mac", "--wait", "--json", "Hello from the Mac: café ☕"]);
  assert.equal(sent.code, 0, sent.stderr);
  assert.deepEqual(sent.events.map((e) => e.event), ["stored", "delivered"]);
  assert.equal(sent.events[0].state, "Sent");
  assert.equal(sent.events[0].type, "text");

  const content = randomBytes(1_048_576 * 2 + 3);
  const file = path.join(dir, "source.bin");
  writeFileSync(file, content);
  const sentFile = await run(["send", "--key", Buffer.from(k.S).toString("hex"), "--relay", r.http, "--file", file, "--json", "--hosts", "10.255.255.1", "--loopback", "--timeout", "15"]);
  assert.equal(sentFile.code, 0, sentFile.stderr);
  assert.equal(sentFile.events[0].type, "offer");
  assert.equal(sentFile.events[0].parts, 1);
  assert.deepEqual(sentFile.events.at(-1), { event: "direct", item: sentFile.events[0].item, result: "done" });

  const heard = await listener;
  assert.equal(heard.code, 0, heard.stderr);
  const items = heard.events.filter((e) => e.event === "item");
  assert.equal(items[0].type, "text");
  assert.equal(items[0].text, "Hello from the Mac: café ☕");
  assert.deepEqual(items[0].from.name, "Test Mac");
  assert.equal(items[1].type, "file");
  assert.equal(items[1].direct, true);
  assert.equal(items[1].name, "source.bin");
  assert.ok(readFileSync(items[1].saved).equals(content));
  assert.equal(path.basename(items[1].saved), "source 2.bin", "an existing name gets a number");
  assert.equal((await r.health()).items, 0, "the listener acknowledged both");
});

test("send waits for another device; listen ignores its own device's items; hello and erase", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const hex = Buffer.from(k.S).toString("hex");
  const own = randomBytes(16).toString("hex");

  // Nobody else is connected: the item waits on the relay.
  const alone = await run(["send", "--key", hex, "--relay", r.http, "--device", own, "--json", "--stdin"], { input: "queued text" });
  assert.equal(alone.code, 0, alone.stderr);
  assert.equal(alone.events[0].state, "Waiting for your other device");

  const hello = await run(["hello", "--key", hex, "--relay", r.http, "--name", "Pixel 10 Pro", "--kind", "android", "--json"]);
  assert.equal(hello.code, 0, hello.stderr);

  // A listener with the same device id skips the first item (its own) and reads the hello.
  const heard = await run(["listen", "--key", hex, "--relay", r.http, "--device", own, "--once", "--json", "--timeout", "10"]);
  assert.equal(heard.code, 0, heard.stderr);
  assert.deepEqual(heard.events.filter((e) => e.event === "own").length, 1);
  const item = heard.events.find((e) => e.event === "item");
  assert.equal(item.type, "hello");
  assert.deepEqual([item.from.name, item.from.kind], ["Pixel 10 Pro", "android"]);
  assert.equal((await r.health()).items, 1, "its own item is not acknowledged");

  // The real phone reads the queued text.
  const phone = await connect(r, k);
  assert.equal(phone.backlogItems.length, 1);
  phone.ws.close();

  const erased = await run(["erase", "--key", hex, "--relay", r.http, "--json"]);
  assert.deepEqual(erased.events, [{ event: "erased", status: 204 }]);
  assert.equal((await r.health()).items, 0);
});

test("errors: a bad key, a relay that is not there, a timeout", async (t) => {
  const bad = await run(["send", "--key", "not twelve words", "hello"]);
  assert.equal(bad.code, 1);
  assert.match(bad.stderr, /invalid key/);
  const nowhere = await run(["send", "--key", "00".repeat(16), "--relay", "http://127.0.0.1:9", "hello"]);
  assert.equal(nowhere.code, 1);
  assert.match(nowhere.stderr, /cannot reach the relay/);
  const r = await relay(t);
  const quiet = await run(["listen", "--key", "00".repeat(16), "--relay", r.http, "--once", "--timeout", "0.5"]);
  assert.equal(quiet.code, 2);
});

test("a file offered where the other device cannot connect: the reply says so, the sender stops", async (t) => {
  const r = await relay(t);
  const k = chainKeys();
  const hex = Buffer.from(k.S).toString("hex");
  let ready;
  const listening = new Promise((resolve) => (ready = resolve));
  // No --loopback: the listener connects to private addresses only, and none answers.
  const listener = run(["listen", "--key", hex, "--relay", r.http, "--once", "--json", "--timeout", "30"], { onEvent: (e) => e.event === "synced" && ready() });
  await listening;
  const dir = mkdtempSync(path.join(tmpdir(), "clipway-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, "photo.png");
  writeFileSync(file, randomBytes(1000));
  // 127.0.0.1 is listed, but a receiver never connects to it outside tests; 192.0.2.1 is not private.
  const sent = await run(["send", "--key", hex, "--relay", r.http, "--file", file, "--json", "--hosts", "192.0.2.1", "--loopback", "--timeout", "20"]);
  assert.equal(sent.code, 1);
  assert.deepEqual(sent.events.at(-1).result, "unreachable");
  const heard = await listener;
  assert.equal(heard.events.find((e) => e.event === "direct-failed")?.reason, "unreachable");
});
