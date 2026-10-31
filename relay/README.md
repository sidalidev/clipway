# Clipway relay

Passes end-to-end encrypted texts between the devices of a sync chain. It cannot read them: it only knows a random chain id, which it computes from the proof each device presents. Items wait 24 hours at most, in memory, for a device that is offline, then they are erased. Nothing is written to disk.

**Texts only, never images or files.** Without accounts and with end-to-end encryption, nobody can moderate what travels, so the relay refuses to be a way to pass pictures or files around: every item is one envelope of at most the size of a 64 KB text, and anything larger or cut in parts is refused (`too_big`). Images and files go directly from one device to the other on their local network; the relay only passes the encrypted offer that tells the other device where to connect ([../docs/PROTOCOL.md](../docs/PROTOCOL.md), section 14).

Specification: [../docs/PROTOCOL.md](../docs/PROTOCOL.md), section 4. License: [AGPL-3.0](LICENSE). One dependency (`ws`), Node 22.

## Run it locally

```bash
cd relay
npm ci
HOST=127.0.0.1 PORT=7710 npm start      # http://127.0.0.1:7710, WebSocket at ws://127.0.0.1:7710/ws
curl -s http://127.0.0.1:7710/health
npm test                                # node --test: shared vectors, relay, test client
```

Debug builds of the apps accept `http://127.0.0.1:7710` as the relay. The Android emulator reaches it after `adb reverse tcp:7710 tcp:7710`, or at `http://10.0.2.2:7710`.

## Test client

`tools/client.mjs` is a small command line device. It speaks the real protocol with the reference cryptography (`crypto.js`), so it can stand in for the Mac or the phone.

```bash
node tools/client.mjs new --relay http://127.0.0.1:7710     # draws a chain: 12 words and the QR text
export CLIPWAY_KEY='clipway:...'                            # or --key, with the QR text, the 12 words or 32 hex
node tools/client.mjs listen                                # prints what arrives, fetches offered files into --out DIR
node tools/client.mjs send "Hello from the Mac"             # --stdin, --wait for Delivered; --file PATH sends directly
node tools/client.mjs hello --name "Test Mac"               # announces a device name, like a new device
node tools/client.mjs erase                                 # DELETE /chain
```

`send --file` listens on this computer and sends an offer through the relay; `listen` fetches offered images and files directly from the device that offers them (`--loopback` also allows 127.0.0.1, for a test on one computer). `--json` prints one JSON object per line (`welcome`, `presence`, `synced`, `item`, `own`, `dropped`, `stored`, `delivered`, `direct`, `erased`, `error`), for scripts. Exit codes: 0 done, 1 error, 2 timeout. `node tools/client.mjs --help` lists every option. It is a test tool: it prints the texts it receives.

## Host your own relay

You need a small server with Docker (1 vCPU and 512 MB are plenty), a domain name and a TLS reverse proxy. The apps only accept `https://` relays in release builds.

### Docker

The image is distroless (no shell), runs as a non-root user and works with a read-only root file system.

```bash
docker build -t clipway-relay relay
docker run -d --name clipway-relay --restart unless-stopped \
  -p 127.0.0.1:7710:7710 --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e CLIPWAY_TRUST_PROXY=1 clipway-relay
```

Or with Compose: copy `docker-compose.example.yml` next to this folder as `docker-compose.yml`, then `docker compose up -d --build`.

### Reverse proxy

Three rules, whatever the proxy:

1. Terminate TLS and forward WebSocket upgrades to `127.0.0.1:7710` (the `Sec-WebSocket-Protocol` header must pass through).
2. Allow idle WebSocket connections of at least 10 minutes: the relay pings every 4 minutes and the phone every 4.5 minutes.
3. Do not log client addresses. The relay never logs them; a proxy access log would.

Set `CLIPWAY_TRUST_PROXY=1` so that the per-IP limits use the last `X-Forwarded-For` entry (the address the proxy saw). Never set it when the relay is reachable without the proxy.

Caddy:

```
clip.example.org {
	reverse_proxy 127.0.0.1:7710
	log {
		output discard
	}
}
```

nginx (inside the `server` block of your TLS site):

```
access_log off;
location / {
    proxy_pass http://127.0.0.1:7710;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_read_timeout 900s;
    proxy_send_timeout 900s;
}
```

Traefik v3: the default `readTimeout` of an entry point (60 s) cuts idle WebSockets. Set `entryPoints.websecure.transport.respondingTimeouts.readTimeout=0` (or 900s), and if the access log is on, drop `ClientHost` and `ClientAddr` (`accessLog.fields.names.ClientHost=drop`).

### Use it in the apps

In both apps: Settings, Relay, then your URL (`https://clip.example.org`). The pairing code shown by the Mac then carries the relay (`clipway:<key>?relay=...`), so the phone picks it up when it scans, and shows the host before joining.

### Check it

```bash
curl -s https://clip.example.org/health
curl -s https://clip.example.org/.well-known/clipway-relay.json
CLIPWAY_RELAY=https://clip.example.org node tools/client.mjs new     # then listen and send from two terminals
```

### Update

`git pull && docker compose up -d --build`. A restart empties the queues (they live in memory only): items still waiting for an offline device are lost, and devices resync on their own (a new epoch).

## Environment

| Variable | Default | |
|---|---|---|
| `PORT` | 7710 | |
| `HOST` | all interfaces | `127.0.0.1` to listen on the loopback only |
| `CLIPWAY_TRUST_PROXY` | 0 | 1: per-IP limits use the last `X-Forwarded-For` entry |
| `CLIPWAY_TTL_H` | 24 | how long an item waits for an offline device, 24 at most |
| `CLIPWAY_MAX_TOTAL_MB` | 256 | memory for all queues and uploads in progress; beyond, uploads get `busy` |
| `CLIPWAY_PING_S` | 240 | protocol ping interval |
| `CLIPWAY_DEAD_S` | 600 | silence before a connection is closed |

## Limits

| Limit | Value | Answer |
|---|---|---|
| Frame, both ways | 128 KiB | close 1009 |
| Item | one part, `enc` of 118 124 characters at most (a 64 KB text, padded and encrypted) | `too_big` |
| Queue per chain | 50 items, 6 MiB (sum of `enc` lengths), 24 h | oldest evicted first |
| Uploads per connection | 4 at once, 1 MiB of ciphertext in progress | `quota` |
| Upload not completed | 2 minutes | `incomplete` |
| Uploads per chain | 60 items per minute, 60 MiB per hour | `rate_limited` |
| Relay memory | `CLIPWAY_MAX_TOTAL_MB` | `busy` |
| Connections per chain | 8 | HTTP 429 |
| Requests per IP (IPv6 /64) | 60 per minute: upgrades, `DELETE /chain`, other HTTP | HTTP 429 |
| Open WebSockets | 20 per IP, 10 000 in total | HTTP 429, 503 |
| Chains held at once | 20 000 | HTTP 503 for a new chain |
| Malformed frames | 10 per connection | close 4002 |
| First frame | `sync` within 10 s | close 4002, 4003 |

## What the relay sees and keeps

- **Sees**: the chain id it computes from the proof, the time and size of each item, how many devices are connected, and IP addresses while connected. Items are padded to 512 bytes, and an offer looks like a short text.
- **Never carries**: images and files. They go directly between the devices, encrypted, and never reach the relay or its host.
- **Keeps**: complete items, encrypted, in memory, until another device acknowledges them, 24 hours pass, or newer items push them out. An erase (`DELETE /chain`) drops them at once and closes the chain's connections with 4001.
- **Never sees**: the key, the content, file names in offers, local addresses in offers, device names or device ids: all of that is inside AES-256-GCM envelopes.
- **Logs**: a counter line every hour (connections, items, bytes, refusals) and errors, with at most the first 6 characters of a chain id. Never an IP address, a proof, a nonce, the size of a given item or any content. Addresses live in memory only, for the per-IP counters.

Implementation notes:

- The proof is compared through the chain id it hashes to (SHA-256), and the chain record found is checked again with a constant-time comparison.
- `seq` counts the items of a chain from 1 while the relay holds the chain. When a chain has nothing queued and nobody connected, the relay forgets it; if it comes back, its `welcome` carries a new epoch, so devices sync from 0 and never skip an item because of an old `after`.
- `delivered` goes to the uploading connection only; an item uploaded before a reconnection is still delivered, without that notice.

## Files

- `server.js`: HTTP and WebSocket server (`start(options)`, exports `LIMITS`, `CLOSE`, `SUBPROTOCOL`, `identify`, `ipKey`, `idFromHexProof`).
- `crypto.js`: the reference cryptography of the protocol (the relay itself only uses `idFromProof` and the size limits).
- `direct.js`: the reference of the direct transfer of images and files (derivations, records, a small sender and receiver on `node:net`). The relay does not use it.
- `bip39-english.js`: the official word list.
- `tools/client.mjs`: the test client above.
- `test/`: `node --test` suites (vectors, handshake, flows, limits, erase and log, direct transfer, test client).
