# Clipway: protocol and architecture (v1)

Clipway is a universal clipboard between a Mac and an Android phone (GrapheneOS first): copy on the Mac, paste on the phone, and back, plus images and files. No account. Everything is end-to-end encrypted with a **sync chain** (a 128-bit secret shown as 12 words or a QR code, or passed over Bluetooth to a phone next to the Mac after both screens showed the same code). Texts pass through a **blind relay** that anyone can host. Images and files go **directly** from one device to the other when both are on the same local network (section 14), and otherwise **through the relay, cut in encrypted chunks**, up to 6 MB (section 15).

**Direct first.** For an image or a file, the sender first offers it directly: the relay only passes a short encrypted offer (where to connect, how big, which fingerprint) and the content crosses the local network, encrypted. When that is not possible (the other device is offline, on another network, or cannot connect), an image or a file of 6 MB at most goes through the relay as a **chunked item**: an encrypted head, then encrypted chunks of 64 KiB, each the size of a text envelope at most. The relay holds them like texts (24 h at most, in memory only, within the queue of a chain, raised from 6 MiB to 9 MiB in 0.4.0 so that a 6 MiB item fits), sees only ciphertext, and drops an upload left incomplete. Larger files still need the same network. Clipway 0.3 refused all media on the relay; 0.4.0 accepts these chunks, so that a photo shared from anywhere reaches the other device (section 11).

Three parts, one protocol:

| Part | Folder | Stack |
|---|---|---|
| Relay | `relay/` | Node 22, one dependency (`ws`), AGPL-3.0, Docker. `relay/direct.js` is the reference of the direct transfer, not used by the relay |
| Android app | `android/` | Kotlin, Jetpack Compose, `dev.sidali.clipway`, minSdk 31, targetSdk 36 |
| Mac app | `mac/` | Swift, SwiftUI menu bar app, `dev.sidali.clipway`, macOS 14+, ad hoc signature |

Reference relay: `https://clip.sidali.dev` (the default in both apps, configurable). Until it is deployed, everything is tested against a local relay on `http://127.0.0.1:7710` (see "Local testing").

The cryptography is the Sonne sync chain (same author, same construction, same envelope), with Clipway labels so that a Sonne chain can never be used here by mistake. Test vectors: [`docs/VECTORS.json`](VECTORS.json), written by `node tools/gen-vectors.mjs` from `relay/crypto.js` (chunked items of section 15 included; `relay/nearby.js` for nearby pairing, section 13, and `relay/direct.js` for the direct transfer, section 14). The Android app (`Crypto.kt`) and the Mac app (`ClipwayCore`) are tested against the same file.

Words used below: a **device** is one installation of Clipway; a **chain** is the set of devices that share the same secret S; an **item** is what one upload to the relay carries: one encrypted envelope (a text, a hello, an offer or a reply), or for a **chunked item** an encrypted head followed by its chunks, each one an envelope (a **part**); an **offer** stands for an image or a file that the receiver then fetches directly from the sender (section 14).

## 1. The sync chain

- **Secret S**: 16 bytes (128 bits) from the system CSPRNG (`SecRandomCopyBytes` or CryptoKit on the Mac, `SecureRandom` on Android). The Mac creates it; the phone joins.
- **12 words**: S as an English BIP39 mnemonic, exactly like a Bitcoin wallet: 128 bits of S, then the first 4 bits of SHA-256(S) as a checksum, cut into 12 groups of 11 bits, each an index in the official 2048-word list (SHA-256 of the list file: `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`). Parsing ignores case and extra spaces; exactly 12 words; an unknown word or a wrong checksum is refused with a distinct message ("Check the words: one of them is not in the list" and "These words do not form a valid key").
- **QR code**: the text `clipway:<base64url(S) without padding>` (22 characters after the prefix), for example `clipway:AAECAwQFBgcICQoLDA0ODw`. When the device uses a relay other than the default one, the code adds it: `clipway:<key>?relay=<percent-encoded URL>`. Readers accept both forms and trailing `=`; they refuse any other prefix. The QR code is never a web link: nothing in it can be sent to a server by a browser or a scanner app.
- **Derivations** (HKDF-SHA256, RFC 5869, empty salt, which is the same as 32 zero bytes):

| Name | Definition | Size | Use |
|---|---|---|---|
| P, proof | `HKDF(S, info = "clipway-proof")` | 16 bytes | shown to the relay at each connection: proves the device holds S without revealing S or the keys |
| id, chain id | `hex(SHA-256("clipway-id" ‖ P))[0:32]` | 32 hex chars | the only thing the relay knows; it computes it from P |
| K_enc | `HKDF(S, info = "clipway-enc")` | 32 bytes | AES-256-GCM key of every envelope, the chunks of section 15 included |
| K_mac | `HKDF(S, info = "clipway-mac")` | 32 bytes | HMAC-SHA256 key of the content fingerprint `fp` |
| K_direct | `HKDF(S, info = "clipway-direct")` | 32 bytes | root of the per-transfer keys of the direct transfer (section 14) |

  `‖` is concatenation; `"clipway-id"` is its UTF-8 bytes. The id is computed from P (not from S directly) so that the relay can check that a device knows P, and so that knowing the id alone is not enough to connect.
- **Where S lives**: Mac: since 0.4.1, sealed to a P-256 key of the Secure Enclave (ECDH with an ephemeral key, HKDF-SHA256, AES-256-GCM), in `Application Support/Clipway/keys/chain.sealed` inside the app's container, never synced: the 12 words are the backup (docs/UPDATES.md explains why: a Keychain item is tied to the code directory hash of each ad hoc build). 0.4.0 and earlier used the login Keychain (service `dev.sidali.clipway`, account `chain`); 0.4.1 moves it once. Android: encrypted with AES-256-GCM by a non-exportable Android Keystore key (StrongBox when available), in credential-protected storage; `allowBackup=false` and data extraction rules exclude everything. Neither app ever puts the words on the clipboard or in a URL, and both clear S from memory they own when the chain is erased.
- **Revocation**: losing a device means a new chain. On the Mac, Settings > Change the key erases the chain on the relay (`DELETE /chain`), draws a new S and shows the pairing screen again. The lost device keeps the old S, which now leads to an empty, unused chain.

## 2. Envelope

Every item is one AES-256-GCM envelope, the same format as the encrypted state of Sonne:

```json
{ "nonce": "<12 bytes, 24 lowercase hex>", "enc": "<standard base64 (with padding) of ciphertext followed by the 16-byte tag>" }
```

- Key: K_enc. Nonce: 12 random bytes, a new one for every envelope (never reused, never fixed outside tests).
- AAD (authenticated, not sent): the chain id (32 ASCII characters). An envelope moved to another chain fails authentication. A chunk of a chunked item has its own AAD (15.2), so it can never be read as a head, nor moved to another item or position.
- An envelope that fails to open is dropped without a retry (it can never become readable) and acknowledged so the relay forgets it. Nothing about it is shown to the user; both apps count these envelopes locally, for a Diagnostics screen to come.

## 3. Items

### 3.1 The head

An item is one envelope; its plaintext, the **head**, is a JSON object, UTF-8, padded (3.3). Reference field order and serialization (`JSON.stringify`: no spaces, `/` not escaped) are only needed to reproduce the vectors byte for byte; readers accept any order.

```json
{
  "v": 1,
  "type": "text",
  "item": "00112233445566778899aabbccddeeff",
  "device": { "id": "f0e1d2c3b4a5968778695a4b3c2d1e0f", "name": "MacBook Air", "kind": "mac" },
  "ts": 1792300000000,
  "mime": "text/plain",
  "size": 33,
  "fp": "963175147d5b7e6d67e6f296258e84b5",
  "data": "Q29waWVkIG9uIHRoZSBNYWM6IGNhZsOpIOKYlSDwn5GL",
  "pad": "      "
}
```

| Field | Rule |
|---|---|
| `v` | `1`. Any other value: the item is dropped (and acknowledged). |
| `type` | `"text"`, `"hello"`, `"offer"`, `"reply"` or `"chunked"` (since 0.4.0, section 15). Anything else is dropped and acknowledged, `"image"` and `"file"` included: Clipway 0.2 sent them inside one envelope. |
| `item` | 16 random bytes, 32 lowercase hex, new for every item. Used for duplicates and history; for an offer, it is also the transfer id (section 14). |
| `device.id` | 16 random bytes drawn at install, 32 lowercase hex. Only inside envelopes: the relay never sees it. A new one after Erase everything. |
| `device.name` | 1 to 64 characters, chosen by the user (default: the Mac's computer name, the phone's model). Only inside envelopes. |
| `device.kind` | `"mac"` or `"android"`. |
| `ts` | sender clock, Unix milliseconds. |
| `pad` | spaces, ignored by readers. |

**text**: `mime` exactly `"text/plain"` (content is always UTF-8), `size` the content length in bytes, **65 536 (64 KiB) at most**, `fp` (below), `data` the standard base64 of the content. No `name`, no `chunks`.

**hello** has only `v`, `type`, `item`, `device`, `ts` (and `pad`). A device sends one right after it joins a chain, whenever its name changes, and after its relay setting changes (the other device may only be on the new relay), so the others learn its name ("Connected to Pixel 10 Pro") before any content is sent. It is not shown in history.

**offer** stands for an image or a file that stays on the sender until the receiver fetches it directly (section 14):

| Field | Rule |
|---|---|
| `media` | `"image"` or `"file"`. |
| `mime` | image: `image/png`, `image/jpeg`, `image/webp`, `image/gif`, `image/heic`, `image/tiff` or any `image/*`. file: any type, `application/octet-stream` when unknown. Lowercase `type/subtype`, no parameters. |
| `name` | file: required, 1 to 255 characters, the original file name. image: optional. Receivers never trust it as a path (3.5). |
| `size` | content length in bytes, 26 214 400 (25 MiB) at most. |
| `fp` | fingerprint of the content (below). |
| `port` | TCP port the sender listens on, 1 to 65 535. |
| `hosts` | 1 to 8 IPv4 addresses of the sender, dotted, without leading zeros. Receivers connect only to addresses of a local network (14.4). |

An offer carries no content (`data` is refused).

**reply** answers an offer through the relay when the direct connection could not deliver it: `offer` (the offer's `item`) and `status`: `"unreachable"` (no address of the offer could be reached: the devices are not on the same network), `"declined"` (the receiver does not take it, for example too large for its storage), `"failed"` (connected, but the transfer broke). `"done"` is also a valid status, but a successful transfer is confirmed on the direct connection itself (14.3).

**chunked** carries an image or a file of 6 MiB at most through the relay (section 15): `media`, `mime`, `name` and `fp` as in an offer, `size` 6 291 456 at most, and `chunks`, exactly `ceil(size / 65 536)`. No `data`, no `port`, no `hosts`. A `chunks` field in a head of another type is refused.

`fp = hex(HMAC-SHA256(K_mac, content)[0:16])`, 32 hex: checked once the content is complete, then used against echo and duplicates. Unknown fields are ignored (forward compatibility).

### 3.2 Sizes

A text, a hello, an offer and a reply are one envelope each; only a chunked item has more parts (section 15), and none of its envelopes is larger than the largest head. The largest head is a 64 KiB text: its `data` is 87 384 base64 characters, the other fields take under 700 bytes (a 64-character device name made of escaped control characters included), and padding rounds it up to **88 064 bytes** (172 x 512). Its envelope's `enc` is at most **117 440** base64 characters. A device never builds a head larger than 88 064 bytes; an offer or a reply takes 512 or 1 024 bytes.

### 3.3 Padding

The head plaintext is padded so that its length says little about short texts: serialize without `pad` (length L bytes, ending with `}`), then insert `,"pad":"<k spaces>"` before the final `}` with the smallest k such that `L + 9 + k` is a multiple of 512. A head is therefore 512, 1024, 1536... bytes. An offer looks like a short text to the relay.

### 3.4 Freshness, duplicates and replays

The relay cannot forge items (it has no key) but it could replay old envelopes. Receivers:

- drop a head whose `ts` is more than 24 h + 10 min in the past or more than 10 min in the future (by the receiver's clock);
- drop an offer whose `ts` is more than 2 minutes in the past: its sender has stopped listening (14.3);
- keep the `item` ids they have seen for 48 h (at most 2 000) and drop a duplicate;
- drop items whose `device.id` is their own (their own items, delivered back after a reconnection) without acknowledging them (5.6).

Dropped items are acknowledged (except their own), so the relay forgets them.

### 3.5 What a receiver does with an item

- **text**: written to the clipboard only if it is the newest text or image received (by `ts`) and its `ts` is less than 10 minutes old; otherwise it only goes to history. A phone that was offline for an hour does not get an hour-old clipboard pasted over its current one.
- **chunked**: its head and all its chunks are opened, put back together and checked (`size`, `fp`, 15.3), then handled exactly like the content of an offer once fetched: image to the clipboard, file saved.
- **offer**: acknowledged at once, then fetched directly (section 14). Once the content is complete and checked, it is handled like the items of Clipway 0.2: an **image** goes to the clipboard under the same rule as a text (and the "Images too" setting), a **file** is saved, never opened automatically. Mac: `~/Downloads/Clipway/`. Android: `Download/Clipway/` through MediaStore (no storage permission). The name is sanitized: path separators, control characters and a leading dot removed, trimmed to 120 characters, `file` if nothing is left; an existing name gets ` 2`, ` 3`... before the extension. On the Mac, received files carry the quarantine attribute (`LSFileQuarantineEnabled`), so Gatekeeper checks them before they run. If the transfer cannot happen, the receiver sends a reply and says it plainly (14.5).
- **reply**: the sender stops waiting for that offer and shows why (14.5). Not shown in history on its own.
- Every received text, image and file goes to history (section 9).

## 4. Relay

### 4.1 Transport and authentication

One WebSocket per device: `GET /ws`, upgraded, JSON text frames only (a binary frame is refused). The device authenticates with its proof in the subprotocol header, never in the URL (proxy access logs write URLs):

```
Sec-WebSocket-Protocol: clipway.v1, clipway.p.<hex(P), 32 lowercase hex>
```

Android (OkHttp) sets the header itself; the Mac passes `["clipway.v1", "clipway.p.<P>"]` as the protocols of `URLSessionWebSocketTask`. The relay computes the chain id from P, refuses with HTTP 400 a missing or malformed proof or a missing `clipway.v1`, and answers with the subprotocol `clipway.v1`. There is no `X-Clipway-Chain` header and the id never travels: P is the only credential, and the relay derives the id from it.

Several devices of the same chain can be connected at once (8 at most). There are no roles: the Mac and the phone use the same protocol.

Clients must accept text frames of 128 KiB (`URLSessionWebSocketTask` accepts 1 MiB by default).

### 4.2 Frames

All frames are JSON objects with a `kind`. Sizes: 128 KiB (131 072 bytes) at most per frame, both ways. Unknown kinds are answered with `error` `bad_request`.

**Relay to device**

| Frame | When |
|---|---|
| `{ "kind": "welcome", "v": 1, "epoch": "<16 hex>", "devices": n, "limits": { "frame", "parts", "text", "enc", "items", "bytes", "ttl" } }` | right after the upgrade. `devices` counts this connection. |
| `{ "kind": "synced", "last": s }` | after the backlog that answers `sync`. `last` = highest seq of the chain. |
| `{ "kind": "item", "seq": s, "part": p, "parts": n, "ts": t, "blob": <envelope> }` | one per part, in seq order then part order: `parts` is 1 except for a chunked item (section 15), whose parts all come together, part 0 first. `ts` = when the relay received the item (relay clock). |
| `{ "kind": "stored", "ref": r, "seq": s }` | to the sender, once all parts of its upload `ref` are received and queued. |
| `{ "kind": "delivered", "seq": s }` | to the sender's connection (if still open), when another connection acknowledges the item. |
| `{ "kind": "presence", "devices": n }` | to every connection of the chain, when the number of open connections changes. |
| `{ "kind": "pong" }` | answer to `ping`. |
| `{ "kind": "error", "ref": r or null, "code": "...", "message": "..." }` | see 4.7. |

**Device to relay**

| Frame | Meaning |
|---|---|
| `{ "kind": "sync", "epoch": "<last epoch seen, or empty>", "after": s }` | must be the first frame, within 10 s of `welcome` (else close 4003). The relay sends every complete queued item with `seq > after`, or every queued item when `epoch` differs from its own, then `synced`. Items sent by other devices before the `sync` are part of this backlog, never sent twice. |
| `{ "kind": "item", "ref": r, "part": p, "parts": n, "blob": <envelope> }` | uploads part `p` of the item the device numbers `r` (integer, 0 to 2^31 - 1). Parts come in order, from 0, on the same connection. `parts` is 1, or up to 97 (`limits.parts`) for a chunked item; more is refused with `too_big`. |
| `{ "kind": "ack", "seq": s }` | the device has received, decrypted and handled every part of item `s` (or dropped it on purpose, see 3.4). |
| `{ "kind": "ping" }` | application heartbeat; the relay answers `pong`. |

The first frame must be `sync`: any other frame before it, `ping` included, closes the connection with 4002, and a second `sync` gets `bad_request`. A malformed `sync` gets `bad_request` and a correct one may still follow within the 10 s. After 10 malformed frames the relay closes with 4002.

The relay checks only shapes and sizes: `blob` must be `{nonce: 24 hex, enc: base64}` with `enc` of **117 440 characters at most** (a 64 KiB text, 3.2); `ref`, `part`, `parts`, `seq` integers in range; `parts` at most 65. It cannot check anything inside, so it cannot tell a text from an offer, nor a chunk from a head; it only sees how many parts an item has.

When the last part of an item arrives, the relay assigns the next `seq`, queues the item, answers `stored` to the uploader, and sends all its parts to every other connection of the chain that has sent `sync`. An upload that is not complete within 2 minutes is dropped (`incomplete`), and so is any upload in progress when its connection closes: an incomplete item is never queued nor delivered.

### 4.3 Sequence numbers and epoch

`seq` counts items (not parts) per chain, from 1, in the order the relay completes them. Nothing is persisted, so a relay restart starts over: `epoch` (8 random bytes, 16 hex) changes, and a device that sees a new epoch syncs with `after = 0`.

The epoch belongs to the chain record, not only to the relay process: a chain the relay forgot (nothing queued, nobody connected) and sees again, or a chain erased with `DELETE /chain`, gets a fresh epoch, because its `seq` starts again at 1. Otherwise a device that kept `(epoch, after = 7)` would skip the new items 1 to 7. The first record of a chain after a start uses the epoch drawn at start. Devices need nothing new for this: a different epoch already means "sync from 0".

Each device stores `(epoch, after)`. It moves `after` up to a seq once that item and every lower seq it was offered are handled: a foreign item when it is written and acknowledged, its own item when `stored` arrives. It never moves `after` past an item still being handled. `after` only saves bandwidth: a device that is unsure sends a lower value, and duplicates are dropped by item id (3.4).

### 4.4 Queue, retention and deletion

- The relay keeps each complete item (all its parts) **in memory only**, per chain, until the first of: an `ack` from any connection other than the one that uploaded it; **24 h** after it was stored (`CLIPWAY_TTL_H`, 24 at most); eviction by the quotas below. It never writes items to disk.
- **Sizes.** An item in more than 97 parts, or with an envelope whose `enc` is longer than 117 440 characters, is refused with `too_big` ("this relay carries texts of 64 KB and images or files of 6 MB at most: larger ones go directly between your devices"). An item larger than the queue of a chain (9 MiB) is refused too.
- Quotas per chain: **50 items** and **9 MiB** (sum of the `enc` string lengths). A new item that would exceed them evicts the oldest items first (a clipboard is "latest wins").
- Global: total stored bytes at most `CLIPWAY_MAX_TOTAL_MB` (256 by default); beyond, new uploads get `busy` until items expire.
- Deletion on the first foreign ack means v1 is built for one Mac and one phone. With more than two devices, a device that is offline when another device acknowledges an item misses it (documented limit; per-device delivery is a candidate for v2).

### 4.5 Presence and heartbeat

- `presence` tells devices how many connections the chain has (the menu bar says "Phone offline, items wait up to 24 hours" when `devices` is 1).
- Protocol pings: the relay pings each connection every 4 min (`CLIPWAY_PING_S`, 240) and closes it after 10 min without any frame or pong (`CLIPWAY_DEAD_S`, 600). Every ping wakes the phone radio: keep them rare.
- Application heartbeat: OkHttp does not show pongs to the app, so devices send `ping` (Android every 4.5 min from its watchdog alarm, the Mac every 60 s) and reconnect if no `pong` comes within 20 s.

### 4.6 HTTP routes

| Route | Answer |
|---|---|
| `GET /ws` | the WebSocket above. |
| `DELETE /chain` with `X-Clipway-Proof: <hex P>` | erases the chain's queue and uploads in progress, closes its connections with code 4001 "chain erased", answers **204** (also when nothing was there: the answer does not reveal whether a chain existed). 400 if the proof is missing or malformed. Counts in the per-IP limit. |
| `GET /health` | `{ "ok": true, "chains", "connections", "items", "bytes", "uptime", "version" }`. |
| `GET /.well-known/clipway-relay.json` | `{ "protocol": 1, "version", "status": "ok" or "degraded" or "end-of-service", "minClient": { "android": "0.4.0", "mac": "0.4.0" }, "limits": {...} }`, cacheable 5 min. Apps read it when the relay is set and once a day (with only their fixed `User-Agent`), and show a banner if their version is below `minClient` or the status is not `ok`. `minClient` is 0.4.0 since the relay carries chunked items, which 0.3 apps cannot read (section 11). The relay always answers `ok` for now; a setting to announce `degraded` or `end-of-service` is planned. |
| `GET /.well-known/security.txt` | contact and expiry. |
| `GET /update.json`, `GET /download/clipway-<x.y.z>.apk`, `GET /download/clipway-mac-<x.y.z>.zip` | since 0.4.1, the release files of the apps' automatic updates, read only from `CLIPWAY_RELEASES_DIR` (404 without it), no proof needed (docs/UPDATES.md). |
| `GET /ws` without upgrade | 426 JSON. |
| anything else | 404 JSON. |

No CORS (only the native apps talk to the relay), security headers on every answer (`nosniff`, `no-referrer`, `DENY`, `default-src 'none'`).

### 4.7 Limits, errors and close codes

| Limit | Value |
|---|---|
| Frame | 128 KiB, both ways (larger: close 1009 by the WebSocket library). Since 0.4.1 both apps check every frame of an item against it, with the 256 bytes the relay keeps to forward it, before queuing it and before sending it; an item in flight when the relay closes with 1009, or cut three times in a row, fails once and is never sent again, so that one item cannot make a device reconnect forever. |
| Item | 97 parts at most, each an envelope with `enc` of 117 440 characters at most (`too_big`) |
| Queue per chain | 50 items, 9 MiB, 24 h |
| Connections per chain | 8 (429 at upgrade) |
| Uploads per chain | 60 items per minute, 60 MiB per hour (`rate_limited`) |
| Requests per IP | 60 per minute (WebSocket upgrades, `DELETE /chain`, other HTTP; 429) |
| Open WebSockets | 20 per IP, 10 000 in total (429, 503) |
| Chains held at once | 20 000 (503 for a new chain), so that random proofs cannot fill the memory |
| Uploads in progress | 4 per connection, 9 MiB of decoded ciphertext (`quota`), 2 minutes each (`incomplete`) |

Per-IP limits reduce an IPv6 address to its /64 and an IPv4-mapped address to IPv4. Behind a trusted proxy (`CLIPWAY_TRUST_PROXY=1`) the address is the last `X-Forwarded-For` entry. Addresses live in memory only, for the counters.

`error` codes: `bad_request` (malformed frame, unknown kind, second `sync`, parts out of order), `too_big` (more than 97 parts, an envelope larger than a 64 KiB text, an item larger than the chain quota), `rate_limited` (60 items per minute or 60 MiB per hour on the chain), `quota` (more than 4 uploads or 9 MiB in progress on the connection), `busy` (`CLIPWAY_MAX_TOTAL_MB` reached), `incomplete` (upload not finished within 2 minutes). Clients retry `rate_limited`, `quota` and `busy` later, and mark the item "Not sent" on `too_big` and `bad_request`. Close codes: 4001 chain erased, 4002 protocol violation (first frame not `sync`, binary frame, repeated malformed frames), 4003 no `sync` in time.

### 4.8 Logs, environment and hosting

- Logged: counters (items, bytes, connections, refusals) every hour and errors. Never an IP address, never a full chain id (6 characters at most), never a nonce, size of a given item or content.
- Environment: `PORT` (7710), `HOST`, `CLIPWAY_TRUST_PROXY` (0), `CLIPWAY_TTL_H` (24, at most 24), `CLIPWAY_MAX_TOTAL_MB` (256), `CLIPWAY_PING_S` (240), `CLIPWAY_DEAD_S` (600).
- Docker: `relay/Dockerfile` (distroless Node 22, no shell, non-root, read-only root file system works), `relay/docker-compose.example.yml`. Put a TLS proxy in front, do not log client addresses there, and allow idle WebSockets of at least 10 minutes (Traefik v3: check `respondingTimeouts.readTimeout`).

## 5. Client rules (both apps)

### 5.1 Connection

1. Build the WebSocket URL from the relay setting: `https://host` gives `wss://host/ws`, `http://127.0.0.1:7710` gives `ws://127.0.0.1:7710/ws`. The setting is trimmed, loses its trailing `/`, and its scheme and host are lowercased (a keyboard may type `Https://`); the path is kept as typed. Release builds accept `https://` only; debug builds also accept `http://` to `127.0.0.1`, `localhost` and `10.0.2.2`.
2. Connect with the subprotocols, wait for `welcome`, send `sync` with the stored `(epoch, after)`, handle the backlog, wait for `synced`.
3. Reconnect after any close or failed heartbeat with a growing delay (1 s, 2 s, 4 s... 60 s at most, plus up to 20 % random), immediately when the network comes back or changes, when the Mac wakes, and when the app comes to the foreground. Close code 4001: stop, remember it across restarts (so an erased chain never comes back by itself), and tell the user the chain was erased from another device, with Pair again.
4. Never send anything before `synced`.

### 5.2 Sending

1. A text of 64 KiB at most: build the head (new `item`, own `device`, `ts` = now, `mime`, `size`, `fp`, `data`), pad it, seal it with a fresh nonce (AAD = chain id). A longer text is not sent: "Too long: Clipway sends texts up to 64 KB". An image or a file: an offer (section 14) or a chunked item (section 15), as 15.4 decides.
2. Send its parts as `item` frames with one `ref`. Keep it until `stored` arrives; if the connection drops before, send it again (same `item` id: receivers drop duplicates) after reconnecting.
3. Show "Sent" on `stored` when another device is connected, "Waiting for your Mac" (or phone) when `presence` is 1; switch to "Delivered" on `delivered`. For an offer, the outcome of the direct transfer decides instead (14.5).

Sending is local first: the item goes to history and the screen changes before any network call.

### 5.3 Receiving

For each item: open the head, apply 3.4, check `size` and `fp` of a text, act (3.5), store in history, then `ack`. Acks are sent only after the content is safely written (clipboard, history), so a crash before that gets the item again. An offer is acknowledged as soon as its transfer starts: it is only valid 2 minutes anyway, and a failed transfer is answered with a reply.

### 5.4 Never sent

- Mac: pasteboard contents whose types include `org.nspasteboard.ConcealedType` or `org.nspasteboard.TransientType` (what password managers set), or `org.nspasteboard.AutoGeneratedType`. Checked on every pasteboard item of the change.
- Android: a clip whose description has `ClipDescription.EXTRA_IS_SENSITIVE` set to true (Android 13+). The tile shows "Not sent: marked as sensitive" instead.
- Both apps say it in What leaves your device.

### 5.5 Echo

- The Mac remembers the `changeCount` its own writes produce and ignores them, so a text received from the phone is not sent back.
- The phone never reads its clipboard on its own (Android forbids it in the background anyway), so it cannot loop.
- Each device skips sending an item whose `fp` equals the last item it received or sent less than 10 s ago (`fp` is keyed by K_mac, so the history can keep it without revealing short texts).

### 5.6 Acks

A device acknowledges every item it received from another device, including dropped ones (3.4), and never acknowledges its own items. The relay ignores an ack from the uploading connection anyway.

### 5.7 Erase everything

In About (both apps), in the semantic red, confirmed by typing `ERASE`:

1. `DELETE /chain` with P, best effort (skipped without network: the relay purges items after 24 h at most, and the text says so). The Mac, which creates the chain, always does it. On the phone it is a switch in the confirmation, "Also erase the key on the relay", off by default: erasing the relay unpairs the Mac too, which a person resetting only their phone may not want.
2. Locally: S, the history key (crypto-shredding: without the key the history files are unreadable even if the flash keeps old blocks), history files, received image copies, preferences, the device id. Mac: the sealed `chain` and `history-key` and the enclave key, `~/Library/Application Support/Clipway`, and any Keychain item left from 0.4.0. Android: Keystore keys, app files, preferences.
3. Back to the first launch.

Files already saved to Downloads are not deleted (they belong to the user now); the text says so.

## 6. Android app

- **Service**: after pairing, a foreground service (`foregroundServiceType="specialUse"`, subtype described in `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`: "Keeps a connection to the user's own relay to receive clipboard items from their computer") holds the WebSocket (OkHttp). Persistent notification, channel "Connection", minimum importance: "Connected to <Mac name>", or "Connecting", "Waiting for network", "Can't reach the relay". There is no manual pause in 0.1.0. Started after pairing, at boot (`RECEIVE_BOOT_COMPLETED`), after an app update (`MY_PACKAGE_REPLACED`). Not `dataSync` (limited to 6 h a day from Android 15).
- **Battery**: a watchdog `AlarmManager.setAndAllowWhileIdle(ELAPSED_REALTIME_WAKEUP)` every 4.5 min sends `ping`, checks `pong`, reconnects if needed, under a short wake lock released at once; reconnection on `ConnectivityManager.NetworkCallback`. After pairing, the app asks once for the battery optimization exemption (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) with one sentence on why, and shows the state in Settings. No exact alarm.
- **Mac to phone (automatic)**: a received text or image is written with `ClipboardManager.setPrimaryClip` from the service (allowed in the background; only reading is restricted). Text: `ClipData.newPlainText("Clipway", text)`. Image (fetched directly, section 14): a copy in the app's no-backup directory served read-only by a non-exported `FileProvider` (`dev.sidali.clipway.clips`), `ClipData.newUri`; only the last two copies are kept. Then a quiet notification, channel "Received", low importance, no sound: "Copied from <Mac name>", no content in it, gone after 4 s, hidden on the lock screen (`VISIBILITY_SECRET`). Files: "Received <name> from <Mac name>" with an Open action, kept until dismissed. A transfer that cannot happen: "Couldn't receive <name> from <Mac name>: your phone and your Mac need to be on the same network" (or "the transfer broke"), on the same quiet channel.
- **Phone to Mac (one gesture)**, three ways, all sending through the service:
  - **Quick Settings tile** "Send to Mac" (`TileService`, `android.permission.BIND_QUICK_SETTINGS_TILE` on the service): a tap starts `SendActivity` with `startActivityAndCollapse(PendingIntent)`. `SendActivity` is invisible (translucent, no animation, `excludeFromRecents`, `noHistory`), reads the clipboard once it has window focus (Android only allows reading the clipboard to the focused app), checks `EXTRA_IS_SENSITIVE`, sends, shows a short toast ("Sent to <Mac name>", "Waiting for <Mac name>", "Clipboard is empty", "Not sent: marked as sensitive", "Already sent"), confirms with haptics, and closes. After pairing the app offers to add the tile (`StatusBarManager.requestAddTileService`).
  - **Text selection menu**: `ProcessTextActivity` with an `android.intent.action.PROCESS_TEXT` filter (`text/plain`), label "Send to Mac". It reads `EXTRA_PROCESS_TEXT`, sends it, never changes the selection (no result set), and closes. Nothing is copied.
  - **Share target**: `ShareActivity`, labeled "Clipway" in the share menu (since 0.4.0, easier to find than "Send to Mac"), for `ACTION_SEND` and `ACTION_SEND_MULTIPLE` (`text/plain`, `image/*`, `*/*`). Text becomes a text item (64 KB at most: "Too long: Clipway sends texts up to 64 KB"), images and anything else go as 15.4 decides: directly (section 14) or through the relay in chunks (section 15). 25 MiB each, larger: "Too large: Clipway sends up to 25 MB"; over 6 MiB without an address on a local network: "Not sent: over 6 MB, connect to the same Wi-Fi as your Mac". It reads the shared URIs with the grant it received, sends, and closes.
- **Screens**: first launch in 3 screens at most (what Clipway does in one sentence, then Pair). Pairing: "Pair nearby" as the one primary action (section 13: Bluetooth permissions asked at that tap, Android 13+), "Scan a code instead" (the screen "Scan the code on your Mac"; camera permission asked at that moment, with one sentence; scanning with ZXing core and Camera2), "Type the 12 words" (keyboard without learning: `IME_FLAG_NO_PERSONALIZED_LEARNING`, no autofill except the password manager), "Use my password manager" (Credential Manager `GetPasswordOption`, Android 14+; hidden on older versions, which need Google services for it). Then "Save to your password manager" as the one primary action (Credential Manager `CreatePasswordRequest`, id `Clipway`, password = the 12 words, Android 14+; on older versions the rescue kit is the backup), notifications permission (Android 13+), battery exemption, add the tile. Home: connection state, last items (history), Send clipboard button. Settings (10 at most): device name, relay, Copy automatically (on), Images too (on), Start when the phone starts (on), notifications, the tile, battery state, Show the key (biometric or device credential via `BiometricPrompt`, `FLAG_SECURE`, hidden again after 60 s), rescue kit (print), About, What leaves your device, Erase everything.
- **Permissions**: exactly the list in [`permissions.txt`](permissions.txt). No Google Play Services, no Firebase, no analytics. Dependencies: AndroidX (Compose, Activity, Credentials), OkHttp, ZXing core.

## 7. Mac app

- **Menu bar app** (`LSUIElement`, no Dock icon), SwiftUI `MenuBarExtra`, macOS 14+. Menu: state ("Connected to <phone name>", "Phone offline, items wait up to 24 hours", "Not paired", "Relay unreachable"), the last 10 history items (click copies back, or reveals a file), Send automatically (on), Images too (on), Send a file..., History..., Pair a phone... (opens on Pair nearby, section 13, with Show a code instead) and Join with 12 words... (not paired, or erased elsewhere) or Show the key... (which also offers Pair nearby), Settings..., About, What leaves your device, Quit. Dropping files on the menu bar icon sends them. Launch at login through `SMAppService`, asked once after pairing.
- **Clipboard watch**: a timer every 300 ms compares `NSPasteboard.general.changeCount`. On a change that is not its own write (5.5), if Send automatically is on: skip concealed, transient and auto-generated content (5.4); file URLs (a Finder copy) are not sent automatically (use Send a file); a plain string is sent as text (at most 64 KB, else a note in the menu: "Too long to send: Clipway sends texts up to 64 KB"); otherwise, if Images too is on, PNG or TIFF data is sent as a PNG image (at most 25 MiB) as 15.4 decides: directly when the phone is connected, through the relay in chunks when it is offline (6 MiB at most; with a relay older than 0.4.0, not at all while the phone is offline). At most one item per change; an item with the same `fp` as the last one sent less than 10 s ago is skipped.
- **Receiving**: text is written as `.string`; an image (fetched directly, section 14) as its own type plus a TIFF representation for older apps; files go to `~/Downloads/Clipway/` (3.5). Notification (`UNUserNotificationCenter`, asked after pairing): "Copied from <phone name>", "Received <name> from <phone name>" (click reveals the file in Finder), "Couldn't receive <name> from <phone name>" with the reason.
- **Key and history keys** sealed by the Secure Enclave (section 1); the history in `~/Library/Application Support/Clipway/history.bin`, AES-256-GCM with a 32-byte key sealed the same way (`history-key`). Show the key: `LAContext` `.deviceOwnerAuthentication` (Touch ID or the Mac password), window excluded from screen capture (`sharingType = .none`), hidden again after 60 s.
- **Sandbox**: App Sandbox with network client, network server (the Mac listens on the local network while it offers an image or a file, 2 minutes at most, section 14), Downloads read-write, user-selected files read-write (Send a file, and the history export saved where the user chooses), printing (the rescue kit) and Bluetooth (nearby pairing, 13.8). `NSLocalNetworkUsageDescription`: "Clipway sends images and files straight to your phone over your local network, without any server." Ad hoc signature, hardened runtime, no debugger entitlement in release builds.
- **Appearance**: the system accent color and semantic colors, light and dark, from `Tokens.swift` only.

## 8. Pairing

1. On the Mac: Pair a phone. The Mac draws S, seals it (section 1), and opens on Pair nearby (section 13): the phone next to it pairs over Bluetooth once both screens show the same 4-digit code and the person pressed Pair on both. Show a code instead shows the QR code (`CIQRCodeGenerator`, error correction M) with the 12 words numbered under it, the text "These 12 words are your key. Anyone who has them can read what you copy. Your Mac keeps them encrypted, with a key only this Mac can use.", Print a rescue kit, and Done. The window cannot be captured.
2. On the phone: Pair nearby (section 13), or scan, type the words, or use the password manager. The relay comes from the code when it names one (the phone shows the host and asks to confirm when it is not the default relay), otherwise the default relay.
3. The phone saves the key to its password manager (one button), connects, and sends `hello`. The Mac shows "Connected to <phone name>" when the hello arrives: the pairing worked end to end. That is the one celebration (haptics on both devices, once; interface sounds come later).
4. Rescue kit (both apps, print): the 12 numbered words, the QR code, and a page "For someone you trust": which app, where the words are, how to open a history export without the app.
5. "If you lose these 12 words and all your devices, nobody can recover your key, not even us." Said once, on the key screen.

## 9. History

- The last **50 items** per device, sent and received, newest first: type, device name, time, a preview (text: first 200 characters; image: thumbnail; file: name and size). Content kept at most **200 MiB**; above, the oldest content is dropped and its row says "Content removed to save space". Files are not copied into history: the row points to the saved file.
- Encrypted at rest: Android: AES-256-GCM, Keystore key (no user authentication required, so the service can write while the phone is locked after the first unlock). Mac: AES-256-GCM, key sealed by the Secure Enclave.
- Tap or click: copies a text or image back to the clipboard (on the Mac this write is "its own", so it is not sent again) or opens a file. Delete removes one item with Undo for 5 s (swipe to delete is planned on Android); Clear history removes all with Undo. Erase everything destroys the keys.
- **Export** (History > Export): a ZIP the user saves where they choose, after a warning that it is not encrypted: `history.json` (one object per item: `type`, `device`, `ts`, `mime`, `name`, `size`, and `text` for texts) and an `items/` folder with the images, named by item id. It opens without Clipway (`unzip`, `jq`). Import is not planned: history is a convenience, not a vault.
- The list ends with "That's everything" and no infinite scroll.

## 10. Threat model (summary)

The full version is [`THREAT_MODEL.md`](../THREAT_MODEL.md).

1. Protected: the content of everything you send (text, images, files), file names, device names and device ids, against the relay, its host and anyone on the network: AES-256-GCM with a key only your devices hold. Images and files cross the local network when they can, encrypted with a key of their own transfer (section 14), or pass through the relay as encrypted chunks (section 15).
2. Protected: integrity and order of parts (GCM tags, AAD binds chain, item, index and count); a relay cannot forge, merge or reorder items.
3. Protected: replays older than 24 h and duplicates (timestamps and item ids, 3.4).
4. Protected: secrets marked by password managers or Android are never sent.
5. The relay sees: a random chain id, the time and size of every item (padded to 512 bytes; an offer for a 25 MiB file looks like a short text; a chunked item shows its number of parts, so its size to within 64 KiB), how many devices are connected, and IP addresses while connected (kept in memory for rate limits, never logged by the relay; a reverse proxy in front of it may log them, see PRIVACY.md for clip.sidali.dev).
6. The relay keeps encrypted items 24 h at most, in memory. A seized relay gives ciphertext only.
7. The relay can drop, delay or replay items within 24 h (replays are recognized and dropped), or refuse service. Availability is not protected.
8. Anyone who has the 12 words or the QR code can read everything sent on the chain and send items to your devices. Change the key if they leak.
9. Not protected: an unlocked device in someone else's hands, malware on a device, the other apps that read the clipboard once Clipway writes to it, and the keyboard.
10. Not protected: someone who records ciphertext today and gets the 12 words later can decrypt it (no forward secrecy in v1; the key is static, see [N2] in the standard).
11. Post-quantum: symmetric only (AES-256, HMAC-SHA256, HKDF), 128-bit secret; no public-key cryptography to break, except during a nearby pairing (X25519): a recording of that pairing could reveal S to a future quantum computer (13.9). Pair with the QR code to avoid it.
12. Timing: the relay can tell when you copy something on the Mac. It cannot tell a text from an offer; an item in several parts is an image or a file sent through it, and its number of parts gives its size to within 64 KiB (15.6).
19. Direct transfer: someone on the same local network sees that two devices exchange encrypted data, how much and when, and the local addresses; never the content, the name or the type (14.6).
13. Erasing destroys the keys; flash storage may keep old encrypted blocks, unreadable without them.
14. A malicious QR code can point the phone at another relay; that relay sees the same as ours (ciphertext and metadata), and the phone shows the host before joining.
15. Both apps are local first: without a relay they keep working (history, clipboard), they just do not sync.
16. Not protected: another clipboard sync on the same device (an emulator's host clipboard, Universal Clipboard) copies what Clipway writes elsewhere, without the password managers' markers, and may hand it back to Clipway as a new copy.
17. Nearby pairing: S crosses Bluetooth only inside a packet encrypted with a key from an ephemeral X25519 exchange, after the person pressed Pair on both devices. A man in the middle makes the two screens show different codes (except 1 time in 10 000 per attempt); pressing Pair without comparing them is not protected (13.9).
18. Nearby pairing: during the 2 minutes of a Pair nearby window, anyone in Bluetooth range sees that a Clipway Mac is pairing, can read its Bluetooth name, and can take the attempt; no location is used, nothing is stored.

## 11. Versioning

- Protocol version 1: `v: 1` in every head, subprotocol `clipway.v1`, `protocol: 1` in the well-known file. A future version uses `clipway.v2`; a relay may accept both during a transition, announced one release ahead.
- Clipway 0.3.0 changed what the relay carries without changing the version: before any release, both apps and the relay moved together. Items of type `image` and `file`, and chunks, are refused by 0.3.0 relays and apps; `minClient` 0.3.0 tells older apps to update.
- Clipway 0.4.0 adds chunked items (section 15), still protocol version 1: a new head type and items of up to 97 parts, announced by `limits.parts` in `welcome` and in the well-known file. Compatibility both ways: a 0.4.0 app with a relay older than 0.4.0 (`parts` 1) never sends a chunked item and keeps images and files direct; a 0.4.0 relay accepts every 0.3.0 item as before. A 0.3.0 app cannot read a chunked item (the Mac drops and acknowledges it, the phone ignores it and the relay keeps it until its 24 hours are over), so a 0.4.0 relay announces `minClient` 0.4.0 and older apps show the update banner. Deploy the relay first, then the apps.
- Direct transfer version 1 is the preamble `CWD1` (section 14); an incompatible change uses another one.
- Nearby pairing version 1 is its service UUID `a4985110-4541-4fcc-bcac-ee9b5ce269d0` and `v: 1` in its packet; an incompatible change uses a new service UUID (13.2).
- App versions follow SemVer and start at 0.1.0 (Android `versionName`, Mac `MARKETING_VERSION`, relay `package.json`), with an entry in `CHANGELOG.md` each.

## 12. Local testing

```bash
cd relay && npm ci && npm start                       # relay on http://127.0.0.1:7710
curl -s http://127.0.0.1:7710/health
adb -s emulator-5554 reverse tcp:7710 tcp:7710        # the phone reaches the relay at http://127.0.0.1:7710
```

Debug builds of both apps accept `http://127.0.0.1:7710` as the relay (the emulator can also use `http://10.0.2.2:7710`). The Mac app reaches a loopback relay with `NSAllowsLocalNetworking`; release builds still require `https://`.

Direct transfer with the emulator (14.7): the emulator reaches the Mac's own addresses, so an image from the Mac works as is (debug builds of the phone also try `10.0.2.2`, the Mac seen from the emulator, at the offer's port). The other way, the Mac cannot reach the emulator: the phone's debug build listens on port 7721 and also lists `127.0.0.1`, which the Mac's debug build accepts, so `adb -s emulator-5554 forward tcp:7721 tcp:7721` makes it work. Release builds connect to local network addresses only.

With `adb reverse`, the pairing code the Mac shows (`clipway:<key>?relay=http%3A%2F%2F127.0.0.1%3A7710`) works as is on the phone: scan it or paste it in the words field, then confirm the other relay. `mac/tools/e2e.sh` runs the Mac app against a local relay with the command line client `relay/tools/client.mjs` as the phone.

Nearby pairing needs real Bluetooth: the Android emulator has none. Its derivations, packets and the Mac's answers are tested without radio from the vectors (13.10).

On the Android emulator, the emulator itself copies the phone's clipboard to the Mac's (and writes an empty text there when the phone's clipboard holds an image). That is not Clipway, and it makes a text appear to travel twice; check what Clipway did in its history or logs, not only with `pbpaste`.

## 13. Nearby pairing (Bluetooth)

Pairing without a QR code or words: the phone is next to the Mac, the person taps Pair nearby, both screens show the same 4-digit code, the person presses Pair on both, and the Mac sends S and its relay to the phone over Bluetooth Low Energy, encrypted. It is the "numeric comparison" model of Bluetooth pairing: an ephemeral X25519 key exchange, and the person comparing the two codes is what stops a man in the middle. The QR code (Show a code instead on the Mac, Scan a code instead on the phone) and the 12 words stay, and the 12 words remain the backup: after a nearby pairing the phone still offers Save to your password manager.

Reference: `relay/nearby.js` (derivations, and the Mac's session state machine without radio), the `nearby` block of [`docs/VECTORS.json`](VECTORS.json), and `relay/test/nearby.test.js`. The vectors were also checked with java.security (JDK 21) and CryptoKit.

### 13.1 Roles, availability, what is kept

- **Mac: GATT peripheral** (`CBPeripheralManager`). It publishes the nearby service and advertises only while its Pair nearby window is open, **120 s at most**, and accepts **one phone per advertisement**.
- **Phone: GATT central** (`BluetoothLeScanner`, `BluetoothGatt`), only while the Pair nearby screen is in the foreground, 120 s at most from the tap.
- **No Bluetooth bonding**: no system pairing dialog, no link encryption, nothing stored by either Bluetooth stack. The security is in the messages, as with the relay.
- **Nothing persists.** The X25519 keys are drawn for one attempt, kept in memory, and forgotten at its end. Only the result, S and the relay, goes on through the usual pairing path (section 8).
- **Where it is offered.** Mac: in Pair a phone (not paired: S is drawn when the window opens, as in section 8) and in Show the key (already paired: after the same Touch ID or password check, since it sends S), as long as the pairing code fits in a packet (13.5). Phone: Android 13 or later (X25519 is in the platform from API 33; Android 12 offers only Scan a code and the words) with Bluetooth LE.
- Bluetooth serves only to pair: items always go through the relay.

### 13.2 Service and characteristics

Version 1 of this exchange is identified by its service UUID; an incompatible version would use a new one. All UUIDs end with `-4541-4fcc-bcac-ee9b5ce269d0`.

| Characteristic | UUID | Direction | Properties | Value |
|---|---|---|---|---|
| (service) | `a4985110-4541-4fcc-bcac-ee9b5ce269d0` | | primary service | |
| Commit | `a4985111-4541-4fcc-bcac-ee9b5ce269d0` | Mac to phone | read | 32 bytes: `commit` (13.4) |
| Phone key | `a4985112-4541-4fcc-bcac-ee9b5ce269d0` | phone to Mac | write with response | 32 bytes: the phone's X25519 public key |
| Mac key | `a4985113-4541-4fcc-bcac-ee9b5ce269d0` | Mac to phone | read | 32 bytes: the Mac's X25519 public key, only to the phone whose key was accepted |
| Confirm | `a4985114-4541-4fcc-bcac-ee9b5ce269d0` | phone to Mac | write with response | 16 bytes: `confirm` (13.4), written when the person presses Pair on the phone |
| Status | `a4985115-4541-4fcc-bcac-ee9b5ce269d0` | Mac to phone | read, notify (CCCD `0x2902`) | 1 byte, below |
| Packet | `a4985116-4541-4fcc-bcac-ee9b5ce269d0` | Mac to phone | read | 284 bytes: S and the relay, encrypted (13.5), once both sides pressed Pair |

| Status | Name | Meaning |
|---|---|---|
| `0x00` | waiting | no phone yet, or waiting for the confirmations |
| `0x01` | ready | both sides pressed Pair: Packet can be read |
| `0x02` | canceled | Cancel on the Mac, the window closed, or Show a code instead |
| `0x03` | expired | 120 s passed before both confirmations |
| `0x04` | failed | wrong confirmation tag |
| `0x05` | busy | what any other phone reads once a phone key was accepted for this advertisement |

- Mac: `CBMutableCharacteristic` with `value: nil` (every value is answered in the delegate, so it can depend on the phone and the state), permissions `.readable` or `.writeable`, never the `EncryptionRequired` variants (they start Bluetooth bonding and a system dialog). Phone key and Confirm have `.write`, not `.writeWithoutResponse`.
- Advertisement: `startAdvertising([CBAdvertisementDataServiceUUIDsKey: [service]])` and nothing else, no local name. The phone scans with `ScanFilter.Builder().setServiceUuid(ParcelUuid(service))`.

### 13.3 Sequence

1. **Mac**: the window opens. If Bluetooth is off or not allowed, it says so and offers Show a code instead. Otherwise it draws an X25519 key pair (sk_mac, pk_mac), computes `commit`, adds the service and, once `didAdd` reports success, starts advertising: "Bring your phone near your Mac."
2. **Phone**: the person taps Pair nearby. The app asks for Nearby devices (`BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`) if needed, after one sentence (13.8), and to turn Bluetooth on if it is off (`BluetoothAdapter.ACTION_REQUEST_ENABLE`). It draws (sk_phone, pk_phone) and scans: service filter, `SCAN_MODE_LOW_LATENCY`. After the first result it keeps scanning 1 s more, takes the strongest signal (the Mac next to it), and stops scanning.
3. **Phone**: `connectGatt(context, false, callback, TRANSPORT_LE)` with the `BluetoothDevice` of the scan result (it keeps the random address type), `requestMtu(517)` (gives up below 35: a 32-byte write needs 35), `discoverServices`, and checks that the service has the six characteristics.
4. **Phone**: subscribes to Status (CCCD `0x0001`), **then reads Commit, then writes Phone key**. This order matters: the commitment only protects if the phone reads it before it sends its own key (13.9).
5. **Mac**, on the Phone key write: checks it (13.7) and accepts it. From then on it serves only this phone ("locked"): it stops advertising, computes Z, N, K_sas, K_key and the code, and shows the code with Pair and Cancel.
6. **Phone**: reads Mac key, checks that `SHA-256("clipway-nearby-commit" ‖ pk_mac)` equals the Commit read in step 4 and that the key passes 13.4, computes the same keys and code, and shows the code with Pair and Cancel.
7. **The person compares the two codes** and presses Pair on both devices, in either order.
   - Phone, Pair: writes Confirm, then waits for Status. Cancel: disconnects.
   - Mac, Pair: marks its side confirmed. Cancel, or closing the window: Status `0x02`.
8. **Mac**: once it has both, its own Pair and a valid Confirm, it seals the packet with a fresh nonce and notifies Status `0x01`: "Finishing on your phone."
9. **Phone**: on Status `0x01` (notified, or read), reads Packet (the stacks use ATT Read Blob when it does not fit in one answer), opens it (13.5), disconnects, closes the `BluetoothGatt` and forgets the ephemeral keys.
10. **Phone**: continues exactly as after scanning a code: `fromQr(code)` gives S and the relay; the phone shows the relay's host and asks to confirm when it is not the default relay; it stores S, connects, sends `hello`, then shows Save to your password manager (section 8).
11. **Mac**: the session ends when the phone leaves after reading Packet, or 10 s after the first read of Packet. It removes the service (`removeAllServices`), forgets the keys, and waits for the phone's `hello` through the relay, which shows "Connected to <phone name>": the one celebration, as in section 8.

Any failure, cancel or timeout ends the attempt on both sides. Try again starts a new one: new keys on both devices, a new advertisement, a new code. Never an automatic retry with the same keys.

CoreBluetooth cannot disconnect a central and reports no disconnection to a peripheral. The Mac learns that the phone left through `didUnsubscribeFrom` on Status (this is why the phone subscribes before it writes its key), and it ends a session by notifying the final Status and removing the service. The phone disconnects on every final Status (`0x02` to `0x05`).

### 13.4 Keys and derivations

`pk_mac` and `pk_phone` are raw X25519 public keys, 32 bytes (RFC 7748: the u-coordinate, little-endian). `‖` is concatenation, labels are UTF-8, and HKDF is HKDF-SHA256 with an empty salt, as in section 1.

| Name | Definition | Size |
|---|---|---|
| commit | `SHA-256("clipway-nearby-commit" ‖ pk_mac)` | 32 bytes |
| T | `pk_mac ‖ pk_phone`, always the Mac first (the roles never swap, so nothing is sorted) | 64 bytes |
| Z | `X25519(own private key, other public key)`, the same on both sides | 32 bytes |
| N | `HKDF(Z ‖ T, info = "clipway-nearby")` | 32 bytes |
| K_sas | `HKDF(N, info = "clipway-nearby-sas")` | 32 bytes |
| K_key | `HKDF(N, info = "clipway-nearby-key")` | 32 bytes |
| code | the first 6 bytes of `HMAC-SHA256(K_sas, T)`, read as an unsigned big-endian integer, modulo 10 000, written as 4 decimal digits with leading zeros (`0195`, never `195`) | 4 digits |
| confirm | `HMAC-SHA256(K_sas, "clipway-nearby-confirm" ‖ T)[0:16]`, compared by the Mac in constant time | 16 bytes |
| AAD | `"clipway-nearby|" + hex(pk_mac) + "|" + hex(pk_phone)`, lowercase hex, UTF-8 | 144 bytes |

- The modulo bias (2^48 is not a multiple of 10 000) is under 1 in 28 billion: negligible.
- **Checks on the other side's key**, on both devices, before use: exactly 32 bytes; the top bit of its last byte clear (`key[31] & 0x80 == 0`: honest keys never set it, and libraries do not all treat it the same way); not equal to the device's own public key; Z not all zeros (a low-order point). CryptoKit, java.security and node:crypto throw for a low-order point instead of returning zeros: same result, the key is refused. A refused key ends the attempt on the phone; on the Mac it gets an error and the advertisement stays open (13.7).
- The code is a value to compare, not a key: someone who sees a screen learns nothing useful from it.
- **Platform calls, no new dependency.** Mac, CryptoKit: `Curve25519.KeyAgreement.PrivateKey()`, `publicKey.rawRepresentation`, `PublicKey(rawRepresentation:)`, `sharedSecretFromKeyAgreement(with:)` then `withUnsafeBytes` for Z, `HKDF<SHA256>.deriveKey`, `HMAC<SHA256>`, `AES.GCM`. Phone, java.security (API 33+): `KeyPairGenerator.getInstance("XDH")`, initialized with `NamedParameterSpec.X25519` where the provider accepts it (the JDK); Android's provider (Conscrypt) refuses that parameter with `InvalidAlgorithmParameterException` and draws X25519 by default, so the phone keeps the default and checks the X.509 prefix below; the raw public key is the last 32 bytes of `getEncoded()` (X.509, 44 bytes); the other side's key is `KeyFactory.getInstance("XDH").generatePublic(X509EncodedKeySpec(302a300506032b656e032100 ‖ raw))`; then `KeyAgreement.getInstance("XDH")`. Fixed private keys, in tests only: `PKCS8EncodedKeySpec(302e020100300506032b656e04220420 ‖ raw)`.

### 13.5 Packet

- **Plaintext**: the JSON `{"v":1,"code":"<pairing code>"}`, where `code` is exactly the text of the QR code (section 1: `clipway:<base64url(S)>`, followed by `?relay=<percent-encoded URL>` when the Mac's relay is not the default one). It is serialized like a head (no spaces, `/` not escaped) and padded like a head (3.3), but to **exactly 256 bytes**: `,"pad":"<k spaces>"` before the final `}`, with k = 256 - L - 9. A code longer than 230 characters does not fit (a relay address of about 190 characters or more): the Mac then does not offer Pair nearby.
- **On the air**: `nonce (12 random bytes) ‖ AES-256-GCM ciphertext (256 bytes) ‖ tag (16 bytes)`, 284 bytes, with the key K_key and the AAD above. It is CryptoKit's `AES.GCM.SealedBox.combined`; on Android, the nonce followed by the output of `Cipher.doFinal`. The existing `seal` and `open` helpers work as they are: envelope `nonce` = hex of the first 12 bytes, `enc` = base64 of the rest.
- **Reading**: exactly 284 bytes, authentication, JSON, `v` equal to 1, `code` a string (other fields ignored), then `fromQr(code)`. Any failure ends the attempt ("Couldn't pair").

### 13.6 Times and limits

| What | Value |
|---|---|
| Mac session | 120 s from the window opening, for advertising, the exchange and both confirmations. At 120 s without both: Status `0x03`, end. A ready session is not cut: it ends when the phone leaves, or 10 s after the first read of Packet. |
| Phone session | 120 s from the tap. No Mac found after 30 s: "No Mac found nearby", with Try again. |
| Connection | 5 s per try; a status 133, 62 or 8 within 3 s gets one more try after 400 ms, within the same 5 s (as in Sonne). |
| Connected to code on screen | 10 s at most, else the attempt fails. |
| MTU | the phone requests 517 and needs at least 35. A read longer than MTU - 1 bytes continues with Read Blob (Packet, when the MTU is under 285). |
| Attempts | one phone key accepted per advertisement on the Mac, one key per tap on the phone; a refused or malformed phone key does not count (13.7). |
| Scans | only while the screen is in the foreground, at most 4 starts in 30 s (Android silently refuses more than 5). |

### 13.7 Mac: the answer to each request

Writes are checked in this order: offset, length, permission, content; reads: permission, then offset. After the end, every read gets `0x02` and every write `0x03` (in practice the service is gone).

| Request | Answer |
|---|---|
| read Commit | `commit` from the offset, to anyone, until the end |
| read Status | the current status to the locked phone, and to anyone before a key was accepted; `0x05` to any other phone after |
| subscribe to Status | accepted; the Mac keeps the set of subscribed phones |
| write Phone key | offset other than 0: `0x07` (invalid offset). Not 32 bytes: `0x0D` (invalid attribute value length). A key already accepted, or the writer not subscribed to Status: `0x03` (write not permitted). Key refused by 13.4: `0x0E` (unlikely error), and nothing changes. Otherwise success: locked to this phone, advertising stops, the code is shown. |
| read Mac key | `pk_mac` to the locked phone; `0x02` (read not permitted) to anyone else, and before a key was accepted |
| write Confirm | offset: `0x07`. Not 16 bytes: `0x0D`. Not the locked phone, no key yet, or a second Confirm: `0x03`. Wrong tag: `0x0E`, Status `0x04` notified, end. Otherwise success, and Status `0x01` notified if Pair was already pressed on the Mac. |
| read Packet | to the locked phone once Status is `0x01`: the packet from the offset (an offset past 284: `0x07`); to anyone else, or before: `0x02` |
| Pair on the Mac | only once the code is shown; Status `0x01` notified if Confirm already arrived |
| Cancel, window closed, Show a code instead | Status `0x02` notified to the locked phone, end |
| the locked phone unsubscribes | it left: end, a success if it had read Packet, otherwise "Pairing stopped on your phone" |

- CoreBluetooth hands every request of one ATT write to `didReceiveWrite`: answer once, to the first request, with the first error found. Prepared ("long") writes arrive with an offset and are refused.
- Reads: answer with the bytes from `request.offset`; the stack cuts them to the MTU and the phone continues with Read Blob.
- Status notifications go only to the locked phone (`updateValue(_:for:onSubscribedCentrals: [phone])`), after the answer to the request that caused them; when `updateValue` returns false, send again on `peripheralManagerIsReady(toUpdateSubscribers:)`.

### 13.8 Screens, words and permissions

| Moment | Phone | Mac |
|---|---|---|
| Start | Pair nearby (the one primary action), Scan a code instead, Type the 12 words, Use my password manager | "Bring your phone near your Mac." Show a code instead |
| Searching | "Looking for your Mac. Keep your phone near it." | |
| Code | "Check that your Mac shows the same code." The code, very large, read digit by digit by TalkBack. Pair, Cancel | "Check that your phone shows the same code." The code, read digit by digit by VoiceOver. Pair, Cancel |
| One side pressed Pair | "Now press Pair on your Mac." | "Now press Pair on your phone." |
| Canceled on the other side | "Pairing was canceled on your Mac." | "Pairing stopped on your phone." |
| Expired | "Time is up. Try again." | "Time is up. Try again." |
| Failed | "Couldn't pair. Try again, or scan a code instead." | "Couldn't pair. Try again, or show a code instead." |
| Busy | "Your Mac is pairing with another phone. Try again." | |
| Bluetooth off | "Turn on Bluetooth to pair nearby." | "Turn on Bluetooth to pair nearby, or show a code instead." |
| Not allowed | "Clipway needs Nearby devices to find your Mac. Allow it in Settings, or scan a code instead." | "Clipway can't use Bluetooth. Allow it in System Settings, Privacy & Security, Bluetooth, or show a code instead." |
| Done | the usual flow after a scan (section 8) | "Finishing on your phone.", then "Connected to <phone name>" |

- Haptics: a light tick when the code appears, a confirmation on Pair, a rejection on a failure. The celebration stays at the `hello` (section 8). Pressed states with springs, sizes and colors from the token files, as everywhere.
- **Android**: the permissions are asked at the tap on Pair nearby, never before, after one sentence: "Clipway uses Bluetooth to find your Mac and show the same code on both screens. It never uses your location." Manifest: `BLUETOOTH_SCAN` with `android:usesPermissionFlags="neverForLocation"`, `BLUETOOTH_CONNECT`, and `<uses-feature android:name="android.hardware.bluetooth_le" android:required="false"/>`. No location permission, no `BLUETOOTH_ADVERTISE`. If they are refused, Pair nearby says so and offers Scan a code instead.
- **Mac**: the App Sandbox entitlement `com.apple.security.device.bluetooth`, added to `mac/Clipway/Clipway.entitlements` and to [`entitlements-mac.txt`](entitlements-mac.txt) in the same commit (CI compares them), and `NSBluetoothAlwaysUsageDescription` in Info.plist: "Clipway uses Bluetooth only while you pair a phone nearby, to show the same code on both screens." The `CBPeripheralManager` is created when the window opens (macOS asks for the permission at that moment, never at launch) and released at the end.

### 13.9 Threat model

1. **Listener in radio range**: sees both public keys, the commitment, the tag and the encrypted packet. Getting S from them means solving the Diffie-Hellman problem on X25519. The code on the screens gives nothing.
2. **Man in the middle**, a device that plays the Mac to the phone and the phone to the Mac during the 2 minutes: it ends up with two different shared secrets, so the two screens show different codes, except by chance, **1 in 10 000 per attempt**. It cannot choose its keys to make the codes match: the Mac commits to its key before it sees a phone key and accepts one phone key per advertisement, and the phone reads that commitment before it sends its own key. If the person presses Pair on both devices **without comparing**, the attacker gets S (it can then read and send items) or makes the phone join its own chain. That is the one rule both screens give: check that the codes match.
3. **Neighbor**: during the 2 minutes, anyone in range sees that a device advertises the Clipway service, can connect, can read the Mac's Bluetooth name through the standard GAP service (Clipway cannot hide it), and can take the one attempt: the Mac then shows a code the person's phone does not show, and the person cancels and tries again. Unless the person presses Pair on the Mac for a code their own phone does not show, the neighbor gets nothing. Outside the window, the Mac advertises nothing.
4. **Wrong Mac**: when two Macs nearby are in Pair nearby at the same time, the phone may pick the other one. The code then appears on that Mac, not on the person's, and the person cancels.
5. **Replay**: every attempt draws new keys on both devices, so a recorded exchange gives nothing later (another Z, another code, the old packet fails authentication). The Bluetooth stacks keep nothing (no bonding).
6. **Post-quantum**: unlike the QR code and the 12 words, nearby pairing relies on X25519. Someone who records a nearby pairing over the air and later has a large quantum computer could recover S, then read what they recorded of the chain. To avoid this, pair with the QR code. A hybrid X25519 and ML-KEM exchange is a candidate for a later version.
7. **Location**: the phone scans with `neverForLocation`, Clipway has no location permission, and scan results only serve to connect to the Mac.
8. **Availability**: jamming, or a neighbor taking every attempt, stops nearby pairing. The QR code and the words still work.
9. The relay is not involved. The relay address in the packet is authenticated (GCM), and the phone still shows a relay that is not the default one before joining.

### 13.10 Tests without Bluetooth

The Android emulator has no Bluetooth LE and CI has no radio, so the exchange is tested without it, then by hand on a Pixel and a Mac.

- **Vectors**, the `nearby` block of `docs/VECTORS.json`: the key pair of RFC 7748, section 6.1 (Mac = Alice, phone = Bob, Z = the RFC's shared secret), `commit`, `transcript` (T), N, K_sas, K_key, `sas_bytes`, `sas_integer`, the code (`sas`), `confirm`, the AAD, two packets with fixed nonces (default relay, and `http://127.0.0.1:7710`) with their plaintext and what they open to, a second phone key whose code starts with 0 (`leading_zero`), codes from raw bytes (`sas_samples`), negative cases (low-order keys, top bit set, own key, wrong commitment, wrong confirm, tampered packet, swapped AAD, short packet), and `sessions`.
- **`sessions`**: 8 scripted exchanges, request by request, with the Mac's answer. Each step has `by` (`phone`, `other` for a second phone, `mac` for the person at the Mac), `op` (`subscribe`, `unsubscribe`, `read`, `write`, `pair`, `cancel`, `expire` for the 120 s limit, `grace_over` for the 10 s after the first read of Packet), `char`, `offset` (0 when absent), `value` (hex, for writes), `expect` (`{"value": hex}`, `{"ok": true}` or `{"error": <ATT code>}`; absent for the person's actions), `notify` (the Status bytes then notified to the locked phone, hex), `state` (`open`, `locked`, `ready`, `ended`), `mac_shows` (the code, while it is shown) and `end` (why the session ended: `done`, `left`, `canceled`, `expired`, `failed`). They run with `mac_private`, the top-level S, the default relay and the nonce of `packet`.
- **Relay**: `relay/test/nearby.test.js` checks `relay/nearby.js` against all of it.
- **Android**, JVM unit tests: the derivations, both packets (open them, and seal them again with the fixed nonce), the negative cases, and the phone's side of the two success sessions: with `phone_private`, the phone writes exactly the `value` of each step it writes (Phone key, then Confirm), computes the code of `mac_shows`, and opens the packet it reads.
- **Mac**: the session state machine lives in `ClipwayCore`, without CoreBluetooth (the app only connects it to `CBPeripheralManager`). `swift test` replays every session with `mac_private` and the packet nonce injected, and a command line test mode plays the phone from the vectors against that machine.
- **By hand**, on a Pixel and a Mac: the success path, Cancel on each side, a code that does not match (a second phone), Bluetooth off, permission refused, the 120 s limit, and the QR code still working.

## 14. Direct transfer of images and files

On the same network, images and files go directly, and nothing of them but a short offer goes through the relay. The device that has the content (the **sender**) listens on its local network and sends an **offer** through the relay (3.1): a short encrypted item with the size, the fingerprint, the port and its local addresses. The other device (the **receiver**) connects to one of those addresses, proves it holds the chain's key, and receives the content, encrypted with a key that exists only for this transfer. Nothing about the content, not even its size, reaches the relay. When the direct transfer is not possible, an image or a file of 6 MiB at most goes through the relay instead (section 15).

Reference: `relay/direct.js` (derivations, records, and a small sender and receiver on `node:net`), the `direct` block of [`docs/VECTORS.json`](VECTORS.json), and `relay/test/direct.test.js`. `relay/tools/client.mjs send --file` and `listen` speak it, so either app can be tested against the command line.

### 14.1 Keys

| Name | Definition | Size |
|---|---|---|
| K_direct | `HKDF(S, info = "clipway-direct")` | 32 bytes |
| transfer | the offer's `item` (16 random bytes, 32 lowercase hex): new for every offer | |
| K_t | `HKDF(K_direct, info = "clipway-direct|" ‖ transfer)` | 32 bytes, AES-256-GCM key of every record of that transfer |

HKDF is HKDF-SHA256 with an empty salt, as in section 1. K_t never travels: both devices derive it from S and the transfer id, which only travels inside the encrypted offer and in the preamble.

### 14.2 Wire format

Plain TCP, the receiver connects. Everything after the preamble is a **record**: `length` (4 bytes, unsigned, big-endian, the number of bytes that follow) ‖ `nonce` (12 random bytes) ‖ AES-256-GCM ciphertext ‖ tag (16 bytes). The AAD of a record is `"clipway-direct|<transfer>|<dir>|<index>"` (UTF-8), where `dir` is `get` (receiver to sender) or `put` (sender to receiver) and `index` counts the records of that direction from 0. A record moved to another transfer, direction or position fails authentication; random nonces under a key used for one transfer only cannot repeat in practice (at most 402 records).

| Step | Who | Bytes |
|---|---|---|
| preamble | receiver | `"CWD1"` (ASCII) ‖ transfer (16 bytes): 20 bytes, in the clear |
| get 0 | receiver | `{"v":1,"get":"<transfer>"}` |
| put 0 to n - 1 | sender | the content, 65 536 bytes per record, the last one shorter; n = ceil(size / 65 536), none for an empty file |
| get 1 | receiver | `{"v":1,"status":"done"}` once the content is checked and written, or `{"v":1,"status":"failed"}` |

- Record sizes: a put record carries at most 65 536 bytes of content (its `length` is at most 65 564); a get record at most 1 024 bytes. A larger `length`, or one under 28, closes the connection.
- The sender looks the transfer up from the preamble, opens get 0 with its K_t, and only then sends anything: a connection that cannot do that (a stranger on the network, an old offer) gets nothing and is closed. **One proven connection per transfer**: once get 0 opened, the offer is taken, and any later connection for it is closed.
- The receiver counts the bytes as they come (never more than `size`; every record but the last full), then checks `size` and `fp` (HMAC with K_mac, 3.1) before writing anything, then writes (clipboard, Downloads, history), then sends get 1. The sender marks the item "Delivered" on get 1 `done`.

### 14.3 Times and limits

| What | Value |
|---|---|
| Offer | valid 2 minutes after its `ts`: the sender listens that long, then stops ("expired"); a receiver drops an older offer |
| Connect | 3 s per address, in the order of `hosts`, 12 s for all of them |
| Handshake | the sender closes a connection without a valid preamble and get 0 within 5 s; 8 such connections at most at once |
| Idle | 15 s without a byte, either side: the connection is closed and the transfer fails |
| Size | 25 MiB (26 214 400 bytes) per image or file |

The sender's listening socket exists only while at least one of its offers is open. It listens on all IPv4 interfaces, on a port the system picks (debug builds of the phone: 7721 when free, 14.7).

### 14.4 Addresses

- An offer lists the sender's IPv4 addresses on a local network, at most 8: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and link-local `169.254.0.0/16`. No public address, no IPv6 in version 1, no host name.
- A receiver connects **only** to such addresses (debug builds also to `127.0.0.1`, and the phone's to `10.0.2.2`, for the emulator). A direct transfer therefore never crosses the Internet, and Clipway never connects to an address on the Internet that an offer names.
- A sender with no such address (the phone on mobile data only, the Mac offline) does not offer: it sends the content through the relay in chunks (section 15) when it is 6 MiB at most, and otherwise says "Not sent: over 6 MB, connect to the same Wi-Fi as your Mac" (or "as your phone").

### 14.5 What each side shows

| Moment | Sender | Receiver |
|---|---|---|
| Offer sent | history row "Sending" | |
| Fetched and checked | "Delivered" | the item, as in 3.5 |
| No address answered | 6 MiB at most: sent through the relay instead (15.4), the row goes back to "Sending". Larger: "Not sent: your devices aren't on the same network" (on the reply `unreachable`) | Larger: "Couldn't receive <name> from <device>: your phone and your Mac need to be on the same network". 6 MiB at most: nothing, the content comes through the relay |
| Transfer broke, or wrong fingerprint | 6 MiB at most: through the relay instead. Larger: "Not sent" (reply `failed`, or get 1 `failed`) | Larger: "Couldn't receive <name> from <device>. Try again." |
| 2 minutes without an answer | "Not sent: your Mac didn't answer. Both need to be on, with Clipway on, on the same network." | |

Phone: a notification on the quiet "Received" channel for the receiver's failures, and the history row for the sender. Mac: a note in the menu, a notification, and the history row. Both apps say in What leaves your device that images and files go directly over the local network when they can, and otherwise through the relay in encrypted pieces, 6 MB at most.

### 14.6 Threat model

1. **The relay** sees an offer as an ordinary item of 512 or 1 024 bytes: it cannot tell it from a short text, and never sees the content, its size, its name, its type, or the local addresses.
2. **Someone on the local network** sees the preamble (a random transfer id), the records (encrypted), their sizes and timing, so roughly how big the content is, and the two local addresses. Without S it cannot open a record nor produce a get 0, so it gets nothing from the sender; it can connect and hold one of the 8 handshake slots for 5 s (availability only).
3. **Integrity**: AES-GCM with the transfer, direction and position in the AAD, then the fingerprint (keyed by K_mac) over the whole content: a record cannot be changed, reordered, dropped, replayed into another transfer or truncated without the receiver refusing the content before writing it.
4. **A forged offer** needs K_enc (it is an encrypted item), so only a device of the chain can make the other one connect somewhere, and only to a local network address.
5. **Replay**: an offer is valid 2 minutes, its transfer id is drawn once, and a sender serves each transfer to one proven connection, then forgets it.
6. **Availability**: a network that isolates its clients (some guest or public Wi-Fi), a firewall, or the devices on different networks stop the direct transfer; texts still go through the relay. The app says so (14.5). A VPN on one device may also hide the local network.
7. **Same keys as the chain**: someone who has the 12 words can derive K_direct and fetch an offered file if they are on the same network within the 2 minutes, exactly as they can read texts (section 10, point 8).
8. Post-quantum: symmetric only, as the relay items.

### 14.7 Local testing

- `relay/tools/client.mjs`: `send --file PATH` listens on this computer (`--port`, `--hosts`, `--loopback` to also list `127.0.0.1`) and sends the offer; `listen` fetches offers (`--loopback` also connects to `127.0.0.1`, `--extra-hosts`) and answers `unreachable` through the relay when it cannot.
- Mac and emulator, with a relay on the Mac and `adb reverse tcp:7710 tcp:7710`:
  - Mac to phone: the emulator reaches the Mac's own addresses through its network, and the phone's debug build also tries `10.0.2.2` at the offer's port.
  - Phone to Mac: the phone's debug build listens on 7721 when free and lists `127.0.0.1` first; `adb -s emulator-5554 forward tcp:7721 tcp:7721` makes the Mac's debug build reach it.
- Release builds keep the rules of 14.4 only.

## 15. Images and files through the relay (chunked items)

When an image or a file cannot go directly (section 14), it goes through the relay as one **chunked item**: an encrypted head, then the content cut in encrypted **chunks**. Since Clipway 0.4.0, on relays that announce `limits.parts` 97.

Reference: `buildItem` and `readItem` in `relay/crypto.js`, the `chunked_item`, `chunked_file_item` and `chunked_empty_item` blocks of [`docs/VECTORS.json`](VECTORS.json), `relay/test/crypto.test.js` and `relay/test/flow.test.js`. `relay/tools/client.mjs send --file PATH --chunked` sends one, and `listen` receives them.

### 15.1 Parts

| Part | Plaintext | AAD | Key |
|---|---|---|---|
| 0: the head | the padded JSON head of type `chunked` (3.1): `media`, `mime`, `name`, `size`, `fp`, `chunks` | the chain id, as every head | K_enc |
| 1 to n: chunk i = part - 1 | content bytes `[i x 65 536, (i + 1) x 65 536)`, the last chunk shorter, none for an empty file | `"clipway-chunk|<chain id>|<item>|<i>|<n>"` (UTF-8) | K_enc |

- `n = chunks = ceil(size / 65 536)`; an item has `1 + n` parts, at most 65.
- Every part is an ordinary envelope (section 2) with its own random nonce. A chunk envelope's `enc` is 87 404 characters (65 536 + 16 bytes in base64), under the 117 440 of a text.
- Sizes: `size` at most **6 291 456 bytes (6 MiB)**, so 96 chunks. All 97 envelopes take about 8.4 MB of base64, under the 9 MiB queue of a chain.

### 15.2 Integrity

The AAD binds each chunk to the chain, the item, its position and the number of chunks: a chunk moved to another item or position, a chunk missing, added or swapped fails authentication or the part count. Once all chunks are open, the receiver checks that every chunk but the last is full, that the total is `size`, and `fp` (HMAC with K_mac) over the whole content, before writing anything.

### 15.3 Receiving

The relay delivers all parts of an item together, in order, only once the upload is complete. A receiver collects the parts of one `seq` (part 0 first; more than 97 parts, or parts out of order, are dropped), then opens the head, applies 3.4 (freshness 24 h + 10 min, duplicates, own items: an offline phone gets the photo up to 24 hours later), opens and checks the chunks (15.2), writes the content (3.5), and only then acknowledges the item. A chunked item that fails a check is dropped and acknowledged; one it could not write (storage full) is not acknowledged, and comes back at the next connection.

### 15.4 Which way an image or a file goes

The sender decides, in this order:

1. **Directly** (section 14) when the other device is connected to the relay (`presence` 2 or more) and this device has an address on a local network. Also directly, as in 0.3.0, when the content cannot go through the relay (over 6 MiB, or a relay with `parts` 1) and there is a local address.
2. If that direct transfer ends `unreachable`, `expired` or `failed` (not `declined`), a content of 6 MiB at most is sent again **through the relay**, as a chunked item with a **new item id**; the history row of the offer goes back to "Sending" and follows the chunked item (Sent, Waiting, Delivered).
3. **Through the relay** at once when the other device is offline, or this device has no local address (the phone on mobile data), and the content is 6 MiB at most on a relay that takes 97 parts.
4. Otherwise not sent: "Not sent: over 6 MB, connect to the same Wi-Fi as your Mac" (or "as your phone"), or, with a relay older than 0.4.0, "Not sent: connect to the same Wi-Fi as your Mac".

Apps learn `limits.parts` from `welcome` (Android also keeps it between connections, reset to 1 when the relay setting changes).

### 15.5 Limits on the relay

The queue of a chain grows from 6 MiB to 9 MiB in 0.4.0 (50 items, 24 h, oldest evicted first), so that a 6 MiB item (about 8.4 MB of envelopes) fits with room for texts; the rates (60 items per minute, 60 MiB per hour per chain), the global memory limit and the per-IP limits stay as they are (4.7). Uploads in progress may hold 9 MiB per connection (a whole 6 MiB item), and an upload that is not complete within 2 minutes, or whose connection closes, is dropped: an incomplete item never reaches another device and never stays in memory.

### 15.6 Threat model

1. **The relay** sees ciphertext only: it cannot read the head nor the chunks, nor tell an image from a file. It sees that an item has several parts, so that it is an image or a file sent through it, and its number of parts, so its size to within 64 KiB. Everything else is as for texts (section 10): kept 24 h at most, in memory, never on disk.
2. **Integrity**: 15.2. A relay can drop or delay a chunked item, or refuse it, not change, truncate or reorder it.
3. **Abuse**: the relay cannot see what travels, as for texts. It limits what one chain can hold and send (9 MiB, 24 h, 60 MiB per hour), so a chain is a poor way to distribute files to many people: there is no link, no account, and items go only to the devices that hold the chain's key.
4. **Same keys as the chain**: someone who has the 12 words can read a chunked item within its 24 hours, exactly as a text (section 10, point 8).
5. Post-quantum: symmetric only, as the other items.

