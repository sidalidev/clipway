# Architecture

```
 Mac (menu bar app)                 relay (Node, in memory)                  Android (foreground service)
 NSPasteboard watch  --texts, offers-->  queue per chain id (24 h)  --texts, offers-->  ClipboardManager.setPrimaryClip
 pasteboard write    <--texts, offers--  ack deletes                <--texts, offers--  tile, PROCESS_TEXT, share

 images and files: sender listens on the local network  <==== TCP, encrypted per transfer ====>  receiver connects
```

**Invariants**

- The key S never leaves a device except as 12 words or a QR code shown to the user, or in nearby pairing's encrypted packet, sent over Bluetooth only after the person pressed Pair on both devices for the same code (docs/PROTOCOL.md, section 13). The relay gets P (a proof derived from S) and computes the chain id from it.
- Every byte of content, every file name and every device name is inside an AES-256-GCM envelope.
- The relay carries texts (64 KB at most, one envelope per item) and, since 0.4.0, images and files of 4 MB at most cut in encrypted chunks of 64 KiB (a chunked item of up to 65 envelopes, section 15). Images and files go directly between the devices on their local network first, encrypted with a key of that transfer (section 14); the relay is the way when that is not possible.
- The relay stores nothing on disk and keeps an item 24 hours at most.
- One protocol document ([docs/PROTOCOL.md](docs/PROTOCOL.md)), one set of vectors ([docs/VECTORS.json](docs/VECTORS.json)), three implementations tested against it.

**Where to start**

| Part | Entry point | Crypto |
|---|---|---|
| Relay | `relay/server.js` (`start`) | `relay/crypto.js` (reference, also used by `tools/gen-vectors.mjs`), `relay/nearby.js` and `relay/direct.js` (nearby pairing and direct transfer references, not used by the relay) |
| Android | `android/app/src/main/java/dev/sidali/clipway/MainActivity.kt` | `Crypto.kt`, `Direct.kt`, tests in `CryptoTest.kt` and `DirectTest.kt` |
| Mac | `mac/Clipway/ClipwayApp.swift` | `mac/ClipwayCore` (Swift package, `swift test`), `Direct.swift` for the direct transfer |

Design tokens: `android/.../Tokens.kt` (the Lac palette of the charter, light and dark, Bricolage Grotesque and Figtree, 4 dp grid, type scale, springs) and `mac/Clipway/Tokens.swift` (the same palette, fonts registered at launch).
