# Security policy

## Reporting a vulnerability

The repository is not public yet. Please write to **contact@sidali.dev** with "Clipway security issue" in the subject, and do not post the issue anywhere public. You will get an answer within a week. Once the repository is public, GitHub's private vulnerability reporting will be the preferred channel. The apps' About screens have a "Report a security issue" button that opens the same address.

Include what an attacker can do, the steps to reproduce, and the version or commit.

## Scope

In scope: anything that lets the relay or a network attacker read, forge or replay content; that lets someone without the 12 words join a chain, or get the key over Bluetooth without both screens showing their code and the person pressing Pair on both; that leaks the key, the history or content marked as sensitive; that makes the relay keep data longer than 24 hours or write it to disk; that logs IP addresses or chain ids; or that survives Erase everything.

Out of scope: what the relay can see by design (see [THREAT_MODEL.md](THREAT_MODEL.md)), the clipboard itself once Clipway writes to it, and denial of service by a relay operator.

## Design notes

- Specification and test vectors: [docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/VECTORS.json](docs/VECTORS.json). The relay, the Android app and the Mac app are all tested against the same vectors.
- Standard primitives only, from the platform: HKDF-SHA256, HMAC-SHA256, AES-256-GCM (node:crypto, javax.crypto, CryptoKit), and X25519 for nearby pairing (java.security, CryptoKit). No custom cryptography.
- The chain id never travels in a URL; devices prove the key with a derived value in the WebSocket subprotocol.
- Android permissions: exactly [docs/permissions.txt](docs/permissions.txt); CI checks the merged release manifest against it.
- Mac: App Sandbox (network client, Downloads, user-selected files, printing, and Bluetooth, used only while a Pair nearby window is open), hardened runtime, quarantine on received files.
- Reviews: [docs/security](docs/security). The latest includes a run of both apps against each other through a relay, and what it found.

## Release signing

Android releases on [GitHub](https://github.com/sidalidev/clipway/releases) are signed with this certificate, the same for every version:

```
SHA-256: 0B:48:D1:79:12:1E:2A:F1:2F:34:F7:3F:9B:68:DB:B8:96:6C:D6:49:51:74:A5:07:95:9E:30:9A:88:FE:A3:8E
```

Check a downloaded APK with `apksigner verify --print-certs clipway-<version>.apk`, or compare with the fingerprint that the About screen shows for the installed app. Each APK and zip in a release comes with a `.sha256` file. The Mac app is signed ad hoc for now (no Apple Developer ID): About shows its code directory hash.
