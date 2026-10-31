# Threat model

Clipway passes the texts you copy between your own devices through a relay that cannot read them. Images and files never go through the relay: they cross the local network directly, encrypted (docs/PROTOCOL.md, section 14). The specification is [docs/PROTOCOL.md](docs/PROTOCOL.md).

**Protected**

1. The content of everything you send (text, images, files), file names, device names and device ids: AES-256-GCM with a key derived from a 128-bit secret that only your devices hold. The relay, its host and the network see ciphertext. Images and files are never on the relay: they go device to device, encrypted with a key derived for that one transfer.
2. Integrity: a relay cannot forge, alter or move items to another chain (GCM tags, the chain id as AAD). On the direct connection, each record binds the transfer, the direction and its position, and the whole content is checked against its keyed fingerprint before anything is written.
3. Replays: items older than 24 hours and duplicates are dropped by the receiving device.
4. Secrets marked by password managers (Mac) or by Android as sensitive are never sent.
5. Keys at rest: Mac Keychain (not synced to iCloud), Android Keystore; no backup, no device transfer. Erase everything destroys the keys.
6. Nearby pairing (Bluetooth): the key crosses the air only inside a packet encrypted with a key from an ephemeral X25519 exchange, and only after you press Pair on both devices. A man in the middle in Bluetooth range makes the two screens show different 4-digit codes (they match by chance 1 time in 10 000 per attempt); he cannot choose his keys to make them match, because the Mac commits to its key first and accepts one phone per attempt. Every attempt uses new keys, so a recorded pairing cannot be replayed. No location is used, and the Bluetooth stacks keep nothing (no bonding). Details: [docs/PROTOCOL.md](docs/PROTOCOL.md), section 13.9.

**Seen by the relay** (and whoever runs or seizes it)

7. A random chain id, the time and size of every item (padded to 512 bytes; texts are 64 KB at most, and an offer for a file looks like a short text), how many devices are connected, and IP addresses while connected (in memory, for rate limits, never logged by the relay; on clip.sidali.dev the web server in front of it keeps IP addresses, times and paths for 7 days). So: when you copy something on the Mac, and roughly how big it is.
8. It keeps encrypted items 24 hours at most, in memory. It can drop, delay or refuse them: availability is not protected.
8b. The relay refuses anything larger than a 64 KB text or cut in parts, so it cannot be used to pass images or files around. A modified app could still hide 64 KB of anything in a "text"; that is the most the relay ever carries per item.

**Seen on the local network** (during a direct transfer)

8c. Someone on the same network sees that two devices exchange encrypted data, how much, when, and their local addresses. Without the key they cannot read it, and the sending device gives nothing to a connection that cannot prove it holds the key. A network that isolates its clients, or devices on different networks, stops images and files (texts still go through the relay), and the apps say so.

**Not protected**

9. Anyone who has your 12 words or the pairing QR code can read everything sent on the chain and send items to your devices. Change the key if they leak.
10. No forward secrecy in v1: someone who records ciphertext and later gets the words can decrypt it.
11. Pressing Pair on both devices without comparing the codes: a man in the middle at that moment would get the key, or make the phone join his chain.
12. During the 2 minutes of a Pair nearby window, anyone in Bluetooth range sees that a Clipway Mac is pairing, can read the Mac's Bluetooth name, and can take the attempt (you then cancel and try again). Outside that window the Mac advertises nothing.
13. An unlocked device in someone else's hands, malware or a rooted system, the keyboard, and the other apps that can read the clipboard once Clipway writes to it.
14. Flash storage may keep old encrypted blocks after erasing; without the destroyed keys they are unreadable.
15. Other clipboard syncs on the same device (an Android emulator's host clipboard, Universal Clipboard, other sync tools) copy what Clipway writes to their own places, without the password managers' markers, and can feed it back to Clipway as a new copy. Erase everything does not clear the system clipboard.

**Position**

16. Post-quantum: symmetric cryptography only (AES-256-GCM, HMAC-SHA256, HKDF) from a 128-bit secret; nothing relies on public-key cryptography, except nearby pairing (X25519). Someone who records a nearby pairing over the air and later has a large quantum computer could recover the key, then read what they recorded of the chain. Pairing with the QR code or the 12 words avoids it. A hybrid X25519 and ML-KEM exchange is a candidate for a later version.
17. A pairing code can name another relay: that relay sees the same metadata as ours, never the content, and the phone shows its host before joining.
18. Audits: internal reviews in [docs/security](docs/security). No external audit yet.
19. Cyber Resilience Act: Clipway is free, non-commercial software, outside the CRA's scope today. To revisit if that changes.
