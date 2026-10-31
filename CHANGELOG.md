# Changelog

Notes for people. The technical details live in the commit history and [docs/PROTOCOL.md](docs/PROTOCOL.md).

## 0.3.0

**New**

- No media on our servers. The relay now carries texts only, 64 KB at most, and refuses anything else. Without accounts and with end-to-end encryption, nobody can check what travels, so Clipway will not be a way to pass pictures or files around.
- Images and files go straight from one device to the other over your local network, never through a server, encrypted with a key made for that one transfer. The relay only passes a short encrypted note that tells the other device where to fetch them.
- When the two devices are not on the same network, both say so plainly: "Not sent: not on the same network" on the sending side, "Couldn't receive photo.jpg from your Mac" with the reason on the other.
- A new look, the same as the icon: Clipway's own color, Lac, light and dark, instead of the wallpaper's colors. Flat, everything rounded. Titles in Bricolage Grotesque, text in Figtree.
- A new icon: two opposite arrows on lac, the same on the phone (with a themed version), in its notifications and tile, and on the Mac.

**Improved**

- What leaves your device, About, the privacy policy and the threat model say where images and files go, and what someone on the same network can see.
- On the Mac, an image copied while the phone is offline is not sent, and the menu says why: an offer lasts 2 minutes.
- On the Mac, the Debug build is its own app, so tests never touch your key.
- First release: a signed APK, kept up to date by Obtainium from the GitHub releases, and a zip of the Mac app (signed ad hoc, no automatic update yet).

**Known problems**

- The direct transfer was tested between the Mac and the Android emulator, and with the command line client, not yet between a real phone and a Mac on Wi-Fi.
- A guest or public Wi-Fi that isolates its clients, a VPN, or the phone on mobile data stops images and files. Texts still go through the relay.
- Clipway 0.2 apps cannot send images or files through this relay any more: update both apps.

## 0.2.2

**New**

- A switch to pause Clipway, on both devices: at the top of the Home screen on the phone, and at the top of the menu bar menu and of the History window on the Mac. One tap pauses, one tap turns it back on, and the state reads On or Paused.
- Paused means nothing runs: no connection to the relay, nothing sent automatically from the Mac, nothing received, no background notification on the phone. What the other device sends meanwhile waits on the relay for 24 hours at most. It stays paused after a restart until you turn it back on, and everything then starts again as before, without asking anything.
- On the phone, the Send to Mac tile says Paused while Clipway is paused. On the Mac, the menu bar icon shows a pause sign.

## 0.2.1

**New**

- Permissions, on both devices: each one Clipway uses, with one sentence on why and which feature needs it, and its state. One tap turns it on, and when it is on, the same tap opens the exact page of the system settings where you can turn it off. On the phone: Notifications, Nearby devices, Camera and Background use, from Settings and from About. On the Mac: Bluetooth, Notifications and Open at login, in Settings.
- The state is read again each time you come back to Clipway, and a feature without its permission says calmly how to turn it back on. Clipway never asks twice in a row.

**Improved**

- On the Mac, Settings scrolls when the screen is short.

## 0.2.0

**New**

- Pair nearby: no QR code, no words to type. On the Mac, Pair a phone; on the phone next to it, Pair nearby. Both screens show the same 4-digit code: check it, press Pair on both, and the key goes to the phone over Bluetooth, encrypted. The QR code is still there (Show a code instead on the Mac, Scan a code instead on the phone), and the 12 words stay your backup.
- On the Mac, Show the key also offers Pair nearby, after Touch ID or your password, to add a phone later.
- On the Mac, Show in Dock (Settings, on by default): Clipway appears in the Dock and in Cmd Tab, and a click on its icon opens the history, or Pair a phone. Turn it off to keep Clipway in the menu bar only. It applies at once, no restart.
- On the phone (Android 13 and later), Pair nearby is the first choice when you pair. Nearby devices is asked at that tap, with one sentence on why, and Bluetooth is used only on that screen. Android 12 keeps Scan the code and the 12 words.

**Improved**

- What leaves your device says when Bluetooth is used: only while you pair, 2 minutes at most, and never for your location.
- On the phone, a nearby pairing then goes exactly like a scanned code: another relay is shown before joining, then Save to your password manager. Clear messages when Bluetooth is off, when Nearby devices is not allowed, when no Mac is found after 30 seconds, and when the Mac cancels.

**Known problems**

- Pair nearby has not been tried yet between a real phone and a Mac. Its exchange is checked without Bluetooth, against the test vectors shared by the apps.
- The first Pair nearby on the Mac asks to allow Bluetooth for Clipway.
- Android: Pair nearby was tried only on the emulator, which finds no Mac over Bluetooth, and with a Mac played inside a debug build.
- Everything listed under 0.1.0 still applies.

## 0.1.0

**New**

- Copy on your Mac, paste on your phone: texts and images reach the phone's clipboard a second later, with a quiet "Copied from your Mac".
- Send from your phone in one gesture: the Send to Mac tile in Quick Settings, Send to Mac in the text selection menu, or the share menu. Texts and images go to the Mac's clipboard.
- Files both ways, up to 25 MB each, into Downloads/Clipway: Send a file or drop on the menu bar icon on the Mac, the share menu on the phone.
- No account: your key is 12 words. The Mac shows them as a QR code that the phone scans. Save them in your password manager (Android 14 and later), print a rescue kit, or show them again behind Touch ID or the phone's lock.
- What password managers mark as secret on the Mac, and what Android marks as sensitive, is never sent.
- History of the last 50 items on each device, encrypted, with Undo, and an export to a ZIP file that opens without Clipway.
- Erase everything, on either device: the key, the history and the settings, and what waits on the relay.
- The relay: passes encrypted items between your devices, keeps them up to 24 hours in memory for a device that is offline, logs no address and no content, and runs anywhere with Docker.

**Known problems**

- The reference relay clip.sidali.dev is not online yet. Until it is, run a relay on your Mac and use the Debug build of the Mac app (see the README).
- On the phone, items not yet stored by the relay are kept in memory: if Android stops Clipway first, they stay "Sending" in history and you send them again.
- With more than one phone or Mac on the same key, a device that is offline can miss an item another device already received.
- Mac: the app is signed ad hoc (no Apple Developer ID). macOS warns the first time you open it, and after each update it asks once to let the new version read the key in the Keychain.
- No automatic updates yet, on either app.
- Not yet tested on a physical phone: scanning the code with the camera, saving the words to Proton Pass, and a full day on battery.
