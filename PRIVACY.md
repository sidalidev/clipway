# Privacy

Clipway has no account, no analytics, no ads and no crash reporting. It is end-to-end encrypted: the relay that passes your texts along cannot read them, and your images and files never reach it at all.

## What leaves your device

The apps show these same facts on their "What leaves your device" screen.

- **Texts you copy and send.** On the Mac, the texts you copy while "Send automatically" is on. On the phone, only what you send yourself: the tile, "Send to Mac" in the text selection menu, or the share menu. Texts of 64 KB at most go to the relay you set (by default `clip.sidali.dev`), **end-to-end encrypted**: only your devices hold the key.
- **Images and files: never on a server.** They go straight from one of your devices to the other over your local network, encrypted with a key made for that one transfer. The relay only passes a short encrypted note that says where to fetch them, so both devices need to be on the same network. Without accounts and with end-to-end encryption, nobody can check what travels, so our relay refuses to carry pictures or files at all: it would otherwise be a way to pass anything around. While a device offers an image or a file, 2 minutes at most, it accepts one connection on the local network; without the key, a connection gets nothing. People on the same network can see that your two devices exchange encrypted data, and how much.
- **What the relay sees.** A random chain id, the time and size of each item, how many of your devices are connected, and your IP address while you are connected. It never sees the content, file names or your device names, and cannot tell a text from a note about a file.
- **How long.** Items wait on the relay for a device that is offline, **24 hours at most**, then they are erased. The relay keeps them in memory only and never writes them to disk. The relay uses your IP address in memory for rate limits and never logs it. On clip.sidali.dev, the web server in front of the relay logs each request (IP address, time, path, response size, never the chain id) for 7 days. A relay you host yourself does not have to.
- **Never sent.** What password managers mark as concealed or transient on the Mac, and what Android marks as sensitive.
- **The relay's status, once a day.** Each app asks its relay for `/.well-known/clipway-relay.json` (is it up, which app versions it accepts). The request carries no key and no content, only the app's name and version in a fixed User-Agent.
- **Bluetooth, only while you pair.** Nearby pairing uses Bluetooth only while you pair; no location is collected. The Mac shows that it is pairing for 2 minutes at most, while its Pair nearby window is open, and sends the key to your phone over Bluetooth, encrypted, only after you press Pair on both. During those 2 minutes, devices in Bluetooth range can see that a Clipway Mac is pairing and read its Bluetooth name. Nothing about it is stored.
- **Nothing else.** No account, no analytics, no crash reports, no third-party services.

## What stays on your device

- **The key** (12 words). Mac: in the Keychain, never synced to iCloud. Phone: encrypted by Android's keystore. Never in a backup.
- **History**: the last 50 items, encrypted on the device. Erase everything destroys the keys, which makes it unreadable.
- **Received files**: in Downloads/Clipway. They are yours; Erase everything does not delete them.

## Erase everything

In About. It deletes the key, the history and the settings on this device, and asks the relay to erase what it holds for your chain (if the network is there; otherwise the relay erases it within 24 hours). The Mac always asks the relay. On the phone it is a switch, "Also erase the key on the relay", off by default, because it unpairs the Mac too. Files saved in Downloads stay: they are yours.

## Contact

contact@sidali.dev
