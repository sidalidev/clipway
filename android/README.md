# Clipway for Android

Kotlin, Jetpack Compose, `dev.sidali.clipway`, minSdk 31, targetSdk 36. Built and tested for GrapheneOS: no Google Play Services, no analytics. Libraries: AndroidX (Compose, Activity, Credentials for the password manager), OkHttp (the WebSocket) and ZXing core (QR codes).

Specification: [../docs/PROTOCOL.md](../docs/PROTOCOL.md), sections 5, 6, 8, 9 and 13 (Pair nearby). Screenshots: [../docs/screenshots/android](../docs/screenshots/android).

```bash
export JAVA_HOME=<JDK 21>            # Android Studio's bundled runtime works
./gradlew :app:testDebugUnitTest     # protocol, engine, crypto and nearby pairing against docs/VECTORS.json
./gradlew :app:lintDebug :app:assembleDebug
./gradlew :app:assembleRelease -Punsigned
```

Release signing reads `~/.clipway/keystore.properties` (never in the repository).

## Where things are

| File | What it does |
|---|---|
| `Crypto.kt` | HKDF, AES-256-GCM envelopes, fingerprints, 12 words, QR text (the Sonne chain with Clipway labels) |
| `Protocol.kt` | Heads, chunks, padding, freshness, duplicates, file names, relay addresses, frames. Pure JVM, tested |
| `Engine.kt` | The relay protocol of one connection: sync, backlog, uploads kept until `stored`, acks. Pure JVM, tested |
| `ClipService.kt` | Foreground service (specialUse): OkHttp WebSocket, reconnection with back-off, watchdog alarm, notification |
| `Inbox.kt` | What arrives: clipboard (text, images through the non-exported `ClipProvider`), Download/Clipway, notifications |
| `Send.kt` | What leaves: Send to Mac tile, text selection menu, share target, Send clipboard; sensitive clips refused |
| `History.kt` | The last 50 items, AES-256-GCM at rest with a key wrapped by the Keystore; ZIP export |
| `Store.kt` | Settings, the chain secret (Keystore, StrongBox when available), device id |
| `Key.kt`, `Scanner.kt` | Password manager, rescue kit (print), biometric lock, QR reader (Camera2 and ZXing) |
| `Nearby.kt` | Pair nearby without radio: X25519 (java.security XDH, Android 13+), derivations, code, packet, and `NearbyPhone`, the order of the phone's requests. Pure JVM, tested |
| `NearbyCentral.kt` | Pair nearby over Bluetooth LE: scan filtered on the Clipway service, GATT client, timeouts; `NearbyPairing`, the one attempt the screen shows |
| `PairNearby.kt` | The Pair nearby card: rings while searching, the 4-digit code, why an attempt stopped |
| `NearbyDemo.kt` | Debug builds only: a Mac played in the app, to try Pair nearby without one (below) |
| `Onboarding.kt`, `Home.kt`, `About.kt`, `Ui.kt`, `Hero.kt` | Screens |
| `Tokens.kt` | Every color (Lac, the color of the icon, light and dark), font, size, type size, spring and glyph. CI refuses sizes and colors elsewhere |

## Testing against a local relay

```bash
cd relay && HOST=127.0.0.1 PORT=7710 node server.js        # the relay
node tools/client.mjs new --relay http://10.0.2.2:7710      # a chain; the QR text names the relay
export CLIPWAY_KEY='clipway:...' CLIPWAY_RELAY=http://127.0.0.1:7710
node tools/client.mjs hello --name "MacBook Air" --kind mac # the Mac stand-in
node tools/client.mjs listen                                # prints what the phone sends
node tools/client.mjs send "some text"                      # lands in the phone's clipboard
```

On the phone (debug build): Pair, Type the 12 words, and paste the QR text (`clipway:...?relay=...`), or type the 12 words and set the relay in Settings. Debug builds accept `http://` to `10.0.2.2` (the emulator's view of this computer), `127.0.0.1` and `localhost` (a real phone with `adb reverse tcp:7710 tcp:7710`). Release builds accept `https://` only.

Useful on the emulator: `adb shell am start -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT "hi" -n dev.sidali.clipway/.ShareActivity` (share), and `adb shell cmd statusbar add-tile dev.sidali.clipway/.SendTile` (the tile).

## Pair nearby without a Mac

Pair nearby needs a Mac running Clipway next to the phone. Without one (the emulator, CI), three things check it:

- `NearbyTest` replays the vectors (`nearby` block of `docs/VECTORS.json`): keys, code, confirmation, packets, refused keys and packets, and the phone's side of the two success sessions, request by request.
- `adb shell am start -n dev.sidali.clipway/.MainActivity --ez nearby_selfcheck true` (debug builds) runs the same checks on the phone's own X25519 and logs `Nearby self-check: ok (10 checks)` under the tag `ClipwayNearby`. Android's provider is not the JDK's: it refuses the curve named in `initialize`, and draws X25519 by default.
- `adb shell "am start -n dev.sidali.clipway/.MainActivity --es nearby_demo 'clipway:...'"` (debug builds) makes Pair nearby talk to a Mac played in the app instead of the radio: the real requests, keys, code and packet, a Mac that presses Pair 2.5 s after the phone, then the usual path after a scan with that pairing code. With a chain from `node tools/client.mjs new --relay http://127.0.0.1:7710` and `adb reverse`, it goes all the way to the hello and "Connected to".

Release builds contain neither: both are behind `BuildConfig.DEBUG`, and R8 removes them.

## Permissions

Exactly the list in [../docs/permissions.txt](../docs/permissions.txt), each with its reason. `aapt2 dump permissions` on the release APK must print the same list.
