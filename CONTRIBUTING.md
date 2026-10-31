# Contributing to Clipway

```bash
cd relay && npm ci && npm test && cd .. && node tools/gen-vectors.mjs && git diff --exit-code docs/VECTORS.json
```

That first command checks the relay and the shared vectors. Then, per part:

- Relay: `cd relay && npm start` (port 7710).
- Android: JDK 21, Android SDK 36. `cd android && ./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug`.
- Mac: Xcode 26, macOS 14+. `cd mac && swift test --package-path ClipwayCore && xcodebuild -project Clipway.xcodeproj -scheme Clipway -configuration Debug CODE_SIGN_IDENTITY=- build`. After editing `project.yml`, run `xcodegen generate`. End to end on a Mac, against a local relay: `mac/tools/e2e.sh`.
- Repository checks: `bash .github/checks.sh` (after an Android release build).

## Ground rules

- **The protocol is one document.** A change to a message, a route or a limit starts in [docs/PROTOCOL.md](docs/PROTOCOL.md), then the vectors (`node tools/gen-vectors.mjs`), then the three parts. CI fails if `docs/VECTORS.json` is not up to date.
- **No custom cryptography.** HKDF, HMAC, AES-GCM from the platform.
- **No new permission** on Android without a line in `docs/permissions.txt` and a reason in PROTOCOL.md. No analytics, no Google Play Services, no Firebase.
- **No new dependency** without a strong reason. Today: `ws` (relay); AndroidX, OkHttp and ZXing core (Android, when needed); nothing outside Apple frameworks (Mac).
- **Colors, sizes and motion come from the token files** (`Tokens.kt`, `Tokens.swift`). CI refuses `.dp`, `.sp` and `Color(0x` elsewhere in the Android sources.
- English only in the apps. Sentence case, one verb per button, no exclamation marks.
- Commits in English, authored `Sid <contact@sidali.dev>`.
