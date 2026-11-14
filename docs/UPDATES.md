# Automatic updates

Since 0.4.1 both apps update themselves, like Sonne and AImpire: one `update.json` is published with each release, the apps read it, check what they download, and install only after the person taps or clicks Install. No store, no account, no identifier.

## Where it is hosted

The reference relay serves the release files, read only, from a folder on its server (`CLIPWAY_RELEASES_DIR`, mounted on `/releases` in `deploy/docker-compose.yml`):

- `GET https://clip.sidali.dev/update.json`: the manifest below, re-read at each request, 64 KB at most, `Cache-Control: public, max-age=300`.
- `GET https://clip.sidali.dev/download/clipway-<x.y.z>.apk` and `/download/clipway-mac-<x.y.z>.zip`: nothing else. The name is checked strictly (`^clipway-(mac-)?\d{1,4}\.\d{1,4}\.\d{1,4}\.(apk|zip)$`, an APK only without `mac-`, a zip only with it), links and folders are refused, a published file never changes under the same name.

The apps always ask `clip.sidali.dev`, whatever relay they use for the clipboard. A self-hosted relay without `CLIPWAY_RELEASES_DIR` answers 404 to these routes, which is fine: they are not used by the apps then.

The same files are attached to the GitHub release `v<x.y.z>`, with their `.sha256` files: Obtainium keeps following the releases, and installs the same APK, signed with the same key, so both ways work side by side.

## update.json

```json
{
  "version": "0.4.1",
  "android": { "version": "0.4.1", "versionCode": 7, "url": "https://clip.sidali.dev/download/clipway-0.4.1.apk",
               "sha256": "<SHA-256 of the APK>", "size": 4321000, "certSha256": "<SHA-256 of the signing certificate>" },
  "mac": { "version": "0.4.1", "build": 7, "url": "https://clip.sidali.dev/download/clipway-mac-0.4.1.zip",
           "sha256": "<SHA-256 of the zip>", "size": 4100000, "ed25519": "<Ed25519 signature of the zip, base64>",
           "minimumSystemVersion": "14.0" },
  "notes": "<the CHANGELOG.md section of the version>",
  "published": "2026-11-14T18:00:00.000Z"
}
```

Written by `tools/update-manifest.mjs`, called by `tools/release.sh`.

## When the apps check

At launch (Mac: 3 seconds after; phone: when the app comes to the foreground, at most once a minute), then once a day (Mac: a timer; phone: the existing watchdog alarm, no new alarm or service), again an hour after a failure. Only when **Automatic updates** is on, which is the default (Mac: Settings; phone: Settings, Updates). "Check for updates" asks at once, also when the setting is off.

The request carries no identifier: no cookie, no device id, no chain id, no system profile; the User-Agent is `Clipway-mac/<version>` or `Clipway-Android/<version>`. The server sees the IP address, as for any request (the web server in front of clip.sidali.dev keeps it 7 days, PRIVACY.md).

A newer version (Android: higher `versionCode`; Mac: higher `build`, and a macOS at least `minimumSystemVersion`) shows a banner on the phone's Home screen and a menu item "Update to Clipway x.y.z…" on the Mac, plus one notification per version. Nothing downloads before Install.

## Android: checks and installation

Same as Sonne's built-in update (`Updater.kt`, `UpdateCheck.kt`).

1. `url` must be exactly `https://clip.sidali.dev/download/clipway-<version>.apk`.
2. Download into the app's cache with OkHttp (no redirect followed), never more than the announced size.
3. Size and SHA-256 equal to the manifest's.
4. `getPackageArchiveInfo`: package `dev.sidali.clipway`, `versionCode` equal to the manifest's.
5. Signing certificates (`GET_SIGNING_CERTIFICATES`, `apkContentsSigners`): exactly those of the installed app, containing `certSha256`, and in release builds the certificate compiled in the app (`BuildConfig.UPDATE_CERT_SHA256`, the one in SECURITY.md, `0b48d179…a38e`). A hacked server or manifest is not enough: the signing key would be needed, and it never leaves the publisher's computer.
6. `PackageInstaller` session, `MODE_FULL_INSTALL`, `setRequireUserAction(USER_ACTION_REQUIRED)`: the system confirmation is always shown. Permission `REQUEST_INSTALL_PACKAGES`; if "Install unknown apps" is off for Clipway, the banner says so and opens the setting (GrapheneOS asks the same way). After the installation, `MY_PACKAGE_REPLACED` restarts the connection; key, history and settings stay.

Any failure deletes the file and says why in the banner (network, checksum, certificate, storage); the installed app keeps working.

## Mac: checks and installation

The Mac app is signed ad hoc (no Apple Developer ID) and sandboxed. A sandboxed app cannot replace itself, and everything it writes is quarantined, so the solution of AImpire (download, check the SHA-256, show the zip in the Finder) would leave the replacement to the person. Sparkle was considered: with an ad hoc signature its framework cannot be loaded under the hardened runtime without turning library validation off. Clipway does the third way, with no third-party code: an atomic replacement checked by SHA-256 and by an Ed25519 signature.

1. `url` must be exactly `https://clip.sidali.dev/download/clipway-mac-<version>.zip` (`Update.parse`, ClipwayCore).
2. After Install, the app downloads the zip into its container and checks the size, the SHA-256 and the **Ed25519 signature of the whole zip** against the public key compiled in the app (`Update.publicKey`). The private key is `~/.clipway/update-ed25519.pem` on the publisher's computer, mode 600, never in the repository or on the server.
3. The app hands the zip to **ClipwayUpdater.xpc**, an XPC service embedded in Clipway.app, reachable only by it, outside the sandbox and without any entitlement. It trusts nothing the app says: it reads the zip itself and checks size, SHA-256 and signature again, unpacks it with `ditto` (without quarantine) into a hidden folder next to Clipway.app, checks that the folder holds only `Clipway.app`, that its bundle id is the installed one's, that its version and build are the announced ones and its build is higher (no downgrade), and that its code signature is valid (`codesign --verify --deep --strict`). Then it swaps the two apps in **one atomic rename** (`renamex_np`, `RENAME_SWAP`) and deletes the old one. Any failure leaves the installed app untouched.
4. The app opens the new version and quits.

If Clipway.app sits in a folder the person cannot write to, the update says so: move Clipway to Applications, or download the zip by hand.

## Keeping the pairing across updates (Mac)

Until 0.4.0 the Mac kept the key in the login Keychain. macOS ties such an item to the code directory hash of the app that created it, and every ad hoc build has another hash: a new version could not read the key without the user's password, and lost the pairing (seen from 0.3.0 to 0.4.0).

Since 0.4.1 the chain key and the history key are sealed to a P-256 key of the Mac's **Secure Enclave** (`KeySeal`, ClipwayCore: ECDH with an ephemeral key, HKDF-SHA256, AES-256-GCM), in `Application Support/Clipway/keys` inside the app's container, files readable by the user only. The enclave key is kept as the enclave's own wrapped blob: only this Mac's Secure Enclave can use it, whatever the app's signature, so every version opens the key, and a copy of the files on another computer (a backup, a disk) opens nothing. The key is never written in clear. Another app needs macOS's permission to read Clipway's container. Erase everything deletes the sealed files and the enclave key.

Moving from 0.4.0: on its first launch, 0.4.1 reads the two Keychain items (macOS asks once per item to let the new version use them: choose Always Allow), seals them and deletes the Keychain items when macOS lets it. A Mac without a Secure Enclave keeps using the Keychain, and asks again after each update.

Tested with two successive builds of different code directory hashes: the first pairs (key sealed, no Keychain item, the 12 words and the pairing code found nowhere in the container), the update installs the second, which opens paired, with no prompt.

## Publishing a release

```bash
tools/release.sh                 # builds, tests, signs; everything in build/release/<version>/
CLIPWAY_VPS=user@host CLIPWAY_RELEASES_DIR=/path/to/releases tools/publish.sh <version>
```

`tools/release.sh` checks that the versions agree, runs the relay, ClipwayCore and Android tests, builds the signed APK (JDK of Android Studio: Homebrew's breaks Gradle) and checks its certificate, runs `.github/checks.sh`, builds the Mac app and its zip, signs the zip and writes `update.json`. `tools/publish.sh` copies the files then `update.json` to the server (each by a rename, so the manifest never points to a missing file), checks them online, and creates the GitHub release.

## Tests

- Relay: `relay/test/update.test.js` (routes, strict names, links, folders, broken manifests), `relay/test/update-manifest.test.js` (the Ed25519 signature with RFC 8032 test 1, the command line).
- Mac: `UpdateTests` (manifest, host, versions, size, checksum, signature, the RFC 8032 vector signed by Node and checked by CryptoKit, the unpacked app), `KeySealTests`.
- Android: `UpdateCheckTest` (manifest, host, checksum, certificates, the pinned certificate equal to SECURITY.md's).
- End to end on the Mac: a Debug build 0.4.1 (7) updated to 0.4.2 (8) through a local relay; a zip signed by another key refused by the app and, with the app's check skipped, by the installer service.
