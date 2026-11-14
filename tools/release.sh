#!/usr/bin/env bash
# Prepares a release of Clipway (docs/UPDATES.md), without sending anything anywhere:
#
#   tools/release.sh
#
# 1. Versions agree (Android versionName/versionCode, Mac MARKETING_VERSION/CURRENT_PROJECT_VERSION,
#    relay), CHANGELOG.md has the section, tests pass (relay, ClipwayCore, Android JVM).
# 2. Android: signed release APK (keystore in ~/.clipway, see android/README.md), one signer, the
#    certificate of SECURITY.md, package and version checked with aapt2, repository checks.
# 3. Mac: Release build signed ad hoc, zipped with ditto.
# 4. update.json: SHA-256 and size of both, the APK's certificate, the Ed25519 signature of the zip
#    (key ~/.clipway/update-ed25519.pem, never in the repository), checked against the public key
#    the Mac app carries (Update.publicKey).
#
# Everything lands in build/release/<version>/: clipway-<v>.apk, clipway-mac-<v>.zip, their .sha256
# files, update.json and notes.md. Then tools/publish.sh puts them online.
#
# Environment: CLIPWAY_JAVA_HOME (default: the JDK of Android Studio; Homebrew's JDK breaks
# Gradle), ANDROID_HOME (default ~/Library/Android/sdk), CLIPWAY_BASE_URL (default https://clip.sidali.dev).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export JAVA_HOME="${CLIPWAY_JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BASE_URL="${CLIPWAY_BASE_URL:-https://clip.sidali.dev}"
KEYS="$HOME/.clipway"
UPDATE_KEY="$KEYS/update-ed25519.pem"
PINNED_CERT="0b48d179121e2af12f34f73f9b68dbb8966cd6495174a507959e309a88fea38e"

fail() { echo "Error: $*" >&2; exit 1; }
step() { echo "==> $*"; }

[ -x "$JAVA_HOME/bin/java" ] || fail "no JDK at $JAVA_HOME (set CLIPWAY_JAVA_HOME)"
BUILD_TOOLS="$(ls -d "$ANDROID_HOME"/build-tools/* 2>/dev/null | sort -V | tail -1)"
APKSIGNER="$BUILD_TOOLS/apksigner"
AAPT2="$BUILD_TOOLS/aapt2"
[ -x "$APKSIGNER" ] && [ -x "$AAPT2" ] || fail "apksigner or aapt2 not found in $ANDROID_HOME/build-tools"
[ -f "$KEYS/keystore.properties" ] || fail "$KEYS/keystore.properties missing: the APK would not be signed"
[ -f "$UPDATE_KEY" ] || fail "$UPDATE_KEY missing: the Mac zip cannot be signed"
[ "$(stat -f %Lp "$UPDATE_KEY")" = 600 ] || fail "$UPDATE_KEY must be readable by you only (chmod 600)"
command -v node > /dev/null || fail "node not found"
command -v xcodebuild > /dev/null || fail "xcodebuild not found"
[ -z "$(git -C "$ROOT" status --porcelain)" ] || echo "    warning: uncommitted changes, this build is not from a commit"

step "Versions"
VERSION="$(sed -nE 's/^[[:space:]]*versionName = "([^"]+)".*/\1/p' "$ROOT/android/app/build.gradle.kts")"
CODE="$(sed -nE 's/^[[:space:]]*versionCode = ([0-9]+).*/\1/p' "$ROOT/android/app/build.gradle.kts")"
MAC_VERSION="$(sed -nE 's/^[[:space:]]*MARKETING_VERSION: "([^"]+)".*/\1/p' "$ROOT/mac/project.yml" | head -1)"
MAC_BUILD="$(sed -nE 's/^[[:space:]]*CURRENT_PROJECT_VERSION: "([^"]+)".*/\1/p' "$ROOT/mac/project.yml" | head -1)"
RELAY_VERSION="$(node -p "require('$ROOT/relay/package.json').version")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "unexpected versionName: $VERSION"
[ "$VERSION" = "$MAC_VERSION" ] && [ "$VERSION" = "$RELAY_VERSION" ] || fail "versions differ: android $VERSION, mac $MAC_VERSION, relay $RELAY_VERSION"
[ "$CODE" = "$MAC_BUILD" ] || fail "Android versionCode $CODE and Mac CURRENT_PROJECT_VERSION $MAC_BUILD differ"
echo "    Clipway $VERSION ($CODE)"

OUT="$ROOT/build/release/$VERSION"
rm -rf "$OUT" && mkdir -p "$OUT"
awk -v v="$VERSION" '/^## /{inside = ($0 == "## " v || index($0, "## " v " ") == 1)} inside' "$ROOT/CHANGELOG.md" | tail -n +2 > "$OUT/notes.md"
grep -q '[^[:space:]]' "$OUT/notes.md" || fail "CHANGELOG.md has no section for $VERSION"

step "Tests: relay, ClipwayCore, Android"
(cd "$ROOT/relay" && npm test > "$OUT/relay-tests.log" 2>&1) || fail "relay tests failed (see $OUT/relay-tests.log)"
(cd "$ROOT/mac/ClipwayCore" && swift test > "$OUT/swift-tests.log" 2>&1) || fail "swift tests failed (see $OUT/swift-tests.log)"
(cd "$ROOT/android" && ./gradlew -q :app:testDebugUnitTest) || fail "Android tests failed"

step "Android: signed release APK"
(cd "$ROOT/android" && ./gradlew -q :app:assembleRelease)
RAW="$ROOT/android/app/build/outputs/apk/release/app-release.apk"
[ -f "$RAW" ] || fail "release APK not found: $RAW"
BADGING="$("$AAPT2" dump badging "$RAW" | sed -n '1p')"
[ "$(sed -E "s/.*package: name='([^']+)'.*/\1/" <<< "$BADGING")" = "dev.sidali.clipway" ] || fail "unexpected package"
[ "$(sed -E "s/.*versionCode='([0-9]+)'.*/\1/" <<< "$BADGING")" = "$CODE" ] || fail "APK versionCode differs"
[ "$(sed -E "s/.*versionName='([^']+)'.*/\1/" <<< "$BADGING")" = "$VERSION" ] || fail "APK versionName differs"
CERTS="$("$APKSIGNER" verify --print-certs "$RAW" 2> /dev/null)" || fail "invalid APK signature"
[ "$(grep -c '^Signer #[0-9]* certificate SHA-256 digest:' <<< "$CERTS" || true)" = 1 ] || fail "one signer expected"
CERT="$(sed -nE 's/^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$/\1/p' <<< "$CERTS")"
[ "$CERT" = "$PINNED_CERT" ] || fail "the APK is not signed with the release key of SECURITY.md ($CERT)"
APK="$OUT/clipway-$VERSION.apk"
cp "$RAW" "$APK"

step "Repository checks"
bash "$ROOT/.github/checks.sh"

step "Mac: Release build, signed ad hoc"
(cd "$ROOT/mac" && ./build.sh)
APP="$ROOT/mac/build/Clipway.app"
[ "$(defaults read "$APP/Contents/Info" CFBundleShortVersionString)" = "$VERSION" ] || fail "Mac version differs"
[ "$(defaults read "$APP/Contents/Info" CFBundleVersion)" = "$CODE" ] || fail "Mac build differs"
[ -d "$APP/Contents/XPCServices/ClipwayUpdater.xpc" ] || fail "the update installer is missing from the app"
codesign --verify --deep --strict "$APP" || fail "invalid code signature"
ZIP="$OUT/clipway-mac-$VERSION.zip"
(cd "$(dirname "$APP")" && ditto -c -k --keepParent Clipway.app "$ZIP")
CDHASH="$(codesign -dvvv "$APP" 2>&1 | sed -n 's/^CDHash=//p')"

step "update.json (zip signed with the update key)"
PUBLIC="$(sed -nE 's/.*public static let publicKey = "([^"]+)".*/\1/p' "$ROOT/mac/ClipwayCore/Sources/ClipwayCore/Update.swift")"
node "$ROOT/tools/update-manifest.mjs" --version "$VERSION" --base "$BASE_URL" --out "$OUT" --notes "$OUT/notes.md" \
  --apk "$APK" --version-code "$CODE" --cert-sha256 "$CERT" \
  --zip "$ZIP" --mac-build "$CODE" --min-macos 14.0 --key "$UPDATE_KEY" --public-key "$PUBLIC"
(cd "$OUT" && shasum -a 256 "clipway-$VERSION.apk" > "clipway-$VERSION.apk.sha256" \
  && shasum -a 256 "clipway-mac-$VERSION.zip" > "clipway-mac-$VERSION.zip.sha256")
rm -f "$OUT"/*-tests.log

echo
echo "Ready in $OUT:"
ls -1 "$OUT" | sed 's/^/    /'
echo "    APK certificate  $CERT"
echo "    Mac cdhash       $CDHASH"
echo "Next: tools/publish.sh $VERSION   (relay files and GitHub release)"
