#!/usr/bin/env bash
# Publishes a release prepared by tools/release.sh (docs/UPDATES.md):
#
#   tools/publish.sh <version>
#
# 1. Copies the APK and the zip, then update.json, to $CLIPWAY_VPS:$CLIPWAY_RELEASES_DIR (the relay
#    serves that folder read only: /update.json and /download/<file>). The files go first and
#    update.json last, each put in place by a rename: the manifest never points to a missing file.
#    A file already published under the same name must not change (apps check its checksum).
# 2. Checks online that update.json and both files are served with the right checksums.
# 3. GitHub release v<version> with the APK, the zip, their .sha256 files and update.json, notes
#    from CHANGELOG.md. Obtainium follows these releases, as before.
#
# Environment, required: CLIPWAY_VPS (SSH target of the relay's server, e.g. user@example.org) and
# CLIPWAY_RELEASES_DIR (the host folder mounted on /releases, CLIPWAY_RELEASES_HOST_DIR in
# deploy/docker-compose.yml). Optional: CLIPWAY_BASE_URL (https://clip.sidali.dev), CLIPWAY_GITHUB_REPO
# (sidalidev/clipway).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:?usage: tools/publish.sh <version>}"
OUT="$ROOT/build/release/$VERSION"
BASE_URL="${CLIPWAY_BASE_URL:-https://clip.sidali.dev}"
REPO="${CLIPWAY_GITHUB_REPO:-sidalidev/clipway}"
VPS="${CLIPWAY_VPS:?set CLIPWAY_VPS, the SSH target of the relay server}"
DIR="${CLIPWAY_RELEASES_DIR:?set CLIPWAY_RELEASES_DIR, the folder of published versions on that server}"
APK="clipway-$VERSION.apk"
ZIP="clipway-mac-$VERSION.zip"

fail() { echo "Error: $*" >&2; exit 1; }
for f in "$APK" "$ZIP" "$APK.sha256" "$ZIP.sha256" update.json notes.md; do
  [ -f "$OUT/$f" ] || fail "$OUT/$f missing: run tools/release.sh first"
done
command -v gh > /dev/null || fail "gh not found"
[ -z "$(git -C "$ROOT" status --porcelain)" ] || fail "uncommitted changes: commit and push before publishing"
(cd "$OUT" && shasum -a 256 -c "$APK.sha256" "$ZIP.sha256" > /dev/null) || fail "the files changed since tools/release.sh"
APK_SHA="$(cut -d' ' -f1 "$OUT/$APK.sha256")"
ZIP_SHA="$(cut -d' ' -f1 "$OUT/$ZIP.sha256")"

echo "==> Server $VPS:$DIR"
for pair in "$APK:$APK_SHA" "$ZIP:$ZIP_SHA"; do
  name="${pair%%:*}" sha="${pair##*:}"
  there="$(ssh "$VPS" "mkdir -p '$DIR' && if [ -f '$DIR/$name' ]; then sha256sum '$DIR/$name' | cut -d' ' -f1; fi")"
  [ -z "$there" ] || [ "$there" = "$sha" ] || fail "$name is already published with another checksum: bump the version"
done
scp -q "$OUT/$APK" "$VPS:$DIR/$APK.tmp"
scp -q "$OUT/$ZIP" "$VPS:$DIR/$ZIP.tmp"
scp -q "$OUT/update.json" "$VPS:$DIR/update.json.tmp"
ssh "$VPS" "cd '$DIR' && chmod 644 '$APK.tmp' '$ZIP.tmp' update.json.tmp && mv -f '$APK.tmp' '$APK' && mv -f '$ZIP.tmp' '$ZIP' && mv -f update.json.tmp update.json"

echo "==> Online check"
curl -fsS -H 'Cache-Control: no-cache' "$BASE_URL/update.json" | cmp -s - "$OUT/update.json" \
  || echo "    update.json not served yet (5 min cache, or the relay lacks CLIPWAY_RELEASES_DIR)"
[ "$(curl -fsS "$BASE_URL/download/$APK" | shasum -a 256 | cut -d' ' -f1)" = "$APK_SHA" ] || fail "the APK served online has another checksum"
[ "$(curl -fsS "$BASE_URL/download/$ZIP" | shasum -a 256 | cut -d' ' -f1)" = "$ZIP_SHA" ] || fail "the zip served online has another checksum"
echo "    $BASE_URL/update.json, /download/$APK and /download/$ZIP: OK"

echo "==> GitHub release v$VERSION"
TITLE="Clipway $VERSION"
if gh release view "v$VERSION" -R "$REPO" > /dev/null 2>&1; then
  gh release upload "v$VERSION" -R "$REPO" --clobber "$OUT/$APK" "$OUT/$APK.sha256" "$OUT/$ZIP" "$OUT/$ZIP.sha256" "$OUT/update.json"
else
  gh release create "v$VERSION" -R "$REPO" --target main --title "$TITLE" --notes-file "$OUT/notes.md" \
    "$OUT/$APK" "$OUT/$APK.sha256" "$OUT/$ZIP" "$OUT/$ZIP.sha256" "$OUT/update.json"
fi
gh release view "v$VERSION" -R "$REPO" --json url -q .url
