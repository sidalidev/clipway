#!/usr/bin/env bash
# Renders every window of the Mac app, light and dark, with sample data (no Keychain, no network),
# into docs/screenshots/mac. Uses the Debug build's --snapshots mode; the sandbox lets the app write
# only in its container, so the files are copied from there.
set -euo pipefail
cd "$(dirname "$0")/.."
./build.sh debug >/dev/null
container="$HOME/Library/Containers/dev.sidali.clipway.debug/Data/tmp/snapshots"
rm -rf "$container"
build/Build/Products/Debug/Clipway.app/Contents/MacOS/Clipway --snapshots "$container" >/dev/null
out=../docs/screenshots/mac
mkdir -p "$out"
rm -f "$out"/*.png
cp "$container"/*.png "$out"/
echo "$(ls "$out" | wc -l | tr -d ' ') screenshots in docs/screenshots/mac"
