#!/usr/bin/env bash
# Checks the Mac's side of Pair nearby without Bluetooth: the Debug build plays the phone (the
# central) against the Mac's session state machine from docs/VECTORS.json, request by request
# (Clipway --debug-nearby-vectors). Prints each check; exit code 0 when all pass.
set -euo pipefail
cd "$(dirname "$0")/.."
./build.sh debug >/dev/null
# The sandbox does not let the app open files in the repository: the vectors go on the standard input.
build/Build/Products/Debug/Clipway.app/Contents/MacOS/Clipway --debug-nearby-vectors < ../docs/VECTORS.json
