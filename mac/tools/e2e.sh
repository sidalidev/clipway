#!/usr/bin/env bash
# End-to-end test of the Mac app against a local relay, on this Mac.
#
#   mac/tools/e2e.sh [port]        (default 7711; a relay is started there if none answers)
#
# The test client relay/tools/client.mjs plays the phone. The Mac app is the Debug build in
# mac/build (./build.sh debug), driven by its debug-only launch arguments, which go through the
# same code as the screens. The Debug build is its own app (dev.sidali.clipway.debug): it never
# touches the key or the history of the installed Clipway. It checks, with the real pasteboard,
# Keychain, Downloads and relay:
#   1. Mac to phone: a text copied on the Mac arrives, then is acknowledged (Delivered).
#   2. Phone to Mac: a text arrives on the pasteboard (pbpaste), and is not sent back (echo).
#   3. Concealed content (password managers) is never sent; a text over 64 KB is not sent.
#   4. Images go directly, never through the relay: an image copied on the Mac reaches the phone
#      as PNG; an image from the phone lands on the pasteboard.
#   5. A 3 MB file from the phone lands in ~/Downloads/Clipway, same SHA-256, quarantined.
#   6. A 3 MB file from the Mac arrives whole; the relay never held more than a short offer.
#   7. A file offered from an address the Mac cannot reach: the Mac answers "unreachable".
#   8. Erased from the phone (close code 4001): the Mac stops, and stays stopped after a restart.
#   9. Erase everything: the relay forgets the chain, the Keychain items and the history are gone.
# The pasteboard is overwritten by the test (text only is restored at the end).
set -euo pipefail
export LANG=en_US.UTF-8
cd "$(dirname "$0")/.."
MAC="$PWD"
RELAY_DIR="$(cd ../relay && pwd)"
PORT="${1:-7711}"
RELAY="http://127.0.0.1:$PORT"
APP="$MAC/build/Build/Products/Debug/Clipway.app/Contents/MacOS/Clipway"
WORK="$(mktemp -d)"
PHONE_ID="0f1e2d3c4b5a69788796a5b4c3d2e1f0"
CLIENT=(node "$RELAY_DIR/tools/client.mjs")
pass=0
fail=0
ok() { echo "  ok    $*"; pass=$((pass + 1)); }
ko() { echo "  FAIL  $*"; fail=$((fail + 1)); }

[ -x "$APP" ] || { echo "Build the Debug app first: mac/build.sh debug"; exit 1; }
pgrep -f "Clipway.app/Contents/MacOS/Clipway" >/dev/null && { echo "Quit Clipway first (the installed app would also watch the pasteboard)."; exit 1; }

# Helper to read and write the pasteboard from Swift (types, PNG, concealed text).
cat > "$WORK/pb.swift" <<'EOF'
import AppKit
let pb = NSPasteboard.general
let a = CommandLine.arguments
switch a[1] {
case "save": try! (pb.string(forType: .string) ?? "").write(toFile: a[2], atomically: true, encoding: .utf8)
case "restore":
    pb.clearContents(); pb.setString(try! String(contentsOfFile: a[2], encoding: .utf8), forType: .string)
case "types": print((pb.types ?? []).map(\.rawValue).joined(separator: " "))
case "concealed":
    pb.clearContents(); pb.setString(a[2], forType: .string)
    pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
case "image":
    let color = a.count > 3 ? NSColor.systemTeal : NSColor.systemIndigo
    let img = NSImage(size: NSSize(width: 64, height: 64), flipped: false) { r in color.setFill(); r.fill(); return true }
    let tiff = img.tiffRepresentation!
    try! NSBitmapImageRep(data: tiff)!.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))
    pb.clearContents(); pb.setData(tiff, forType: .tiff)
default: break
}
EOF
swiftc -O "$WORK/pb.swift" -o "$WORK/pb" 2>/dev/null
"$WORK/pb" save "$WORK/clipboard.txt"

relay_pid=""
if ! curl -fs "$RELAY/health" >/dev/null 2>&1; then
  (cd "$RELAY_DIR" && PORT="$PORT" HOST=127.0.0.1 exec node server.js >"$WORK/relay.log" 2>&1) &
  relay_pid=$!
  for _ in $(seq 50); do curl -fs "$RELAY/health" >/dev/null 2>&1 && break; sleep 0.1; done
fi

app_pid=""
start_app() {
  "$APP" "$@" >>"$WORK/app.log" 2>&1 &
  app_pid=$!
}
stop_app() {
  [ -n "$app_pid" ] && kill "$app_pid" 2>/dev/null && wait "$app_pid" 2>/dev/null || true
  app_pid=""
}
cleanup() {
  stop_app
  [ "$fail" = 0 ] || cp "$WORK/app.log" "${TMPDIR:-/tmp}/clipway-e2e-app.log" 2>/dev/null || true
  [ -n "$relay_pid" ] && kill "$relay_pid" 2>/dev/null || true
  "$WORK/pb" restore "$WORK/clipboard.txt" 2>/dev/null || true
  rm -f "$HOME/Downloads/Clipway/e2e "*.pdf
  rmdir "$HOME/Downloads/Clipway" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

wait_log() { # wait_log PATTERN SECONDS
  for _ in $(seq $(($2 * 10))); do grep -q "$1" "$WORK/app.log" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}

KEY=$("${CLIENT[@]}" new --relay "$RELAY" --json | jq -r '.words | join(" ")')
PHONE=(--key "$KEY" --relay "$RELAY" --device "$PHONE_ID")
echo "Relay $RELAY, Mac app $(defaults read "$MAC/build/Build/Products/Debug/Clipway.app/Contents/Info" CFBundleShortVersionString)"

# Pair: the Mac joins the chain with the 12 words.
start_app --debug-relay "$RELAY" --debug-join "$KEY"
wait_log "link phoneOffline\\|link connected" 30 && ok "the Mac joined the chain and connected" || ko "the Mac did not connect"

# 1. Mac to phone, text
"${CLIENT[@]}" listen "${PHONE[@]}" --json --timeout 12 >"$WORK/listen1.json" 2>&1 &
listener=$!
sleep 1.5
printf 'From the Mac: café ☕ 👋' | pbcopy
sleep 2.5
kill "$listener" 2>/dev/null || true
wait "$listener" 2>/dev/null || true
grep '"type":"hello"' "$WORK/listen1.json" | grep -q '"kind":"mac"' && ok "hello with the Mac's name arrived" || ko "no hello"
[ "$(jq -r 'select(.type=="text") | .text' "$WORK/listen1.json")" = "From the Mac: café ☕ 👋" ] && ok "Mac to phone: text arrived" || ko "Mac to phone: text missing"
wait_log ": delivered" 5 && ok "Mac to phone: Delivered after the phone's ack" || ko "no Delivered"

# 2. Phone to Mac, text, and no echo
before=$(grep -c "pasteboard changed" "$WORK/app.log" || true)
"${CLIENT[@]}" send "${PHONE[@]}" --name "Test Pixel" --kind android --wait --timeout 10 "From the phone: naïve ✓" >/dev/null
sleep 1
[ "$(pbpaste)" = "From the phone: naïve ✓" ] && ok "phone to Mac: text on the pasteboard (pbpaste)" || ko "phone to Mac: pbpaste is '$(pbpaste)'"
sleep 1
after=$(grep -c "pasteboard changed" "$WORK/app.log" || true)
[ "$before" = "$after" ] && ok "the received text was not sent back (no echo)" || ko "echo: the Mac saw its own write"

# 3. Concealed content is never sent
"${CLIENT[@]}" listen "${PHONE[@]}" --json --timeout 4 >"$WORK/listen3.json" 2>&1 &
listener=$!
sleep 1.5
"$WORK/pb" concealed "a password from a password manager"
wait "$listener" 2>/dev/null || true
! grep -q "password manager" "$WORK/listen3.json" && grep -q "marked as secret" "$WORK/app.log" \
  && ok "concealed content was not sent" || ko "concealed content left the Mac"
head -c 70000 /dev/zero | tr '\0' 'x' | pbcopy
wait_log "Too long to send" 5 && ok "a text over 64 KB is not sent, and the menu says why" || ko "no note for a text over 64 KB"

# 4. Images both ways, directly (the phone needs to be online for the Mac to offer an image)
"${CLIENT[@]}" listen "${PHONE[@]}" --json --timeout 8 --out "$WORK/phone" --loopback >"$WORK/listen4.json" 2>&1 &
listener=$!
sleep 1.5
"$WORK/pb" image "$WORK/square.png"
for _ in $(seq 60); do grep -q '"type":"image"' "$WORK/listen4.json" 2>/dev/null && break; sleep 0.1; done
kill "$listener" 2>/dev/null || true
wait "$listener" 2>/dev/null || true
saved=$(jq -r 'select(.type=="image") | .saved' "$WORK/listen4.json" | head -1)
[ -n "$saved" ] && [ "$(head -c 8 "$saved" | xxd -p)" = "89504e470d0a1a0a" ] && grep -q '"direct":true' "$WORK/listen4.json" \
  && ok "Mac to phone: image arrived directly as PNG" || ko "Mac to phone: image missing"
wait_log "sent item .*: delivered" 5 && ok "Mac to phone: Delivered once the phone fetched it" || ko "no Delivered for the image"
"$WORK/pb" image "$WORK/phone.png" teal
"${CLIENT[@]}" send "${PHONE[@]}" --name "Test Pixel" --kind android --timeout 15 --file "$WORK/phone.png" --type image --mime image/png --loopback >/dev/null
sleep 0.3
types=$("$WORK/pb" types)
[[ "$types" == *public.png* && "$types" == *public.tiff* ]] && ok "phone to Mac: image on the pasteboard (PNG and TIFF)" \
  || ko "phone to Mac: no image on the pasteboard (types: $types)"

# 5. A 3 MB file from the phone, directly
head -c 3000000 /dev/urandom >"$WORK/e2e report.pdf"
out=$("${CLIENT[@]}" send "${PHONE[@]}" --name "Test Pixel" --kind android --timeout 20 --file "$WORK/e2e report.pdf" --type file --mime application/pdf --loopback || true)
[[ "$out" == *"Fetched directly"* ]] && ok "phone to Mac: 3 MB file fetched directly by the Mac" || ko "phone to Mac: file not fetched ($out)"
"${CLIENT[@]}" send "${PHONE[@]}" --name "Test Pixel" --kind android --timeout 20 --file "$WORK/e2e report.pdf" --type file --mime application/pdf --loopback >/dev/null
sleep 1
want=$(shasum -a 256 <"$WORK/e2e report.pdf" | cut -d' ' -f1)
got=$(shasum -a 256 <"$HOME/Downloads/Clipway/e2e report.pdf" 2>/dev/null | cut -d' ' -f1 || true)
[ "$want" = "$got" ] && ok "the file is in ~/Downloads/Clipway, same SHA-256" || ko "file missing or different"
[ -f "$HOME/Downloads/Clipway/e2e report 2.pdf" ] && ok "a second file with the same name became 'e2e report 2.pdf'" || ko "no collision rename"
xattr -p com.apple.quarantine "$HOME/Downloads/Clipway/e2e report.pdf" >/dev/null 2>&1 && ok "received file is quarantined" || ko "no quarantine attribute"

# 6. A 3 MB file from the Mac (restart the app: it keeps its key)
stop_app
"${CLIENT[@]}" listen "${PHONE[@]}" --json --timeout 15 --out "$WORK/phone" --loopback >"$WORK/listen6.json" 2>&1 &
listener=$!
start_app --debug-send-file 3000000 --debug-menu
for _ in $(seq 150); do grep -q '"name":"pattern.bin"' "$WORK/listen6.json" 2>/dev/null && break; sleep 0.1; done
kill "$listener" 2>/dev/null || true
wait "$listener" 2>/dev/null || true
file=$(jq -r 'select(.name=="pattern.bin") | .saved' "$WORK/listen6.json" | head -1)
expected=$(node -e 'const b=Buffer.alloc(3000000);for(let i=0;i<b.length;i++)b[i]=i%251;console.log(require("crypto").createHash("sha256").update(b).digest("hex"))')
[ -n "$file" ] && [ "$(shasum -a 256 <"$file" | cut -d' ' -f1)" = "$expected" ] && ok "Mac to phone: 3 MB file arrived whole, directly" || ko "Mac to phone: file missing or different"
[ "$(curl -fs "$RELAY/health" | jq .bytes)" -lt 10000 ] && ok "the relay held only short offers, never the file" || ko "the relay holds more than offers"

# 7. A file offered at an address the Mac cannot reach (no loopback, a private address nobody answers)
out=$("${CLIENT[@]}" send "${PHONE[@]}" --name "Test Pixel" --kind android --timeout 30 --json --file "$WORK/e2e report.pdf" --type file --hosts 10.255.255.1 || true)
[[ "$out" == *'"result":"unreachable"'* ]] && ok "unreachable: the Mac answered through the relay, the phone stopped" || ko "no unreachable reply ($out)"
wait_log "Couldn't receive" 5 && ok "the Mac says it could not receive, and why" || ko "no note on the Mac"
grep -q "link phoneOffline\|link connected" "$WORK/app.log" && ok "after a restart the Mac reconnects with the key from the Keychain" || ko "no reconnection"
for _ in $(seq 50); do grep -q "menu: Quit Clipway" "$WORK/app.log" && break; sleep 0.1; done
grep -q "menu: From the phone: naïve ✓" "$WORK/app.log" && grep -q "menu: Send a file…" "$WORK/app.log" \
  && ok "the menu lists the history, read back encrypted after the restart" || ko "the menu or the history is wrong"

# 8. The phone erases the chain on the relay: the Mac stops at once and after a restart.
"${CLIENT[@]}" erase "${PHONE[@]}" >/dev/null
wait_log "link erasedElsewhere" 10 && ok "erased from the phone: the Mac stopped (close code 4001)" || ko "the Mac did not see the erase"
stop_app
menus=$(grep -c "menu: Quit Clipway" "$WORK/app.log" || true)
start_app --debug-menu
for _ in $(seq 80); do [ "$(grep -c "menu: Quit Clipway" "$WORK/app.log" || true)" -gt "$menus" ] && break; sleep 0.1; done
[ "$(curl -fs "$RELAY/health" | jq .connections)" = 0 ] && grep -q "menu: This key was erased on another device" "$WORK/app.log" \
  && ok "after a restart the Mac stays unpaired and does not reconnect" || ko "the Mac came back on an erased chain"

# 9. Erase everything
stop_app
"${CLIENT[@]}" send "${PHONE[@]}" --name "Test Pixel" --kind android "waiting for the Mac" >/dev/null
items_before=$(curl -fs "$RELAY/health" | jq .items)
start_app --debug-erase
for _ in $(seq 100); do kill -0 "$app_pid" 2>/dev/null || break; sleep 0.1; done
app_pid=""
grep -q "erased, relay confirmed: true" "$WORK/app.log" && ok "Erase everything: the relay confirmed (DELETE /chain, 204)" || ko "the relay did not confirm"
[ "$(curl -fs "$RELAY/health" | jq .items)" -lt "$items_before" ] && ok "the relay dropped the chain's waiting items" || ko "items still on the relay"
security find-generic-password -s dev.sidali.clipway.debug -a chain >/dev/null 2>&1 && ko "the key is still in the Keychain" || ok "the key is gone from the Keychain"
security find-generic-password -s dev.sidali.clipway.debug -a history-key >/dev/null 2>&1 && ko "the history key is still in the Keychain" || ok "the history key is gone from the Keychain"
[ ! -e "$HOME/Library/Containers/dev.sidali.clipway.debug/Data/Library/Application Support/Clipway/history.bin" ] && ok "history.bin is gone" || ko "history.bin is still there"
security find-generic-password -s dev.sidali.clipway -a chain >/dev/null 2>&1 && ok "the installed Clipway's key was not touched" || echo "  (no installed Clipway key on this Mac)"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
