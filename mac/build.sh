#!/usr/bin/env bash
# Builds Clipway.app into mac/build/, signed ad hoc, ready to open with a double click.
#
#   ./build.sh          Release: the relay must use https://
#   ./build.sh debug    Debug: also accepts a relay on this Mac (http://127.0.0.1:7710) and has
#                       the launch arguments used by tools/e2e.sh
#
# Needs Xcode (xcodebuild). XcodeGen is only needed after editing project.yml.
set -euo pipefail
cd "$(dirname "$0")"
config=Release
[ "${1:-}" = "debug" ] && config=Debug

if command -v xcodegen >/dev/null 2>&1 && [ project.yml -nt Clipway.xcodeproj/project.pbxproj ]; then
  xcodegen generate --quiet
fi

xcodebuild -project Clipway.xcodeproj -scheme Clipway -configuration "$config" -derivedDataPath build \
  -destination "generic/platform=macOS" \
  CODE_SIGN_IDENTITY=- -quiet build

rm -rf build/Clipway.app
ditto "build/Build/Products/$config/Clipway.app" build/Clipway.app
codesign --verify --strict build/Clipway.app
cdhash=$(codesign -dvvv build/Clipway.app 2>&1 | sed -n 's/^CDHash=//p')
version=$(defaults read "$PWD/build/Clipway.app/Contents/Info" CFBundleShortVersionString)
echo "build/Clipway.app: Clipway $version ($config), ad hoc signature, code directory hash $cdhash"
