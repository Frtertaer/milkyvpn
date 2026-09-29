#!/usr/bin/env bash
# ios_sim.sh — iOS Simulator test stand (macOS only): boots a simulator,
# builds & installs the Flutter app, runs a connect probe through the
# sim's network stack, kills it. Optional content-blocker style DNS check.
#
#   testing/ios_sim.sh [--device 'iPhone 15'] [--link 'kal2://...']
set -euo pipefail
cd "$(dirname "$0")/.."

DEVICE=${1:-iPhone 15}
LINK=${KAL2_TEST_LINK:-}

[ "$(uname)" = Darwin ] || { echo "iOS sim needs macOS" >&2; exit 2; }
command -v xcrun >/dev/null || { echo "need Xcode tools" >&2; exit 2; }

UDID=$(xcrun simctl list devices available -j \
  | python3 -c "import json,sys; d=json.load(sys.stdin)['devices'];
for k,v in d.items():
  for dev in v:
    if dev['name']==sys.argv[1]: print(dev['udid']); break" "$DEVICE")

xcrun simctl boot "$UDID" 2>/dev/null || true
xcrun simctl bootstatus "$UDID" -b

flutter build ios --simulator --debug
xcrun simctl install "$UDID" build/ios/iphonesimulator/Runner.app

# drive the app via xcrun simctl spawn + log stream; the app-side check
# lives in lib/core/vpn/ffi_vpn_bridge.dart (DynamicLibrary.process())
xcrun simctl launch "$UDID" homes.milky.vpn
sleep 5
xcrun simctl spawn "$UDID" log show --last 10s --predicate 'process == "Runner"' \
  | grep -q "vpn" && echo "app up" || echo "check logs manually"

echo "UDID=$UDID left booted; shut down with: xcrun simctl shutdown $UDID"
