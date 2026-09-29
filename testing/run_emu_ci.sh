#!/usr/bin/env bash
# CI entrypoint for the emulator-matrix workflow: gated connect, then best-effort
# network scenarios. Env: KAL2_TEST_LINK (required), SERIAL (default emulator-5554).
set -uo pipefail
cd "$(dirname "$0")/.."

SERIAL=${SERIAL:-emulator-5554}
APK=${APK:-build/app/outputs/flutter-apk/app-debug.apk}
LINK=${KAL2_TEST_LINK:?KAL2_TEST_LINK must be set}

adb -s "$SERIAL" install -r "$APK" >/dev/null && echo "installed $APK"

./testing/scenarios.sh --apk "$APK" --serial "$SERIAL" --scenario connect \
  || { echo "connect scenario FAILED"; exit 1; }

for s in wifi_lte net_loss dns_change dns_leak fgs_doze; do
  ./testing/scenarios.sh --serial "$SERIAL" --scenario "$s" || true
done
