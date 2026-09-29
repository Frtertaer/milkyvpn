#!/usr/bin/env bash
# CI entrypoint for the emulator-matrix workflow: gated connect, then the full
# scenario battery — every scenario gates the job. Env: KAL2_TEST_LINK
# (required), SERIAL (default emulator-5554).
set -uo pipefail
cd "$(dirname "$0")/.."

SERIAL=${SERIAL:-emulator-5554}
APK=${APK:-build/app/outputs/flutter-apk/app-debug.apk}
LINK=${KAL2_TEST_LINK:?KAL2_TEST_LINK must be set}

# Dump device logs into ci-artifacts/ while the emulator is still alive — by the
# time the workflow's post steps run, the emulator is already killed.
ART_DIR=${GITHUB_WORKSPACE:-$PWD}/ci-artifacts
mkdir -p "$ART_DIR"
# Stream the device log for the whole job — the ring buffer wraps on noisy
# APIs and drops MilkyVPN lines before post-mortem collection, so nothing in
# this pipeline may rely on `logcat -d` alone. scenarios.sh reads this file
# via mark_log/wait_state byte offsets.
LOGFILE=$ART_DIR/logcat-full.txt
export LOGFILE
adb -s "$SERIAL" logcat -c 2>/dev/null || true
adb -s "$SERIAL" logcat -v threadtime > "$LOGFILE" 2>/dev/null &
LOGPID=$!

collect_logs() {
  kill "$LOGPID" 2>/dev/null || true
  adb -s "$SERIAL" logcat -d > "$ART_DIR/logcat.txt" 2>/dev/null || true
  adb -s "$SERIAL" shell 'run-as vpn.milky.app.debug cat /data/data/vpn.milky.app.debug/files/crashes.jsonl 2>/dev/null' \
    > "$ART_DIR/app-crashes.jsonl" || true
}
trap collect_logs EXIT

# adbd answers long before the system is ready — installing into a half-booted
# device is a known race. Wait for real boot + the package manager first.
for _ in $(seq 1 40); do
  [ "$(adb -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] \
    && adb -s "$SERIAL" shell pm list packages >/dev/null 2>&1 && break
  sleep 5
done
adb -s "$SERIAL" wait-for-device
sleep 5

adb -s "$SERIAL" install -r "$APK" >/dev/null && echo "installed $APK"

./testing/scenarios.sh --apk "$APK" --serial "$SERIAL" --scenario connect \
  || { echo "connect scenario FAILED"; exit 1; }

for s in wifi_lte net_loss dns_change dns_leak battery_opt fgs_doze on_revoke; do
  ./testing/scenarios.sh --serial "$SERIAL" --scenario "$s" \
    || { echo "scenario $s FAILED"; exit 1; }
done
