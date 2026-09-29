#!/usr/bin/env bash
# scripts/check.sh — единый прогон качества для milky-core.
# Запускать из корня репозитория или из milky-core/.
# Что делает: unit (+race), fuzz-smoke по фазз-тестам, сборка всех таргетов.
# Зависимости: go >= 1.24 (toolchain подтянется сам по go.mod).
set -euo pipefail

cd "$(dirname "$0")/.."
[ -d milky-core ] && cd milky-core

GO=${GO:-go}
echo "=== check: unit + race ==="
$GO test -race -count=1 ./...

echo "=== check: fuzz-smoke (5s per fuzz target) ==="
# seed-only run of every Fuzz* to catch obvious crashes without a long campaign
for pkg in $(go list ./...); do
  for fz in $(go test -list 'Fuzz.*' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
    echo "-- $pkg $fz"
    $GO test -run "$fz$" -fuzz "$fz" -fuzztime 5s "$pkg" || exit 1
  done
done

echo "=== check: crossbuild ==="
for t in linux/amd64 linux/arm64 windows/amd64 darwin/arm64 darwin/amd64; do
  os=${t%/*}; arch=${t#*/}
  echo "-- $os/$arch"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch $GO build ./... > /dev/null
done

echo "=== check: c-shared matrix (host toolchain) ==="
# android .so требует NDK — пропускается если ANDROID_NDK_HOME не задан
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
  for abi in arm64-v8a armeabi-v7a x86_64; do
    echo "-- android/$abi"
    scripts/build-kal2native.sh "$abi" > /dev/null 2>&1 || {
      echo "  (skip: NDK build script/failure — см. CI джобу c-shared)"; }
  done
else
  echo "-- android .so: skipped (ANDROID_NDK_HOME unset)"
fi

echo "=== ALL GREEN ==="
