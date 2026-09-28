#!/usr/bin/env bash
# build-cshared.sh — build libmilky (unified C ABI, see include/milky.h)
# for a target GOOS/GOARCH.
#
#   ./scripts/build-cshared.sh                      # host platform
#   GOOS=windows GOARCH=amd64 ./scripts/build-cshared.sh
#   GOOS=android GOARCH=arm64 ANDROID_NDK_HOME=... ./scripts/build-cshared.sh
#
# c-shared requires the matching C toolchain:
#   linux   amd64   host gcc            arm64: CC=aarch64-linux-gnu-gcc
#   windows amd64   CC=x86_64-w64-mingw32-gcc
#   darwin  */ios   run on macOS (no Linux→Darwin cross); for iOS build both
#                   -tags ios slices then: xcodebuild -create-xcframework
#   android         ANDROID_NDK_HOME (or ~/android-sdk/ndk/*) llvm clang
set -euo pipefail
cd "$(dirname "$0")/.."

GOOS=${GOOS:-$(go env GOHOSTOS)}
GOARCH=${GOARCH:-$(go env GOHOSTARCH)}
API=${ANDROID_API:-34}
OUT=${OUT:-dist/native}
PKG=${PKG:-./cmd/milkynative}

CC_BIN=""
case "$GOOS" in
  android)
    ndk=${ANDROID_NDK_HOME:-}
    if [ -z "$ndk" ]; then
      ndk=$(ls -d "$HOME"/android-sdk/ndk/* 2>/dev/null | sort -V | tail -1 || true)
    fi
    [ -n "$ndk" ] || { echo "ANDROID_NDK_HOME not set and no NDK under ~/android-sdk/ndk" >&2; exit 1; }
    host=$(ls "$ndk/toolchains/llvm/prebuilt" | head -1)
    case "$GOARCH" in
      arm64)   CC_BIN="$ndk/toolchains/llvm/prebuilt/$host/bin/aarch64-linux-android${API}-clang"; lib=libmilky.so ;;
      arm)     CC_BIN="$ndk/toolchains/llvm/prebuilt/$host/bin/armv7a-linux-androideabi${API}-clang"; lib=libmilky.so ;;
      amd64)   CC_BIN="$ndk/toolchains/llvm/prebuilt/$host/bin/x86_64-linux-android${API}-clang"; lib=libmilky.so ;;
      386)     CC_BIN="$ndk/toolchains/llvm/prebuilt/$host/bin/i686-linux-android${API}-clang"; lib=libmilky.so ;;
      *) echo "unsupported android arch $GOARCH" >&2; exit 1 ;;
    esac
    ;;
  windows)
    lib=milky.dll
    CC_BIN=${CC:-x86_64-w64-mingw32-gcc}
    ;;
  darwin)
    lib=libmilky.dylib
    ;;
  ios)
    lib=libmilky.dylib
    ;;
  linux|freebsd)
    lib=libmilky.so
    ;;
  *) echo "unsupported GOOS $GOOS" >&2; exit 1 ;;
esac

mkdir -p "$OUT"
out="$OUT/${lib%.*}-${GOOS}-${GOARCH}.${lib##*.}"
[ "$GOOS" = "windows" ] && out="$OUT/milky-${GOOS}-${GOARCH}.dll"

echo ">> $GOOS/$GOARCH -> $out (CC=${CC_BIN:-default})"
CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH CC="$CC_BIN" \
  go build -trimpath -buildmode=c-shared -o "$out" "$PKG"
echo "built $out"
