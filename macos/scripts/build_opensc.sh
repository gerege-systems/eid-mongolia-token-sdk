#!/bin/bash
# Builds the OpenSC 0.26.1 PKCS#11 module that bundle_opensc.sh copies into the test app.
#
#   scripts/build_opensc.sh [out-dir]      # default: macos/.opensc/opensc-0.26.1 (gitignored)
#
# Output (module only — no pkcs15-init or other tools, no profiles):
#   <out>/lib/opensc-pkcs11.so, <out>/lib/libopensc.12.dylib, <out>/share/doc/opensc/{COPYING,OPENSSL-LICENSE.txt}
# Universal (ARCHS, default "arm64 x86_64"), minimum macOS = MACOSX_DEPLOYMENT_TARGET (default 14.0). OpenSSL
# (libcrypto) is linked statically, so the module needs nothing outside the system. Unmodified upstream sources,
# pinned by SHA-256.
#
# Why 0.26.1: the OpenSC version the eID tokens are formatted and tested with.
set -euo pipefail

OPENSC_VER=0.26.1
OPENSC_SHA=f16291a031d86e570394762e9f35eaf2fcbc2337a49910f3feae42d54e1688cb
OPENSSL_VER=3.5.9
OPENSSL_SHA=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

MACOS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$MACOS_DIR/.opensc/opensc-$OPENSC_VER}"
ARCHS="${ARCHS:-arm64 x86_64}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
# Baked-in default paths point here; the apps always override them via OPENSC_CONF.
PREFIX=/opt/eid-opensc
JOBS="$(sysctl -n hw.ncpu)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/eid-opensc-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fetch() { # url sha256 dest
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | shasum -a 256 -c - >/dev/null
}
fetch "https://github.com/OpenSC/OpenSC/releases/download/$OPENSC_VER/opensc-$OPENSC_VER.tar.gz" \
  "$OPENSC_SHA" "$WORK/opensc.tgz"
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VER/openssl-$OPENSSL_VER.tar.gz" \
  "$OPENSSL_SHA" "$WORK/openssl.tgz"

host_arch="$(uname -m)"
for arch in $ARCHS; do
  echo "== $arch"
  A="$WORK/$arch"; mkdir -p "$A"
  tar xzf "$WORK/openssl.tgz" -C "$A"
  tar xzf "$WORK/opensc.tgz" -C "$A"
  ossl="$A/ossl"
  (cd "$A/openssl-$OPENSSL_VER" &&
   ./Configure "darwin64-$arch-cc" no-shared no-tests no-docs no-apps no-module \
     --prefix="$ossl" --libdir=lib "-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" >/dev/null &&
   make -j"$JOBS" build_libs >/dev/null && make install_dev >/dev/null)

  host_flag=()
  [ "$arch" != "$host_arch" ] && host_flag=(--host="$arch-apple-darwin")
  (cd "$A/opensc-$OPENSC_VER" &&
   ./configure ${host_flag[@]+"${host_flag[@]}"} --prefix="$PREFIX" \
     --disable-doc --disable-notify --disable-tests --disable-static --disable-readline \
     CC="clang -arch $arch" \
     CFLAGS="-O2 -Wno-error -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" \
     LDFLAGS="-Wl,-headerpad_max_install_names -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" \
     OPENSSL_CFLAGS="-I$ossl/include" OPENSSL_LIBS="$ossl/lib/libcrypto.a" >/dev/null &&
   make -j"$JOBS" CFLAGS="-O2 -Wno-error -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" >/dev/null &&
   make install DESTDIR="$A/stage" >/dev/null)
done

rm -rf "$OUT"
mkdir -p "$OUT/lib" "$OUT/share/doc/opensc"
first="$(echo "$ARCHS" | awk '{print $1}')"
for f in lib/opensc-pkcs11.so lib/libopensc.12.dylib; do
  inputs=()
  for arch in $ARCHS; do inputs+=("$WORK/$arch/stage$PREFIX/$f"); done
  lipo -create "${inputs[@]}" -output "$OUT/$f"
done
cp "$WORK/$first/opensc-$OPENSC_VER/COPYING" "$OUT/share/doc/opensc/COPYING"
cp "$WORK/$first/openssl-$OPENSSL_VER/LICENSE.txt" "$OUT/share/doc/opensc/OPENSSL-LICENSE.txt"
echo "OpenSC $OPENSC_VER PKCS#11 module (OpenSSL $OPENSSL_VER static, $ARCHS, macOS >= $MACOSX_DEPLOYMENT_TARGET) -> $OUT"
