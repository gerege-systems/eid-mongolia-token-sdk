#!/bin/bash
# Copies the OpenSC PKCS#11 module built by build_opensc.sh into the test app and signs it with the app's identity.
# READ-ONLY bundle — only:
#
#   Contents/Frameworks/opensc-pkcs11.so, libopensc.12.dylib
#   Contents/Resources/OpenSC/COPYING (LGPL-2.1), OPENSSL-LICENSE.txt
#
# No pkcs15-init or other OpenSC tools, no OpenSC profiles.
#
#   Xcode build phase (project.yml): input OPENSC_PREFIX (default $SRCROOT/.opensc/opensc-0.26.1); a missing tree
#   fails the build. By hand on a built app: bundle_opensc.sh <path/to/App.app> [identity]
#
# Install names are rewritten to @loader_path / @rpath so nothing points at the build machine.
set -euo pipefail

if [ $# -ge 1 ]; then
  APP="$1"; IDENTITY="${2:--}"
  PREFIX="${OPENSC_PREFIX:-$(cd "$(dirname "$0")/.." && pwd)/.opensc/opensc-0.26.1}"
else
  APP="$TARGET_BUILD_DIR/$WRAPPER_NAME"
  PREFIX="${OPENSC_PREFIX:-$SRCROOT/.opensc/opensc-0.26.1}"
  IDENTITY="-"
  if [ "${CODE_SIGNING_ALLOWED:-NO}" = "YES" ] && [ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]; then
    IDENTITY="$EXPANDED_CODE_SIGN_IDENTITY"
  fi
fi

for f in lib/opensc-pkcs11.so lib/libopensc.12.dylib share/doc/opensc/COPYING share/doc/opensc/OPENSSL-LICENSE.txt; do
  if [ ! -e "$PREFIX/$f" ]; then
    echo "error: OpenSC tree missing ($PREFIX/$f) — run macos/scripts/build_opensc.sh or set OPENSC_PREFIX"
    exit 1
  fi
done

FW="$APP/Contents/Frameworks"; RES="$APP/Contents/Resources/OpenSC"
mkdir -p "$FW" "$RES"
install -m 0755 "$PREFIX/lib/opensc-pkcs11.so" "$FW/opensc-pkcs11.so"
install -m 0755 "$PREFIX/lib/libopensc.12.dylib" "$FW/libopensc.12.dylib"
install -m 0644 "$PREFIX/share/doc/opensc/COPYING" "$RES/COPYING"
install -m 0644 "$PREFIX/share/doc/opensc/OPENSSL-LICENSE.txt" "$RES/OPENSSL-LICENSE.txt"
# Nothing of a provisioning toolset may ever end up in this bundle.
rm -rf "$APP/Contents/Helpers" "$RES/profiles"

old_lib="$(otool -D "$FW/libopensc.12.dylib" | tail -1)"
install_name_tool -id @rpath/libopensc.12.dylib "$FW/libopensc.12.dylib" 2>/dev/null
install_name_tool -change "$old_lib" @loader_path/libopensc.12.dylib "$FW/opensc-pkcs11.so" 2>/dev/null
strip -x "$FW/opensc-pkcs11.so" "$FW/libopensc.12.dylib" 2>/dev/null

for b in "$FW/opensc-pkcs11.so" "$FW/libopensc.12.dylib"; do
  deps="$(otool -L "$b" | grep -E '^[[:space:]]' | awk '{print $1}' | sort -u)"
  bad="$(echo "$deps" | grep -vE '^(/usr/lib/|/System/|@loader_path/|@executable_path/|@rpath/)' || true)"
  if [ -n "$bad" ]; then echo "error: $b links outside the bundle/system: $bad"; exit 1; fi
done

# Same identity as the app; hardened runtime only with a real (team) identity.
sign_flags=(--force --sign "$IDENTITY")
if [ "$IDENTITY" != "-" ]; then sign_flags+=(--options runtime --timestamp=none); fi
codesign "${sign_flags[@]}" "$FW/libopensc.12.dylib"
codesign "${sign_flags[@]}" "$FW/opensc-pkcs11.so"
echo "Bundled the OpenSC PKCS#11 module from $PREFIX into $APP (signed: $IDENTITY)"
