#!/usr/bin/env bash
# Build a signed + notarized Spark.app / DMG from the Tauri UI (gui-tauri), embedding the
# org.getlantern.spark.tunnel system extension — the NE Model A product (ADR 0008). The Tauri
# analogue of build-gui-dmg.sh (which does the same for the retired Flutter GUI).
#
# Env knobs:
#   SIGN_IDENTITY   Developer ID Application identity (auto-detected from the keychain otherwise)
#   APP_PROFILE     path to the "Spark macOS App" .provisionprofile (auto-located from the Xcode store)
#   NOTARY_PROFILE  notarytool keychain profile, OR
#   AC_USERNAME + AC_PASSWORD  Apple-ID + app-specific password
#   SKIP_NOTARIZE=1 build signed-but-not-notarized (fast local iteration)
#   OUTPUT_DIR      where Spark.app/Spark.dmg land (default: dist/)
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
APPLE_DIR="$REPO_ROOT/platforms/apple"
GUI="$REPO_ROOT/gui-tauri"
TEAM_ID="ACZRKC3LQ9"
SYSEXT_ID="org.getlantern.spark.tunnel"
VOLNAME="Spark"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ARCHIVE="$WORK/SparkApp.xcarchive"
OUT="${OUTPUT_DIR:-$REPO_ROOT/dist}"; mkdir -p "$OUT"
APP="$OUT/Spark.app"
DMG="$OUT/Spark.dmg"
ENT="$GUI/src-tauri/Release.entitlements"
SKIP_NOTARIZE="${SKIP_NOTARIZE:-0}"

log() { echo "[build-tauri-dmg] $*" >&2; }

SIGN_IDENTITY="${SIGN_IDENTITY:-$(security find-identity -v -p codesigning \
  | awk -F'"' '/Developer ID Application/{print $2; exit}')}"
[[ -n "$SIGN_IDENTITY" ]] || { echo "no Developer ID Application identity in the keychain" >&2; exit 1; }

NOTARY_ARGS=()
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
  elif [[ -n "${AC_USERNAME:-}" && -n "${AC_PASSWORD:-}" ]]; then
    NOTARY_ARGS=(--apple-id "$AC_USERNAME" --password "$AC_PASSWORD" --team-id "$TEAM_ID")
  else
    echo "no notary creds: set NOTARY_PROFILE, or AC_USERNAME+AC_PASSWORD, or SKIP_NOTARIZE=1" >&2
    exit 1
  fi
fi

# Locate the controlling-app provisioning profile (org.getlantern.spark) in the Xcode store.
locate_profile() {
  local d="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
  local f
  for f in "$d"/*.provisionprofile; do
    [[ -f "$f" ]] || continue
    if security cms -D -i "$f" 2>/dev/null | plutil -p - 2>/dev/null \
         | grep -q "$TEAM_ID.org.getlantern.spark\""; then echo "$f"; return 0; fi
  done
  return 1
}
APP_PROFILE="${APP_PROFILE:-$(locate_profile || true)}"
[[ -f "$APP_PROFILE" ]] || { echo "no 'Spark macOS App' provisioning profile found (set APP_PROFILE)" >&2; exit 1; }

# 1. Signed system extension (platforms/apple archive) + extract it.
log "building the system extension (platforms/apple archive)"
"$APPLE_DIR/build-xcframework.sh"
( cd "$APPLE_DIR" && xcodegen generate )
xcodebuild -project "$APPLE_DIR/Spark.xcodeproj" -scheme SparkApp -configuration Release \
  -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" \
  ARCHS=arm64 CURRENT_PROJECT_VERSION="$(date +%s)" archive
SYSEXT_SRC="$ARCHIVE/Products/Applications/SparkApp.app/Contents/Library/SystemExtensions/$SYSEXT_ID.systemextension"
[[ -d "$SYSEXT_SRC" ]] || { echo "system extension not found in archive: $SYSEXT_SRC" >&2; exit 1; }

# 2. The Tauri controlling app (config resolves at runtime via config.rs: config.toml → SPARK_CONFIG
#    → SPARK_PROXY → direct, so there's nothing to bake here).
log "building the Tauri app"
( cd "$GUI" && APPLE_SIGNING_IDENTITY="$SIGN_IDENTITY" npm run tauri build )
TAURI_APP="$GUI/src-tauri/target/release/bundle/macos/Spark.app"
[[ -d "$TAURI_APP" ]] || { echo "tauri build did not produce $TAURI_APP" >&2; exit 1; }
rm -rf "$APP"; cp -R "$TAURI_APP" "$APP"

# 3. Embed the system extension + the app provisioning profile.
log "embedding $SYSEXT_ID.systemextension + embedded.provisionprofile"
mkdir -p "$APP/Contents/Library/SystemExtensions"
cp -R "$SYSEXT_SRC" "$APP/Contents/Library/SystemExtensions/"
cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"

# 4. Re-sign the top level (no --deep): seal the sysext into CodeResources, apply Release.entitlements
#    (NE + system-extension.install + app group) + hardened runtime. The embedded sysext keeps its
#    own archive signature.
log "re-signing the app bundle"
codesign --force --options runtime --timestamp --entitlements "$ENT" --sign "$SIGN_IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

# 5. Notarize + staple the app.
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing the app (notarytool submit --wait)"
  ditto -c -k --keepParent "$APP" "$WORK/app.zip"
  xcrun notarytool submit "$WORK/app.zip" "${NOTARY_ARGS[@]}" --wait
  xcrun stapler staple "$APP"
fi

# 6. Build the DMG (drag-to-/Applications), sign it.
log "building the DMG"
STAGE="$WORK/stage"; mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG"

# 7. Notarize + staple the DMG.
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing the DMG (notarytool submit --wait)"
  xcrun notarytool submit "$DMG" "${NOTARY_ARGS[@]}" --wait
  xcrun stapler staple "$DMG"
fi

# 8. Verify.
log "verifying"
codesign --verify --deep --strict --verbose=2 "$APP"
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  spctl --assess --type execute --verbose=4 "$APP"
  xcrun stapler validate "$DMG"
fi
log "done → $DMG"
du -sh "$APP" "$DMG" >&2
