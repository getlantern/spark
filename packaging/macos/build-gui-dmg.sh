#!/usr/bin/env bash
# Build a notarized macOS DMG of the **Flutter** controlling app (Model A, ADR 0005) with the
# SparkTunnel NE system extension embedded. This is the macOS *product* DMG (the Flutter `gui/` app
# as the controlling app), distinct from packaging/macos/build-dmg.sh which packages the
# platforms/apple SwiftUI harness.
#
# Pipeline: build the signed system extension (via the platforms/apple archive) → `flutter build
# macos --release` → embed the sysext into the Flutter .app → re-sign the app bundle (seals the
# sysext + strips get-task-allow + hardened runtime) → DMG → notarize+staple .app and DMG → verify.
#
# Prereqs + creds: identical to build-dmg.sh (Developer ID Application cert + "Spark macOS App"/
# "Spark macOS Tunnel" profiles; NOTARY_PROFILE or AC_USERNAME+AC_PASSWORD; SKIP_NOTARIZE=1 for a
# no-creds dry run). Env: VERSION, OUTPUT_DIR, TEAM_ID, SIGN_IDENTITY (as in build-dmg.sh).
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
APPLE_DIR="$REPO_ROOT/platforms/apple"
GUI_DIR="$REPO_ROOT/gui"
TEAM_ID="${TEAM_ID:-ACZRKC3LQ9}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/dist}"
SKIP_NOTARIZE="${SKIP_NOTARIZE:-0}"
VERSION="${VERSION:-$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
VERSION="${VERSION#v}"
APP_NAME="spark_gui.app"
VOLNAME="Spark"
SYSEXT_ID="org.getlantern.spark.tunnel"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ARCHIVE="$WORK/Spark.xcarchive"
APP="$WORK/$APP_NAME"
DMG="$OUTPUT_DIR/spark-gui-$VERSION-macos-arm64.dmg"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }

# --- preflight (mirrors build-dmg.sh) -----------------------------------------------------------
command -v xcodegen >/dev/null || { echo "xcodegen not found (brew install xcodegen)" >&2; exit 1; }
command -v flutter >/dev/null || { echo "flutter not found" >&2; exit 1; }
SIGN_IDENTITY="${SIGN_IDENTITY:-$(security find-identity -v -p codesigning \
  | awk -v t="$TEAM_ID" '/Developer ID Application/ && index($0, t) {print $2; exit}')}"
[[ -n "$SIGN_IDENTITY" ]] \
  || { echo "No 'Developer ID Application ... ($TEAM_ID)' identity in the keychain" >&2; exit 1; }

NOTARY_ARGS=()
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    NOTARY_ARGS=(--keychain-profile "$NOTARY_PROFILE")
  elif [[ -n "${AC_USERNAME:-}" && -n "${AC_PASSWORD:-}" ]]; then
    NOTARY_ARGS=(--apple-id "$AC_USERNAME" --password "$AC_PASSWORD" --team-id "$TEAM_ID")
  else
    echo "No notarization creds: set NOTARY_PROFILE, or AC_USERNAME+AC_PASSWORD, or SKIP_NOTARIZE=1" >&2
    exit 1
  fi
fi

mkdir -p "$OUTPUT_DIR"
log "building spark GUI $VERSION → $DMG (skip-notarize=$SKIP_NOTARIZE)"

# --- 1. build the signed system extension (platforms/apple archive) + extract it ----------------
log "building the system extension (platforms/apple archive)"
"$APPLE_DIR/build-xcframework.sh"
( cd "$APPLE_DIR" && xcodegen generate )
xcodebuild -project "$APPLE_DIR/Spark.xcodeproj" -scheme SparkApp -configuration Release \
  -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" \
  ARCHS=arm64 CURRENT_PROJECT_VERSION="$(date +%s)" archive
SYSEXT_SRC="$ARCHIVE/Products/Applications/SparkApp.app/Contents/Library/SystemExtensions/$SYSEXT_ID.systemextension"
[[ -d "$SYSEXT_SRC" ]] || { echo "system extension not found in archive: $SYSEXT_SRC" >&2; exit 1; }

# --- 2. build the Flutter controlling app -------------------------------------------------------
# Bake the data-path config into the app so connect tunnels accordingly (egress = the relay/server):
#  - SPARK_PROXY ("host:port" IP literal) → a plain relay.
#  - SPARK_CONFIG (base64 of a full TOML Config — AnyTLS + handshake shaping + gambit) → the whole
#    transport stack; takes precedence over SPARK_PROXY.
# Unset → the app forwards directly.
DART_DEFINES=()
[[ -n "${SPARK_PROXY:-}" ]] && DART_DEFINES+=(--dart-define=SPARK_PROXY="$SPARK_PROXY")
[[ -n "${SPARK_CONFIG:-}" ]] && DART_DEFINES+=(--dart-define=SPARK_CONFIG="$SPARK_CONFIG")
log "flutter build macos --release ${SPARK_CONFIG:+(anytls config baked) }${SPARK_PROXY:+(proxy $SPARK_PROXY)}"
( cd "$GUI_DIR" && flutter build macos --release "${DART_DEFINES[@]}" )
FLUTTER_APP="$GUI_DIR/build/macos/Build/Products/Release/$APP_NAME"
[[ -d "$FLUTTER_APP" ]] || { echo "flutter build did not produce $FLUTTER_APP" >&2; exit 1; }
rm -rf "$APP"
cp -R "$FLUTTER_APP" "$APP"

# --- 3. embed the system extension --------------------------------------------------------------
log "embedding $SYSEXT_ID.systemextension"
mkdir -p "$APP/Contents/Library/SystemExtensions"
cp -R "$SYSEXT_SRC" "$APP/Contents/Library/SystemExtensions/"

# --- 4. re-sign the app bundle (top-level only) -------------------------------------------------
# Adding the sysext breaks the app's seal; re-sign the top level to (a) include the sysext in
# CodeResources, (b) re-sign the main executable with Release.entitlements — which omits
# get-task-allow, so the binary is notarizable — and (c) apply the hardened runtime. No --deep: the
# nested frameworks (signed by flutter) and the sysext (signed by the archive, with its own
# entitlements + profile) keep their existing signatures.
log "re-signing the app bundle"
codesign --force --options runtime --timestamp \
  --entitlements "$GUI_DIR/macos/Runner/Release.entitlements" \
  --sign "$SIGN_IDENTITY" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

# --- 5. notarize + staple the .app --------------------------------------------------------------
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing $APP_NAME (notarytool submit --wait)"
  ditto -c -k --keepParent "$APP" "$WORK/app.zip"
  xcrun notarytool submit "$WORK/app.zip" "${NOTARY_ARGS[@]}" --wait
  log "stapling $APP_NAME"
  xcrun stapler staple "$APP"
fi

# --- 6. build the DMG ---------------------------------------------------------------------------
log "building DMG (drag-to-/Applications layout)"
STAGE="$WORK/stage"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
log "codesigning the DMG ($SIGN_IDENTITY)"
codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG"

# --- 7. notarize + staple the DMG ---------------------------------------------------------------
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing the DMG (notarytool submit --wait)"
  xcrun notarytool submit "$DMG" "${NOTARY_ARGS[@]}" --wait
  log "stapling the DMG"
  xcrun stapler staple "$DMG"
fi

# --- 8. verify ----------------------------------------------------------------------------------
log "verifying"
codesign --verify --deep --strict --verbose=2 "$APP"
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  spctl --assess --type execute --verbose=4 "$APP"
  xcrun stapler validate "$DMG"
fi

log "done: $DMG"
echo "$DMG"
