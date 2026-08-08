#!/usr/bin/env bash
# Build a notarized, stapled macOS DMG of the spark app (Model A — ADR 0005): the controlling app
# embeds the SparkTunnel Network Extension *system extension*, drag-installed from the DMG into
# /Applications. Wraps the proven platforms/apple recipe (archive -> exportArchive with the
# Developer-ID ExportOptions.plist) and adds: notarize+staple the .app, build the DMG, notarize+staple
# the DMG, and verify with spctl/stapler. This script is the source of truth; the CI release job
# (.github/workflows/release.yml) calls it.
#
# Prerequisites (one-time, human — see platforms/apple/README.md):
#   - The "Developer ID Application: ... (ACZRKC3LQ9)" cert + its private key in this keychain.
#   - The portal Developer-ID provisioning profiles installed: "Spark macOS App", "Spark macOS Tunnel".
#   - xcodegen + (for the xcframework) the rust apple targets. Xcode CLT.
#
# Notarization credentials (pick ONE; omit all + SKIP_NOTARIZE=1 for a local build/sign/dmg dry run):
#   - NOTARY_PROFILE=<name>      a `xcrun notarytool store-credentials` keychain profile (preferred, CI), or
#   - AC_USERNAME + AC_PASSWORD  Apple ID + app-specific password (team is TEAM_ID).
#
# Env knobs:
#   VERSION         release version for the DMG name + CFBundleVersion bump (default: git describe).
#   SKIP_NOTARIZE   "1" -> build + sign + DMG + verify only (no notarytool calls). For local dry runs.
#   OUTPUT_DIR      where the .dmg lands (default: dist/).
#   TEAM_ID         Apple Developer team (default: ACZRKC3LQ9).
#
# Usage:
#   NOTARY_PROFILE=spark VERSION=0.1.0 packaging/macos/build-dmg.sh
#   SKIP_NOTARIZE=1 packaging/macos/build-dmg.sh        # local dry run, no creds
set -euo pipefail

# --- config -------------------------------------------------------------------------------------
cd "$(dirname "$0")/../.."                      # repo root (script is packaging/macos/)
REPO_ROOT="$PWD"
APPLE_DIR="$REPO_ROOT/platforms/apple"
SCHEME="SparkApp"
APP_NAME="SparkApp.app"
VOLNAME="Spark"
TEAM_ID="${TEAM_ID:-ACZRKC3LQ9}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/dist}"
SKIP_NOTARIZE="${SKIP_NOTARIZE:-0}"
# Version: explicit, else `git describe`, else a dev stamp the caller can override.
VERSION="${VERSION:-$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)}"
VERSION="${VERSION#v}"                          # strip a leading v from a tag like v0.1.0

WORK="$(mktemp -d)"
ARCHIVE="$WORK/Spark.xcarchive"
EXPORT_DIR="$WORK/export"
APP="$EXPORT_DIR/$APP_NAME"
DMG="$OUTPUT_DIR/spark-$VERSION-macos-arm64.dmg"
trap 'rm -rf "$WORK"' EXIT

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }

# --- preflight ----------------------------------------------------------------------------------
command -v xcodegen >/dev/null || { echo "xcodegen not found (brew install xcodegen)" >&2; exit 1; }
command -v xcodebuild >/dev/null || { echo "xcodebuild not found (install Xcode CLT)" >&2; exit 1; }

# Resolve the signing identity to a specific SHA-1 hash. Signing by the name string is ambiguous when
# several "Developer ID Application ... (TEAM_ID)" certs share the keychain (common after renewals);
# the hash is unambiguous. Override with SIGN_IDENTITY=<sha1> if a specific cert is required.
SIGN_IDENTITY="${SIGN_IDENTITY:-$(security find-identity -v -p codesigning \
  | awk -v t="$TEAM_ID" '/Developer ID Application/ && index($0, t) {print $2; exit}')}"
[[ -n "$SIGN_IDENTITY" ]] \
  || { echo "No 'Developer ID Application ... ($TEAM_ID)' signing identity in the keychain" >&2; exit 1; }

# Resolve notarization mode early so we fail fast (unless skipping).
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
log "building spark $VERSION → $DMG (skip-notarize=$SKIP_NOTARIZE)"

# --- 1. xcframework + project -------------------------------------------------------------------
log "building SparkCore.xcframework"
"$APPLE_DIR/build-xcframework.sh"
log "generating Spark.xcodeproj (xcodegen)"
( cd "$APPLE_DIR" && xcodegen generate )

# --- 2. archive (Developer-ID, manual signing per project.yml) ----------------------------------
log "xcodebuild archive ($SCHEME, Release, arm64)"
# `CODE_SIGN_IDENTITY` is overridden with the resolved SHA-1 for the reason the hash was resolved in
# the first place. project.yml sets it to the NAME ("Developer ID Application"), which is ambiguous
# once a renewal leaves several such certs in the keychain: xcodebuild picks one, and if that is not
# the cert embedded in the provisioning profile the archive fails with "Provisioning profile ...
# doesn't include signing certificate". The hash was already being computed here — it was just not
# reaching the step that actually needed it (the DMG codesign below got it; the archive did not).
xcodebuild -project "$APPLE_DIR/Spark.xcodeproj" -scheme "$SCHEME" -configuration Release \
  -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" \
  ARCHS=arm64 MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$(date +%s)" \
  CODE_SIGN_IDENTITY="$SIGN_IDENTITY" \
  archive

# --- 3. export the Developer-ID .app ------------------------------------------------------------
# Same ambiguity as the archive step, one layer down: the committed ExportOptions.plist names the
# certificate ("Developer ID Application"), which is correct on a CI runner that imports exactly one
# and wrong on any machine holding a renewal alongside the old cert. Export a copy with the resolved
# SHA-1 substituted rather than editing the committed file, so the repo keeps a plist that is
# readable and machine-independent while this build gets a deterministic one.
EXPORT_PLIST="$WORK/ExportOptions.plist"
cp "$APPLE_DIR/ExportOptions.plist" "$EXPORT_PLIST"
/usr/libexec/PlistBuddy -c "Set :signingCertificate $SIGN_IDENTITY" "$EXPORT_PLIST"

log "xcodebuild -exportArchive (ExportOptions.plist → $APP_NAME)"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$EXPORT_DIR" \
  -exportOptionsPlist "$EXPORT_PLIST"
[[ -d "$APP" ]] || { echo "export did not produce $APP" >&2; exit 1; }

# --- 4. notarize + staple the .app --------------------------------------------------------------
# The .app carries the embedded system extension; notarize the whole bundle, then staple so the
# ticket travels with the .app after it's dragged out of the DMG.
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing $APP_NAME (notarytool submit --wait)"
  ditto -c -k --keepParent "$APP" "$WORK/app.zip"
  xcrun notarytool submit "$WORK/app.zip" "${NOTARY_ARGS[@]}" --wait
  log "stapling $APP_NAME"
  xcrun stapler staple "$APP"
else
  log "SKIP_NOTARIZE=1 → not notarizing/stapling the .app"
fi

# --- 5. build the DMG (hdiutil: deterministic + headless-safe for CI) ----------------------------
log "building DMG (drag-to-/Applications layout)"
STAGE="$WORK/stage"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

# Sign the DMG itself with the Developer ID Application identity (so the container is signed too).
log "codesigning the DMG ($SIGN_IDENTITY)"
codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG"

# --- 6. notarize + staple the DMG ---------------------------------------------------------------
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing the DMG (notarytool submit --wait)"
  xcrun notarytool submit "$DMG" "${NOTARY_ARGS[@]}" --wait
  log "stapling the DMG"
  xcrun stapler staple "$DMG"
fi

# --- 7. verify ----------------------------------------------------------------------------------
log "verifying signatures"
codesign --verify --deep --strict --verbose=2 "$APP"
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  spctl --assess --type execute --verbose=4 "$APP"   # Gatekeeper accepts the app
  xcrun stapler validate "$DMG"                        # the DMG has a stapled ticket
fi

log "done: $DMG"
echo "$DMG"
