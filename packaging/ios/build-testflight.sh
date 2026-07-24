#!/usr/bin/env bash
# Build + sign + upload a Spark iOS TestFlight build (App Store Connect), headless.
#
# The recipe, and why it isn't just `tauri ios build`: `tauri ios build --export-method app-store-connect`
# builds the .xcarchive correctly, but its OWN export step uses automatic signing and fails on a machine
# with no Apple ID in Xcode ("No Accounts / No profiles for 'org.getlantern.spark' were found") even with
# the profiles installed. So we take the archive it produced and export it ourselves with a manual-signing
# ExportOptions (packaging/ios/ExportOptions-appstore.plist), then upload with altool.
#
# Prereqs on the signing host (see docs/ios-support-validation.md + platforms/apple/README.md):
#   - "Apple Distribution" identity (team ACZRKC3LQ9) in the keychain, with its private key.
#   - Provisioning profiles installed: "Spark iOS App Store" + "Spark Tunnel iOS App Store".
#   - App Store Connect API key at ~/.appstoreconnect/private_keys/AuthKey_<ASC_API_KEY_ID>.p8.
#
# Env:
#   ASC_API_KEY_ID   App Store Connect API key ID (the <KEYID> in AuthKey_<KEYID>.p8). REQUIRED.
#   ASC_ISSUER_ID    App Store Connect issuer UUID (Users and Access -> Integrations). REQUIRED.
#   BUILD_NUMBER     CFBundleVersion; default a monotonic timestamp so TestFlight never sees a dup.
#
# Credentials never live in the repo: the key ID + issuer are passed in, and the private .p8 stays in
# ~/.appstoreconnect/ (altool finds it there). Mirrors "sign offline, verify everywhere".
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${ASC_API_KEY_ID:?set ASC_API_KEY_ID (the KEYID in ~/.appstoreconnect/private_keys/AuthKey_KEYID.p8)}"
: "${ASC_ISSUER_ID:?set ASC_ISSUER_ID (App Store Connect issuer UUID)}"
BUILD_NUMBER="${BUILD_NUMBER:-$(date +%y%m%d%H%M)}"

BUILD_DIR="gui-tauri/src-tauri/gen/apple/build"
EXPORT_DIR="$BUILD_DIR/export-appstore"
OPTS="packaging/ios/ExportOptions-appstore.plist"

echo "==> tauri ios build (archive), build $BUILD_NUMBER" >&2
# Remove any stale archive so the existence check below can't pass on an old build. Tauri's own export
# step is expected to fail headless (see header); `|| true` lets us proceed to the manual export.
rm -rf "$BUILD_DIR"/*.xcarchive
( cd gui-tauri && npx tauri ios build --export-method app-store-connect --build-number "$BUILD_NUMBER" --ci ) || true

ARCHIVE="$(find "$BUILD_DIR" -maxdepth 1 -name '*.xcarchive' -type d | head -1)"
[[ -n "$ARCHIVE" && -d "$ARCHIVE" ]] || { echo "no .xcarchive produced in $BUILD_DIR — the archive step failed" >&2; exit 1; }
echo "==> archive: $ARCHIVE" >&2

echo "==> exportArchive with manual signing (no Apple account needed)" >&2
rm -rf "$EXPORT_DIR"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportOptionsPlist "$OPTS" -exportPath "$EXPORT_DIR"
IPA="$(find "$EXPORT_DIR" -maxdepth 1 -name '*.ipa' | head -1)"
[[ -n "$IPA" && -f "$IPA" ]] || { echo "export produced no .ipa" >&2; exit 1; }
echo "==> IPA: $IPA ($(du -h "$IPA" | cut -f1))" >&2

echo "==> uploading to TestFlight (altool, API key $ASC_API_KEY_ID)" >&2
xcrun altool --upload-app -f "$IPA" -t ios --apiKey "$ASC_API_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
echo "==> done: uploaded '$IPA' as build $BUILD_NUMBER — processing in App Store Connect -> TestFlight" >&2
