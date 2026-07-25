#!/usr/bin/env bash
# Build a signed + notarized Spark.app / DMG from the Tauri UI (gui-tauri), embedding the
# org.getlantern.spark.tunnel system extension — the NE Model A product (ADR 0008). This is the macOS
# product DMG (the former Flutter build-gui-dmg.sh was removed; Tauri is the single cross-platform UI).
#
# Env knobs:
#   SIGN_IDENTITY   Developer ID Application identity (auto-detected from the keychain otherwise)
#   APP_PROFILE     path to the "Spark macOS App" .provisionprofile (auto-located from the Xcode store)
#   NOTARY_PROFILE  notarytool keychain profile, OR
#   AC_USERNAME + AC_PASSWORD  Apple-ID + app-specific password
#   SKIP_NOTARIZE=1 build signed-but-not-notarized (fast local iteration)
#   REUSE_SYSEXT    path to a prebuilt .systemextension to embed instead of building one (keeps the
#                   sysext version stable → reinstall needs no reboot; for app-only Rust/JS changes)
#   MAC_ARCH        macOS arch: arm64 (default) or x86_64. x86_64 → a separate Spark-x86_64.dmg.
#   OUTPUT_DIR      where Spark.app + the DMG land (default: dist/); the DMG is Spark.dmg for
#                   arm64 and Spark-x86_64.dmg for MAC_ARCH=x86_64
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$PWD"
APPLE_DIR="$REPO_ROOT/platforms/apple"
GUI="$REPO_ROOT/gui-tauri"
TEAM_ID="${TEAM_ID:-ACZRKC3LQ9}"
SYSEXT_ID="org.getlantern.spark.tunnel"
VOLNAME="Spark"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ARCHIVE="$WORK/SparkApp.xcarchive"
OUT="${OUTPUT_DIR:-$REPO_ROOT/dist}"; mkdir -p "$OUT"

# macOS target arch — arm64 (default) or x86_64. Selects the Rust target for the Tauri app and the
# sysext ARCHS, and (exported) the xcframework macOS slice. An Intel build lands as a separate
# Spark-x86_64.dmg beside the arm64 Spark.dmg; the .app inside is always named Spark.app so it
# installs under the same name regardless of arch.
MAC_ARCH="${MAC_ARCH:-arm64}"
case "$MAC_ARCH" in
  arm64)  RUST_TARGET=aarch64-apple-darwin; ARCH_SUFFIX="" ;;
  x86_64) RUST_TARGET=x86_64-apple-darwin;  ARCH_SUFFIX="-x86_64" ;;
  *) echo "MAC_ARCH must be arm64 or x86_64 (got: $MAC_ARCH)" >&2; exit 1 ;;
esac
export MAC_ARCH   # consumed by build-xcframework.sh to pick the macOS slice arch

APP="$OUT/Spark.app"
DMG="$OUT/Spark${ARCH_SUFFIX}.dmg"
ENT="$GUI/src-tauri/Release.entitlements"
SKIP_NOTARIZE="${SKIP_NOTARIZE:-0}"

log() { echo "[build-tauri-dmg] $*" >&2; }

# Pick the Developer ID Application identity for TEAM_ID (not just the first one —
# avoids signing with the wrong cert when multiple teams are in the keychain).
SIGN_IDENTITY="${SIGN_IDENTITY:-$(security find-identity -v -p codesigning \
  | awk -F'"' -v t="$TEAM_ID" '/Developer ID Application/ && $0 ~ t {print $2; exit}')}"
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

# 1. System extension: build fresh, OR reuse a prebuilt .systemextension via REUSE_SYSEXT to keep
#    its version stable. App-only changes (Rust/JS) don't need a new sysext, and a fresh build bumps
#    CURRENT_PROJECT_VERSION, which forces the user to reboot to re-activate the replacement (macOS
#    stages it as `terminated_waiting_to_uninstall_on_reboot` while the old one keeps running).
#    Reusing the existing sysext makes the reinstall a no-reboot, no-re-approval drop-in.
if [[ -n "${REUSE_SYSEXT:-}" ]]; then
  log "reusing prebuilt system extension (no version bump): $REUSE_SYSEXT"
  SYSEXT_SRC="$REUSE_SYSEXT"
  [[ -d "$SYSEXT_SRC" ]] || { echo "REUSE_SYSEXT not found: $SYSEXT_SRC" >&2; exit 1; }
  # A prebuilt sysext is arch-specific; embedding an arm64 sysext in an x86_64 app (or vice-versa)
  # yields an extension that won't load on the target Mac. Fail loudly on a mismatch.
  if command -v lipo >/dev/null 2>&1; then
    # `|| true` so an empty glob (no executable found) doesn't trip errexit under `set -o pipefail`
    # (ls exits non-zero on no match); the `-n "$ext_bin"` guard below then skips the check.
    ext_bin="$(ls "$SYSEXT_SRC"/Contents/MacOS/* 2>/dev/null | head -1 || true)"
    if [[ -n "$ext_bin" ]] && ! lipo -archs "$ext_bin" 2>/dev/null | tr ' ' '\n' | grep -qx "$MAC_ARCH"; then
      echo "REUSE_SYSEXT arch mismatch: $ext_bin is [$(lipo -archs "$ext_bin" 2>/dev/null)], need $MAC_ARCH" >&2
      exit 1
    fi
  fi
else
  log "building the system extension (platforms/apple archive, arch=$MAC_ARCH)"
  "$APPLE_DIR/build-xcframework.sh"
  ( cd "$APPLE_DIR" && xcodegen generate )
  # Pin the archive to the resolved SIGN_IDENTITY. project.yml's CODE_SIGN_IDENTITY is the generic
  # "Developer ID Application" name AND it sets the per-SDK CODE_SIGN_IDENTITY[sdk=macosx*] variant; on
  # a keychain with several Developer ID certs sharing that display name, xcodebuild can otherwise pick
  # one that isn't in the provisioning profile and fail with "profile doesn't include signing
  # certificate". Override BOTH keys — the per-SDK variant is more specific, so overriding the generic
  # one alone may not take — and quote the [sdk=…] arg so the shell doesn't glob it. To fully
  # disambiguate when certs share a name, pass a SHA-1 via SIGN_IDENTITY (the auto-detected default is
  # the cert *name*, which is itself ambiguous across same-named certs).
  xcodebuild -project "$APPLE_DIR/Spark.xcodeproj" -scheme SparkApp -configuration Release \
    -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" \
    ARCHS="$MAC_ARCH" CURRENT_PROJECT_VERSION="$(date +%s)" \
    CODE_SIGN_IDENTITY="$SIGN_IDENTITY" "CODE_SIGN_IDENTITY[sdk=macosx*]=$SIGN_IDENTITY" archive
  SYSEXT_SRC="$ARCHIVE/Products/Applications/SparkApp.app/Contents/Library/SystemExtensions/$SYSEXT_ID.systemextension"
  [[ -d "$SYSEXT_SRC" ]] || { echo "system extension not found in archive: $SYSEXT_SRC" >&2; exit 1; }
fi

# 2. The Tauri controlling app (config resolves at runtime via config.rs: config.toml → SPARK_CONFIG
#    → SPARK_PROXY → direct, so there's nothing to bake here).
log "building the Tauri app (target=$RUST_TARGET)"
( cd "$GUI" && APPLE_SIGNING_IDENTITY="$SIGN_IDENTITY" npm run tauri build -- --target "$RUST_TARGET" )
TAURI_APP="$GUI/src-tauri/target/$RUST_TARGET/release/bundle/macos/Spark.app"
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
log "building the DMG (branded drag-to-Applications layout)"
STAGE="$WORK/stage"; mkdir -p "$STAGE/.background"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
# Branded background (⚡ Spark wordmark + drag arrow) and a custom volume icon (the app icon).
cp "$REPO_ROOT/packaging/branding/dmg-background.png" "$STAGE/.background/background.png"
cp "$GUI/src-tauri/icons/icon.icns" "$STAGE/.VolumeIcon.icns"

# Lay the window out on a read-write image, then compress to the final UDZO DMG. If Finder
# automation is unavailable (headless CI without an Aqua session / Automation TCC grant), fall
# back to the default layout so the build still produces a working DMG.
RW="$WORK/rw.dmg"
# Detach any stale volume of this name first. A lingering /Volumes/$VOLNAME (e.g. a previously-mounted
# DMG) makes the new RW image mount as "$VOLNAME 1", and the Finder layout below — which targets the
# volume by name — would then style the WRONG volume, yielding a DMG with no .DS_Store (no styling).
for v in /Volumes/"$VOLNAME" /Volumes/"$VOLNAME "[0-9]*; do
  [[ -e "$v" ]] && hdiutil detach "$v" -force >/dev/null 2>&1 || true
done
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -ov -format UDRW "$RW" >/dev/null
if MNT="$(hdiutil attach -readwrite -noverify -noautoopen "$RW" 2>/dev/null | grep -Eo '/Volumes/[^"]+$' | head -1)" && [[ -n "$MNT" ]]; then
  # Target the ACTUAL mounted volume by name (not the fixed $VOLNAME) so a name collision can't
  # misdirect the layout osascript to a different volume.
  VOL="$(basename "$MNT")"
  # Set the Finder "custom icon" bit so .VolumeIcon.icns is honored. Non-fatal, but warn
  # loudly if SetFile is missing/fails so we don't silently ship an unbranded volume icon.
  if command -v SetFile >/dev/null 2>&1; then
    SetFile -a C "$MNT" || log "WARN: SetFile failed — volume icon may not show (DMG still valid)"
  else
    log "WARN: SetFile not found (install Xcode command-line tools) — volume icon skipped"
  fi
  if osascript >/dev/null 2>&1 <<EOF
tell application "Finder"
  tell disk "$VOL"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set the bounds of container window to {200, 160, 920, 640}
    set vo to the icon view options of container window
    set arrangement of vo to not arranged
    set icon size of vo to 128
    set text size of vo to 13
    set background picture of vo to file ".background:background.png"
    set position of item "$VOLNAME.app" of container window to {200, 235}
    set position of item "Applications" of container window to {520, 235}
    update without registering applications
    delay 1
    close
  end tell
end tell
EOF
  then log "DMG window laid out"; else log "WARN: Finder layout skipped (automation unavailable) — DMG uses default layout"; fi
  sync
  hdiutil detach "$MNT" >/dev/null 2>&1 || hdiutil detach "$MNT" -force >/dev/null 2>&1 || true
fi
hdiutil convert "$RW" -format UDZO -imagekey zlib-level=9 -o "$DMG" -ov >/dev/null
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
