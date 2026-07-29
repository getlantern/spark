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
#   NOTARY_TIMEOUT  seconds to wait for each notarization verdict (default 1800). On timeout the
#                   submission id is printed so the wait can be resumed without rebuilding.
#   NOTARY_SUBMIT_TRIES  upload attempts before giving up (default 3); Apple's notary endpoint
#                   intermittently connect-times-out, and a failed upload has no id to resume from.
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

# ── Certs and profiles ───────────────────────────────────────────────────────
# The signing cert must be embedded in the provisioning profile, or the result notarizes fine and then
# refuses to launch (AMFI spawn error 163). The profiles name exactly which cert they accept, so the
# identity is DERIVED from them below rather than guessed and validated after the fact.

# Every cert SHA-1 (upper-case, no colons) embedded in provisioning profile $1, one per line.
profile_certs() {
  local pl c i=0
  pl="$(security cms -D -i "$1" 2>/dev/null)" || return 0
  while c="$(printf '%s' "$pl" | plutil -extract "DeveloperCertificates.$i" raw -o - - 2>/dev/null \
      | base64 -d 2>/dev/null | openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
      | sed 's/.*=//; s/://g' | tr '[:lower:]' '[:upper:]')" && [[ -n "$c" ]]; do
    echo "$c"
    i=$((i + 1))
  done
}

# True if provisioning profile $1 embeds the cert whose SHA-1 (upper-case, no colons) is $2.
profile_has_cert() { profile_certs "$1" | grep -qx "$2"; }

# Paths of the Xcode-store profiles whose app-id is exactly $1 (e.g. `org.getlantern.spark`), one per
# line. The trailing quote in the match keeps `…spark` from also matching `…spark.tunnel`.
profiles_for_appid() {
  local d="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles" f
  for f in "$d"/*.provisionprofile; do
    [[ -f "$f" ]] || continue
    security cms -D -i "$f" 2>/dev/null | plutil -p - 2>/dev/null \
      | grep -qF "$TEAM_ID.$1\"" && echo "$f"
  done
  return 0
}

# SHA-1s of the Developer ID Application certs for TEAM_ID that this keychain can actually sign with
# (`find-identity -v` lists only identities holding a private key), in keychain order.
keychain_dev_id_certs() {
  security find-identity -v -p codesigning \
    | awk -v t="$TEAM_ID" '/Developer ID Application/ && $0 ~ t {print $2}'
}

# Print the profile's name and its embedded certs, for a diagnosable error.
describe_profile() {
  local pl name
  pl="$(security cms -D -i "$1" 2>/dev/null)" || { echo "         $1 (unreadable)" >&2; return 0; }
  name="$(printf '%s' "$pl" | plutil -extract Name raw -o - - 2>/dev/null)"
  echo "         $(basename "$1") \"$name\" accepts: $(profile_certs "$1" | tr '\n' ' ')" >&2
}

# Derive the signing identity from the profiles when the caller didn't pin one.
#
# Do NOT just take the first Developer ID Application cert in the keychain. Several certs routinely
# share the identical display name `Developer ID Application: <org> (<TEAM_ID>)`, so "the first one"
# is really "whichever the keychain happens to list first" — and adding an unrelated cert silently
# changes which one a build picks. That is a build that was working yesterday failing today with a
# profile-mismatch, for a reason nowhere in the diff.
#
# The profiles are the authority: each embeds the exact set of certs it accepts. Intersect that with
# what the keychain can sign with and the answer is normally unique, with no guessing at all.
derive_sign_identity() {
  local app_certs tunnel_certs c both="" any=""
  app_certs="$(while read -r p; do profile_certs "$p"; done < <(profiles_for_appid org.getlantern.spark) | sort -u)"
  tunnel_certs="$(while read -r p; do profile_certs "$p"; done < <(profiles_for_appid org.getlantern.spark.tunnel) | sort -u)"
  [[ -n "$app_certs" ]] || return 1
  while read -r c; do
    [[ -n "$c" ]] || continue
    grep -qx "$c" <<<"$app_certs" || continue
    any="${any:-$c}"
    # Prefer a cert both the app and the sysext profiles accept — the sysext's own check happens only
    # after a multi-minute xcodebuild archive, so catching a mismatch here is worth a lot. Preference,
    # not a requirement: with no tunnel profile in the store there is nothing to intersect.
    if [[ -n "$tunnel_certs" ]] && grep -qx "$c" <<<"$tunnel_certs"; then both="${both:-$c}"; fi
  done < <(keychain_dev_id_certs)
  [[ -n "${both:-$any}" ]] || return 1
  echo "${both:-$any}"
}

if [[ -z "${SIGN_IDENTITY:-}" ]]; then
  SIGN_IDENTITY="$(derive_sign_identity || true)"
  if [[ -z "$SIGN_IDENTITY" ]]; then
    echo "ERROR: no Developer ID Application cert for $TEAM_ID is both in this keychain and accepted" >&2
    echo "       by a Spark provisioning profile. Signing with any other cert would notarize and then" >&2
    echo "       fail to launch (AMFI spawn error 163). Pass SIGN_IDENTITY=<sha1> to override." >&2
    echo "       keychain can sign with: $(keychain_dev_id_certs | tr '\n' ' ')" >&2
    while read -r p; do describe_profile "$p"; done \
      < <(profiles_for_appid org.getlantern.spark; profiles_for_appid org.getlantern.spark.tunnel)
    exit 1
  fi
  log "signing identity derived from the provisioning profiles: $SIGN_IDENTITY"
fi

# Canonical SHA-1 (upper-case, no colons) of the signing cert, for matching against profile certs.
# SIGN_IDENTITY is a SHA-1 when auto-detected above or passed as one — accept it with or without the
# colon separators some tools emit; a passed display name is resolved to the first matching cert's SHA-1.
sign_id_norm="$(printf '%s' "$SIGN_IDENTITY" | tr -d ':' | tr '[:lower:]' '[:upper:]')"
if [[ "$sign_id_norm" =~ ^[0-9A-F]{40}$ ]]; then
  SIGN_SHA1="$sign_id_norm"
else
  SIGN_SHA1="$(security find-identity -v -p codesigning \
    | awk -v n="$SIGN_IDENTITY" 'index($0, n) {print $2; exit}')"
fi
# Fail early + clearly if the identity didn't resolve, instead of later with a misleading "profile does
# not embed the signing cert" (which presumes a known cert).
[[ -n "$SIGN_SHA1" ]] \
  || { echo "could not resolve SIGN_IDENTITY ('$SIGN_IDENTITY') to a Developer ID Application cert in the keychain" >&2; exit 1; }
# Sign with the canonical SHA-1 from here on — not a possibly-ambiguous display name or colon-separated
# form — so the cert actually used to sign is exactly the one validated against the profiles below.
SIGN_IDENTITY="$SIGN_SHA1"

# Fail loud if a profile's embedded cert doesn't include the signing cert: the app/sysext would
# notarize fine but AMFI refuses to spawn it (RBS "Launch failed", POSIX 163). An obvious build error
# beats an unlaunchable, fully-notarized DMG that only fails on the user's first double-click.
assert_profile_matches() {  # <profile-path> <label>
  [[ -f "$1" ]] || { echo "ERROR: the '$2' provisioning profile was not found: $1" >&2; exit 1; }
  profile_has_cert "$1" "$SIGN_SHA1" && return 0
  echo "ERROR: the '$2' provisioning profile does not embed the signing cert $SIGN_SHA1:" >&2
  echo "         $1" >&2
  echo "       It would notarize but fail to launch (AMFI spawn error 163). Remove stale same-named" >&2
  echo "       profiles from ~/Library/Developer/Xcode/UserData/Provisioning Profiles/, or point the" >&2
  echo "       profile at the cert you are signing with." >&2
  exit 1
}

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

# How long to wait for Apple to finish notarizing one artifact.
NOTARY_TIMEOUT="${NOTARY_TIMEOUT:-1800}"
# How many times to attempt the upload before giving up (transient connect timeouts are common).
NOTARY_SUBMIT_TRIES="${NOTARY_SUBMIT_TRIES:-3}"

# Submit `$1` for notarization and wait for a verdict — submitting and polling as SEPARATE steps.
#
# `notarytool submit --wait` does both in one process, so a crash in its polling loop takes the
# submission id with it and forces a full rebuild even though Apple is still processing the upload
# happily. That is not hypothetical: on 2026-07-28 it died with `Bus error: 10` *after* a successful
# upload, and `notarytool history` showed the submission progressing server-side while the build had
# already aborted and wiped its work dir. Polling separately means a crash costs a poll, not 8 minutes —
# and on timeout we print the id so the wait can be resumed by hand instead of rebuilding.
notarize() {
  local path="$1" name id status deadline tries=0
  name="$(basename "$path")"
  # Retry the SUBMIT too, not just the poll. Reaching Apple is the flaky part: within one day this hit
  # `Bus error: 10` inside `--wait`'s polling AND `HTTPClientError.connectTimeout` on the upload. Both are
  # transient, and neither deserves to lose an 8-minute build — a submit that never happened has no id to
  # resume from, so if it is not retried here the whole build has to be re-run.
  while :; do
    id="$(xcrun notarytool submit "$path" "${NOTARY_ARGS[@]}" --no-wait --output-format json \
          | plutil -extract id raw -o - - 2>/dev/null)" || true
    [[ -n "$id" && "$id" != "null" ]] && break
    tries=$((tries + 1))
    if (( tries >= NOTARY_SUBMIT_TRIES )); then
      echo "notarytool submit produced no submission id for $name after $tries attempt(s)" >&2
      return 1
    fi
    echo "  submit attempt $tries for $name failed (transient?); retrying in 20s" >&2
    sleep 20
  done
  log "submitted $name → $id (polling, up to ${NOTARY_TIMEOUT}s)"
  deadline=$(( $(date +%s) + NOTARY_TIMEOUT ))
  while :; do
    # `|| true` so a transient failure (or another crash) retries on the next tick rather than
    # aborting the build — the whole point of splitting submit from poll.
    status="$(xcrun notarytool info "$id" "${NOTARY_ARGS[@]}" --output-format json 2>/dev/null \
              | plutil -extract status raw -o - - 2>/dev/null || true)"
    case "$status" in
      Accepted)
        log "notarization accepted: $name ($id)"
        return 0
        ;;
      Invalid | Rejected)
        echo "notarization $status for $name ($id) — log follows:" >&2
        xcrun notarytool log "$id" "${NOTARY_ARGS[@]}" >&2 || true
        return 1
        ;;
    esac
    if (( $(date +%s) >= deadline )); then
      echo "notarization of $name still '${status:-unknown}' after ${NOTARY_TIMEOUT}s." >&2
      echo "  It is probably still progressing — resume without rebuilding:" >&2
      echo "  xcrun notarytool info $id ${NOTARY_ARGS[*]}" >&2
      return 1
    fi
    sleep 15
  done
}

# Locate the controlling-app provisioning profile (org.getlantern.spark) in the Xcode store,
# PREFERRING one whose embedded cert matches the signing cert. Selecting purely by name/app-id can pick
# a stale same-named profile carrying a different cert — which passes codesign/notarize but fails to
# spawn (AMFI: signing cert not in the embedded profile). Fall back to the first app-id match only if
# none embed the signing cert (the assert below then turns that into a clear error).
locate_profile() {
  local d="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
  local f fallback=""
  for f in "$d"/*.provisionprofile; do
    [[ -f "$f" ]] || continue
    security cms -D -i "$f" 2>/dev/null | plutil -p - 2>/dev/null \
      | grep -qF "$TEAM_ID.org.getlantern.spark\"" || continue
    fallback="${fallback:-$f}"
    profile_has_cert "$f" "$SIGN_SHA1" && { echo "$f"; return 0; }
  done
  [[ -n "$fallback" ]] && { echo "$fallback"; return 0; }
  return 1
}
APP_PROFILE="${APP_PROFILE:-$(locate_profile || true)}"
[[ -f "$APP_PROFILE" ]] || { echo "no 'Spark macOS App' provisioning profile found (set APP_PROFILE)" >&2; exit 1; }
assert_profile_matches "$APP_PROFILE" "Spark macOS App"

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
  # "Developer ID Application" name; on a keychain with several Developer ID certs sharing that display
  # name, xcodebuild can otherwise pick one that isn't in the provisioning profile and fail with
  # "profile doesn't include signing certificate". A command-line `CODE_SIGN_IDENTITY=<value>` override
  # takes precedence over project.yml's per-SDK `CODE_SIGN_IDENTITY[sdk=macosx*]` (verified: the archive
  # signs with the pinned cert). Do NOT also pass `CODE_SIGN_IDENTITY[sdk=macosx*]=…` on the command
  # line — xcodebuild splits NAME=VALUE on the first `=`, so the `=` inside the brackets mangles the
  # value ("No certificate matching 'macosx*]=…'"). Pass a SHA-1 via SIGN_IDENTITY to disambiguate
  # same-named certs (the auto-detected default is the cert *name*).
  xcodebuild -project "$APPLE_DIR/Spark.xcodeproj" -scheme SparkApp -configuration Release \
    -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" \
    ARCHS="$MAC_ARCH" CURRENT_PROJECT_VERSION="$(date +%s)" \
    CODE_SIGN_IDENTITY="$SIGN_IDENTITY" archive
  SYSEXT_SRC="$ARCHIVE/Products/Applications/SparkApp.app/Contents/Library/SystemExtensions/$SYSEXT_ID.systemextension"
  [[ -d "$SYSEXT_SRC" ]] || { echo "system extension not found in archive: $SYSEXT_SRC" >&2; exit 1; }
fi

# Guard the sysext's embedded profile too. Its profile comes from the archive's by-name selection,
# which (unlike the app profile) we can't pin per-target on the xcodebuild command line — so if a stale
# same-named "Spark macOS Tunnel" profile with a different cert is picked, catch it here rather than
# shipping a sysext that can't activate.
assert_profile_matches "$SYSEXT_SRC/Contents/embedded.provisionprofile" "Spark macOS Tunnel"

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
  log "notarizing the app"
  ditto -c -k --keepParent "$APP" "$WORK/app.zip"
  notarize "$WORK/app.zip"
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
  # Style the DMG window (background + icon layout). PREFER a committed .DS_Store template so styling
  # works HEADLESSLY (CI, background/automated builds) with no Finder automation or Aqua session; fall
  # back to driving Finder via osascript when the template is absent. Regenerate the template from a
  # known-good branded DMG: `hdiutil attach Spark.dmg` then
  # `cp "/Volumes/Spark/.DS_Store" packaging/branding/dmg.DS_Store`.
  DS_TEMPLATE="$REPO_ROOT/packaging/branding/dmg.DS_Store"
  if [[ -f "$DS_TEMPLATE" ]]; then
    cp "$DS_TEMPLATE" "$MNT/.DS_Store"
    log "DMG styled from committed .DS_Store template (headless — no Finder automation needed)"
  elif osascript >/dev/null 2>&1 <<EOF
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
  then log "DMG window laid out (Finder automation)"; else log "WARN: no .DS_Store template and Finder automation unavailable — DMG uses default layout"; fi
  sync
  hdiutil detach "$MNT" >/dev/null 2>&1 || hdiutil detach "$MNT" -force >/dev/null 2>&1 || true
fi
hdiutil convert "$RW" -format UDZO -imagekey zlib-level=9 -o "$DMG" -ov >/dev/null
codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG"

# 7. Notarize + staple the DMG.
if [[ "$SKIP_NOTARIZE" != "1" ]]; then
  log "notarizing the DMG"
  notarize "$DMG"
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
