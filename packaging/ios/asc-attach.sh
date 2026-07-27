#!/usr/bin/env bash
# Attach an uploaded build to a TestFlight beta group, then verify it can actually reach testers.
#
# Why this exists: `altool --upload-app` printing UPLOAD SUCCEEDED means Apple accepted the binary — not
# that any tester can see it. Two independent gates sit behind the upload, and both are silent:
#   1. export compliance — answered at build time by ITSAppUsesNonExemptEncryption in the app's Info.plist;
#   2. beta-group membership — a group with hasAccessToAllBuilds=false shows ONLY the builds explicitly
#      attached to it, and a fresh upload is attached to nothing.
# Gate 2 hid three consecutive uploads. It can't be retired once-and-for-all on the group: App Store
# Connect rejects the attribute in a PATCH ("The attribute 'hasAccessToAllBuilds' can not be included in
# a 'UPDATE' operation"), so it is settable only when a group is created. Hence attach per upload, here,
# and verify the result instead of inferring it.
#
# Usage: packaging/ios/asc-attach.sh <build-number>        # the BUILD_NUMBER passed to the upload
#
# Env:
#   ASC_API_KEY_ID    App Store Connect API key ID (the <ID> in AuthKey_<ID>.p8). REQUIRED.
#   ASC_ISSUER_ID     App Store Connect issuer UUID. REQUIRED.
#   TESTFLIGHT_GROUP  Beta group name to attach to; default "Team". Set to "" to skip attaching.
#   BUNDLE_ID         App bundle id; default org.getlantern.spark.
#   WAIT_SECS         Seconds to wait for Apple to finish processing the build; default 1800.
set -euo pipefail

API="https://api.appstoreconnect.apple.com"
BUNDLE_ID="${BUNDLE_ID:-org.getlantern.spark}"
WAIT_SECS="${WAIT_SECS:-1800}"
# `-` not `:-`: an explicitly empty TESTFLIGHT_GROUP means "skip", an unset one means "Team".
GROUP="${TESTFLIGHT_GROUP-Team}"

[ "$#" -eq 1 ] || { echo "usage: $0 <build-number>" >&2; exit 2; }
BUILD_NUMBER="$1"

for tool in curl openssl jq xxd; do
    command -v "$tool" >/dev/null 2>&1 || { echo "required tool not on PATH: $tool" >&2; exit 1; }
done
: "${ASC_API_KEY_ID:?set ASC_API_KEY_ID (the KEYID in ~/.appstoreconnect/private_keys/AuthKey_KEYID.p8)}"
: "${ASC_ISSUER_ID:?set ASC_ISSUER_ID (App Store Connect issuer UUID)}"

KEY="$HOME/.appstoreconnect/private_keys/AuthKey_${ASC_API_KEY_ID}.p8"
[ -f "$KEY" ] || { echo "no App Store Connect private key at $KEY" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

die() { echo "error: $*" >&2; exit 1; }

b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# Left-pad a DER INTEGER's hex to exactly 32 bytes: DER omits leading zero bytes and prepends one when
# the high bit is set, while JOSE wants both halves fixed-width.
pad32() { local h="$1"; h="${h#"${h%%[!0]*}"}"; printf '%064s' "$h" | tr ' ' '0'; }

# A fresh 15-minute ES256 JWT. Minted per request so a long processing wait can't outlive the token.
mint_token() {
    local hdr pl input der r s now
    hdr="$(printf '{"alg":"ES256","kid":"%s","typ":"JWT"}' "$ASC_API_KEY_ID" | b64u)"
    now="$(date +%s)"
    pl="$(printf '{"iss":"%s","iat":%d,"exp":%d,"aud":"appstoreconnect-v1"}' \
        "$ASC_ISSUER_ID" "$now" "$((now + 900))" | b64u)"
    input="$hdr.$pl"
    der="$TMP/sig.der"
    printf '%s' "$input" | openssl dgst -sha256 -sign "$KEY" -out "$der"
    r="$(openssl asn1parse -inform DER -in "$der" | sed -n 's/.*INTEGER *://p' | sed -n 1p)"
    s="$(openssl asn1parse -inform DER -in "$der" | sed -n 's/.*INTEGER *://p' | sed -n 2p)"
    [ -n "$r" ] && [ -n "$s" ] || die "could not parse the ECDSA signature from $KEY"
    printf '%s.%s' "$input" \
        "$(printf '%s%s' "$(pad32 "$r")" "$(pad32 "$s")" | xxd -r -p | b64u)"
}

# api <METHOD> <path> [json-body] — response body on stdout; Apple's error detail on stderr for non-2xx.
api() {
    local method="$1" path="$2" body="${3:-}" code out="$TMP/resp.json"
    if [ -n "$body" ]; then
        code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "$API$path" \
            -H "Authorization: Bearer $(mint_token)" -H "Content-Type: application/json" -d "$body")"
    else
        code="$(curl -sS -o "$out" -w '%{http_code}' -X "$method" "$API$path" \
            -H "Authorization: Bearer $(mint_token)")"
    fi
    case "$code" in
        2*) cat "$out"; return 0 ;;
        *)  echo "App Store Connect $method $path -> HTTP $code" >&2
            jq -r '.errors[]? | "  \(.code): \(.detail)"' "$out" 2>/dev/null >&2 || true
            return 1 ;;
    esac
}

if [ -z "$GROUP" ]; then
    echo "==> TESTFLIGHT_GROUP is empty — skipping the beta-group attach." >&2
    echo "    The build will be visible to NO testers until it is attached." >&2
    exit 0
fi

APP_ID="$(api GET "/v1/apps?filter%5BbundleId%5D=$BUNDLE_ID&limit=1" | jq -r '.data[0].id // empty')"
[ -n "$APP_ID" ] || die "no app found for bundle id $BUNDLE_ID"

# Find the build. Tauri stamps CFBundleVersion as <marketing-version>.<build-number>, so App Store
# Connect reports e.g. "0.1.0.2607270436" for BUILD_NUMBER=2607270436 — match either form.
BUILD_ID=""
STATE=""
DEADLINE="$(( $(date +%s) + WAIT_SECS ))"
while :; do
    RESP="$(api GET "/v1/builds?filter%5Bapp%5D=$APP_ID&sort=-uploadedDate&limit=20")"
    BUILD_ID="$(printf '%s' "$RESP" | jq -r --arg b "$BUILD_NUMBER" \
        '[.data[] | select(.attributes.version == $b or (.attributes.version | endswith("." + $b)))][0].id // empty')"
    STATE="$(printf '%s' "$RESP" | jq -r --arg b "$BUILD_NUMBER" \
        '[.data[] | select(.attributes.version == $b or (.attributes.version | endswith("." + $b)))][0].attributes.processingState // empty')"
    case "$STATE" in
        VALID) break ;;
        FAILED|INVALID) die "build $BUILD_NUMBER finished processing as $STATE — see App Store Connect" ;;
    esac
    [ "$(date +%s)" -lt "$DEADLINE" ] || die "gave up after ${WAIT_SECS}s; build $BUILD_NUMBER is ${STATE:-not visible yet}. Re-run once it processes: packaging/ios/asc-attach.sh $BUILD_NUMBER"
    echo "    build $BUILD_NUMBER: ${STATE:-not visible yet} — waiting 30s..." >&2
    sleep 30
done
echo "==> build $BUILD_NUMBER processed VALID (id $BUILD_ID)" >&2

GROUP_ID="$(api GET "/v1/betaGroups?filter%5Bapp%5D=$APP_ID&limit=200" \
    | jq -r --arg n "$GROUP" '[.data[] | select(.attributes.name == $n)][0].id // empty')"
[ -n "$GROUP_ID" ] || die "no beta group named '$GROUP' on this app (App Store Connect -> TestFlight -> Groups)"

ATTACHED="$(api GET "/v1/betaGroups/$GROUP_ID/builds?limit=200" \
    | jq -r --arg id "$BUILD_ID" '[.data[] | select(.id == $id)] | length')"
if [ "$ATTACHED" = "0" ]; then
    api POST "/v1/betaGroups/$GROUP_ID/relationships/builds" \
        "$(jq -nc --arg id "$BUILD_ID" '{data:[{type:"builds",id:$id}]}')" >/dev/null
    echo "==> attached build $BUILD_NUMBER to beta group '$GROUP'" >&2
else
    echo "==> build $BUILD_NUMBER already attached to beta group '$GROUP'" >&2
fi

# The attach is necessary but not sufficient — export compliance is a separate gate, so confirm the
# build's own state rather than trusting the POST.
BETA_STATE="$(api GET "/v1/builds/$BUILD_ID/buildBetaDetail" \
    | jq -r '.data.attributes.internalBuildState // "unknown"')"
case "$BETA_STATE" in
    # IN_BETA_TESTING is the stronger of the two: the build is not merely eligible, it is being
    # distributed to a group. READY_FOR_BETA_TESTING means processed + compliant but not yet
    # distributed — expected for the moment right after the attach.
    IN_BETA_TESTING)
        echo "==> verified: build $BUILD_NUMBER is IN_BETA_TESTING — live to group '$GROUP'" >&2 ;;
    READY_FOR_BETA_TESTING)
        echo "==> verified: build $BUILD_NUMBER is READY_FOR_BETA_TESTING in group '$GROUP'" >&2 ;;
    MISSING_EXPORT_COMPLIANCE)
        die "build $BUILD_NUMBER is attached but MISSING_EXPORT_COMPLIANCE, so no tester can install it.
    ITSAppUsesNonExemptEncryption should be set in the app's Info.plist at build time; to clear this
    build, PATCH /v1/builds/$BUILD_ID with {\"attributes\":{\"usesNonExemptEncryption\":false}}" ;;
    *)
        echo "==> warning: build $BUILD_NUMBER is attached to '$GROUP' but its state is $BETA_STATE" >&2 ;;
esac
