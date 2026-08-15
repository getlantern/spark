#!/usr/bin/env bash
# Build the Debian package for the spark dynamic-transport exit, from a pre-built release binary.
# Mirrors build-deb.sh (hand-rolled `dpkg-deb`, no cargo-deb), but ships a different binary, unit and
# config path — an exit shares no files with the client package and is not useful on a client host.
#
# This is the artifact lantern-cloud's provisioning installs: cloud-init curls the .deb from GitHub
# Releases for the tag the orchestrator picked for a route, apt-get installs it, and the config push
# writes /etc/spark-wasm-server/config.json and enables the unit. See
# docs/wasm-exit-deployment-design.md.
#
# Usage: build-exit-deb.sh <version> <arch> <bindir> [outdir]
#   <version>  package version, e.g. 0.1.0 (no leading 'v')
#   <arch>     Debian architecture: amd64 | arm64
#   <bindir>   directory holding the built `spark-wasm-server` binary
#   [outdir]   where to write the .deb (default: current dir)
set -euo pipefail

version="${1:?usage: build-exit-deb.sh <version> <arch> <bindir> [outdir]}"
arch="${2:?missing <arch> (amd64|arm64)}"
bindir="${3:?missing <bindir>}"
outdir="${4:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# /usr/sbin, matching the unit's ExecStart: a server binary with no user-facing subcommands worth
# putting on a plain user's PATH.
install -Dm755 "$bindir/spark-wasm-server" "$stage/usr/sbin/spark-wasm-server"
install -Dm644 "$root/packaging/systemd/spark-wasm-server.service" \
    "$stage/lib/systemd/system/spark-wasm-server.service"

# An example, NOT a conffile. The real config is written by the provisioning pipeline and contains a
# secret (`k_srv`) plus a hex-encoded module bundle; shipping it as a package-managed conffile would
# put dpkg in the business of merging generated secrets on upgrade.
install -Dm644 "$root/packaging/spark-wasm-server.example.json" \
    "$stage/etc/spark-wasm-server/config.example.json"

mkdir -p "$stage/DEBIAN"
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" "$here/exit-control.template" >"$stage/DEBIAN/control"
install -m755 "$here/exit-postinst" "$stage/DEBIAN/postinst"
install -m755 "$here/exit-prerm" "$stage/DEBIAN/prerm"

mkdir -p "$outdir"
out="$outdir/spark-wasm-server_${version}_${arch}.deb"
# --root-owner-group so files are owned by root:root without needing fakeroot.
dpkg-deb --root-owner-group --build "$stage" "$out"
echo "$out"
