#!/usr/bin/env bash
# Build a Debian package for spark from pre-built release binaries — hand-rolled with `dpkg-deb`
# (no cargo-deb dependency, so the layout is fully explicit). Run on a Debian/Ubuntu host
# (CI: the ubuntu runner) after `cargo build --release`.
#
# Usage: build-deb.sh <version> <arch> <bindir> [outdir]
#   <version>  package version, e.g. 0.1.0 (no leading 'v')
#   <arch>     Debian architecture: amd64 | arm64
#   <bindir>   directory holding the built `spark` and `spark-service` binaries
#   [outdir]   where to write the .deb (default: current dir)
set -euo pipefail

version="${1:?usage: build-deb.sh <version> <arch> <bindir> [outdir]}"
arch="${2:?missing <arch> (amd64|arm64)}"
bindir="${3:?missing <bindir>}"
outdir="${4:-.}"

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# Filesystem layout: client in /usr/bin, daemon in /usr/sbin, unit + default config in place.
install -Dm755 "$bindir/spark" "$stage/usr/bin/spark"
install -Dm755 "$bindir/spark-service" "$stage/usr/sbin/spark-service"
install -Dm644 "$root/packaging/systemd/spark.service" "$stage/lib/systemd/system/spark.service"
install -Dm644 "$root/packaging/config.example.toml" "$stage/etc/spark/config.toml"

# Control metadata + maintainer scripts.
mkdir -p "$stage/DEBIAN"
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" "$here/control.template" >"$stage/DEBIAN/control"
install -m755 "$here/postinst" "$stage/DEBIAN/postinst"
install -m755 "$here/prerm" "$stage/DEBIAN/prerm"
install -m644 "$here/conffiles" "$stage/DEBIAN/conffiles"

mkdir -p "$outdir"
out="$outdir/spark_${version}_${arch}.deb"
# --root-owner-group so files are owned by root:root without needing fakeroot.
dpkg-deb --root-owner-group --build "$stage" "$out"
echo "$out"
