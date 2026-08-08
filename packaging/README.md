# Packaging & installation (desktop)

Desktop ships two binaries: the privileged **`spark-service`** daemon (owns the TUN + routes,
runs the core) and the unprivileged **`spark`** client. Build them with:

```bash
cargo build --release          # -> target/release/{spark, spark-service}
./scripts/size-budget.sh       # verify both are within the <3 MB stripped budget
```

## Size budget

Per CLAUDE.md the budget is **< 3 MB stripped per binary**. `scripts/size-budget.sh` builds
and checks it (CI-friendly: non-zero exit if over). Current (aarch64, stripped): `spark`
≈ 1.20 MB, `spark-service` ≈ 1.20 MB — comfortably under.

## Cross-build status

| Target | Status |
| --- | --- |
| `aarch64-apple-darwin` (macOS) | native; data path live-verified (M1/M2/M5/M7) |
| `x86_64-unknown-linux-gnu` (Linux) | full workspace cross-checks clean |
| `x86_64-pc-windows-msvc` (Windows) | full workspace cross-checks clean; control transport is the admin-only **named pipe** (`service::pipe`). Not yet run on a real Windows host |

Verify a target yourself with e.g. `cargo check --workspace --all-features --target x86_64-unknown-linux-gnu`.
CI (`.github/workflows/ci.yml`) runs fmt + clippy + tests on all three OSes plus both cross-checks on every push/PR.

## Release builds & distribution

Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`, which builds release binaries on
each native runner, enforces the size budget, packages per platform, and uploads everything to
the GitHub Release:

| Platform | Artifact | Built by |
| --- | --- | --- |
| macOS (arm64 + x86_64) | `spark-<ver>-<target>.tar.gz` (+ `.sha256`) — the CLI/daemon binaries | `tar` in the workflow |
| **macOS app (arm64)** | `spark-<ver>-macos-arm64.dmg` — notarized Tauri app + embedded NE system extension | `packaging/macos/build-tauri-dmg.sh` (gated CI job) |
| Linux (x86_64) | `spark_<ver>_amd64.deb` + tarball | `packaging/debian/build-deb.sh` (hand-rolled `dpkg-deb`) |
| Windows (x86_64) | `spark-<ver>-<target>.zip` (binaries + example config) | `Compress-Archive` in the workflow |

**Homebrew:** `packaging/homebrew/spark.rb` is the formula. After a release, fill its per-arch
`url` + `sha256` from the published macOS tarballs (the `.sha256` assets) and push it to the tap
(mirrors the wider release flow). Then `brew install <tap>/spark` installs both binaries and a
root launchd service.

**Debian:** `build-deb.sh` lays out `/usr/bin/spark`, `/usr/sbin/spark-service`, the systemd
unit, and `/etc/spark/config.toml` (a conffile), with `postinst`/`prerm` that reload systemd
and stop/disable on removal. It deliberately avoids `cargo-deb` so the layout is fully explicit.

## macOS app — notarized DMG (Model A, ADR 0005)

The macOS *product* ships as a notarized DMG of the controlling app with the **Network Extension
system extension embedded** (`platforms/apple`), drag-installed to `/Applications` — see
[ADR 0005](../docs/adr/0005-macos-distribution-and-privileged-component.md). The CLI/daemon tarball
(above) remains the Homebrew/enterprise channel.

`packaging/macos/build-tauri-dmg.sh` is the source of truth (the CI job calls it): build the
`SparkCore.xcframework` → `xcodegen` → `xcodebuild archive` → `-exportArchive` with the Developer-ID
`platforms/apple/ExportOptions.plist` → notarize + staple the `.app` → build the DMG (`hdiutil`,
drag-to-`/Applications` layout) → sign + notarize + staple the DMG → verify (`codesign`/`spctl`/
`stapler`).

```bash
# Local dry run — build + sign + DMG + verify, NO notarization (no Apple creds needed):
SKIP_NOTARIZE=1 packaging/macos/build-tauri-dmg.sh      # -> dist/Spark.dmg

# Full run — notarize + staple (pick ONE credential source):
NOTARY_PROFILE=<notarytool-keychain-profile> packaging/macos/build-tauri-dmg.sh
AC_USERNAME=<apple-id> AC_PASSWORD=<app-specific-pw> packaging/macos/build-tauri-dmg.sh
```

**One-time prerequisites** (human; see `platforms/apple/README.md`): the *Developer ID Application*
cert + private key in the keychain, and the portal Developer-ID provisioning profiles **Spark macOS
App** + **Spark macOS Tunnel** installed. The signing identity is resolved to a SHA-1 hash
automatically (override with `SIGN_IDENTITY=<sha1>` if several Developer-ID certs share the keychain).

**CI:** the `package-macos-app` job in `release.yml` runs this on a tag, but is **gated behind the
repo variable `MACOS_APP_PACKAGING=true`** so releases work before signing is set up. Enable it after
adding the repo secrets `MACOS_CERT_P12`/`MACOS_CERT_PASSWORD` (base64 `.p12` + password),
`MACOS_PROFILE_APP`/`MACOS_PROFILE_TUNNEL` (base64 profiles), and `AC_USERNAME`/`AC_PASSWORD`
(notarytool). The job uploads the DMG to the same GitHub Release.

### macOS product DMG (Tauri) — the only macOS DMG

**`packaging/macos/build-tauri-dmg.sh`** builds the **Tauri `gui-tauri` app** as the controlling app
(ADR 0008): it builds the signed system extension via the platforms/apple archive, builds the Tauri
release app, embeds the sysext, re-signs the bundle (hardened runtime, notarizable), then DMG →
notarize+staple → verify.

There is exactly **one** macOS DMG script, deliberately. Two predecessors were removed:

> The Flutter `gui/` controlling-app DMG and its `build-gui-dmg.sh` were removed when Tauri became
> the single cross-platform UI (desktop Win/macOS/Linux + Android + iOS). See `docs/STATE.md`.
>
> `build-dmg.sh` was removed later, for the same reason one step further on. It packaged the
> `platforms/apple` SwiftUI harness — the NE test shell, no product UI — as a DMG, and the release
> workflow still called it, so enabling the gated CI job would have shipped that as the macOS
> product. Its stated use (exercising the sysext in isolation) is still available without it:
> `xcodebuild -project platforms/apple/Spark.xcodeproj -scheme SparkApp` archives the same harness,
> which is exactly what `build-tauri-dmg.sh` does to source the sysext.

## Linux — systemd

```bash
sudo install -m 0755 target/release/spark-service /usr/local/bin/
sudo install -m 0755 target/release/spark         /usr/local/bin/
sudo install -d /etc/spark
sudo install -m 0644 packaging/config.example.toml /etc/spark/config.toml   # then edit
sudo install -m 0644 packaging/systemd/spark.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now spark
```
Set `protect_interface` in `/etc/spark/config.toml` to your egress NIC. By default only root
may drive the daemon; to allow a `spark` group, create it and add `--spark-gid <gid>` to the
unit's `ExecStart`. Drive it with `spark connect|status|disconnect --socket /run/spark/control.sock`.

## macOS — launchd (daemon path: CLI/Homebrew/enterprise)

```bash
sudo install -m 0755 target/release/spark-service /usr/local/bin/
sudo install -m 0755 target/release/spark         /usr/local/bin/
sudo install -d /etc/spark
sudo install -m 0644 packaging/config.example.toml /etc/spark/config.toml   # then edit
sudo install -m 0644 packaging/launchd/org.getlantern.spark.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/org.getlantern.spark.plist
```
The App-Store/GUI macOS form (and iOS) use a NetworkExtension instead of a daemon — that's the
**M10** Apple path, not this. See `docs/process-architecture-and-ipc.md` §4.

## Windows

`spark-service` and `spark` build for Windows; the control channel is an admin-only **named
pipe** (`\\.\pipe\spark`, DACL-restricted to SYSTEM + Administrators — see `service::pipe`).
The release workflow ships a `.zip` of the two `.exe`s + example config.

`spark-service` is a **dual-mode binary**: launched by the Service Control Manager it runs as a
proper Windows service (reports RUNNING, handles STOP/SHUTDOWN; see `service::winsvc`); launched
from a console it runs in the foreground. So you can either run it directly:

```powershell
spark-service.exe --config C:\ProgramData\spark\config.toml   # foreground (dev)
spark.exe connect    # in another (elevated) prompt
```

…or register it as a service with the SCM (the service responds to `sc stop`/`sc start`
correctly now that it implements the control handler):

```powershell
sc.exe create spark binPath= "\"C:\Program Files\spark\spark-service.exe\" --config \"C:\ProgramData\spark\config.toml\"" start= auto
sc.exe start spark
sc.exe stop  spark
```

Or install the **MSI** (`spark-<ver>-x64.msi`, built by the release workflow from
`packaging/windows/spark.wxs` with the `wix` dotnet tool): it drops both binaries into
`Program Files\spark`, registers the `spark` service (LocalSystem, auto-start) via WiX
`ServiceInstall`/`ServiceControl`, and ships the example config as reference. The service is
registered with no config-file argument, so it starts on `Config::default()` — the example is
unix-shaped (`protect_interface = "en0"`) and isn't used as the live config on Windows.

**Still to do (tracked in `docs/STATE.md`):** the MSI hasn't been built on a real WiX toolchain
yet (the `.wxs` is well-formed XML; first build happens in CI). Service logging currently goes to
stderr (discarded under the SCM) — routing to the Windows Event Log or a file is a refinement. A
live run on a real Windows host is also still pending.
