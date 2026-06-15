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
| `x86_64-pc-windows-msvc` (Windows) | `spark-core` + `spark-ipc` cross-check clean; the control transport (`UnixListener`/`UnixStream`) still needs a Windows **named-pipe** port before `spark-service`/`spark` build there |

Verify a target yourself with e.g. `cargo check --workspace --all-features --target x86_64-unknown-linux-gnu`.

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

`spark-service` needs a named-pipe control transport (the unix-socket listener is unix-only)
before it runs on Windows; the SCM service wrapper + MSI follow once that lands. Tracked as the
Windows item in `docs/STATE.md`.
