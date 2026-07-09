# Windows on-device validation checklist

Everything in the Windows Spark stack (W1–W4) is built **code-complete + cross-compiled
(`x86_64-pc-windows-msvc`) + host-unit-tested**, but **none of the runtime behavior is validated on a
real Windows machine** — the macOS dev host and PR CI can't exercise the SCM, WinTun, `route.exe`/
`netsh`, or the GUI↔service named pipe. This checklist is that validation. Run it on a real Windows 10/11
box (ideally a VM you can snapshot) after installing a build produced by the W4 release workflow.

Prereqs: a Windows build with the MSI (installs `spark-service` + `wintun.dll`, W4) and the Tauri GUI;
a working `config_raw.json` / profile the service can connect with. Take a VM snapshot first — routing
and DNS changes are system-wide.

## 1. Install + service registration (W4 MSI, W2c transport)
- [ ] Install the MSI. `sc query spark` (or Services.msc) shows **spark** as **Running**, LocalSystem, auto-start.
- [ ] `wintun.dll` is present next to `spark-service.exe` in `C:\Program Files\spark\`.
- [ ] Event Log / `spark-service` logs show it started and is listening on `\\.\pipe\spark`.
- [ ] The service can be stopped/started via SCM (`sc stop spark` / `sc start spark`) cleanly (winsvc.rs).

## 2. GUI ↔ service control plane (W3 + the Option-A pipe DACL)
- [ ] Launch the Tauri GUI **without elevation** (as the normal logged-in user).
- [ ] The GUI shows a real status (not an error) — confirms the unprivileged GUI can open the
      admin+`IU` pipe (the widened `CONTROL_PIPE_SDDL`). **If it shows "service ipc" / access-denied,
      the `IU` access mask in `pipe.rs` is wrong — try `FRFW` (targeted file read/write) first. `FA`
      (full access) is only a temporary diagnostic to confirm it's a mask problem; do NOT ship `FA` —
      it's far broader than needed.**
- [ ] Status polling (~2s) works steadily with no errors; the service log shows the connections.

## 3. Connect → tunnel up (W1 routing + W2a params + W2b loop-prevention)
- [ ] Click **Connect**. The GUI goes Connecting → Connected.
- [ ] `route print` shows the split-default covers `0.0.0.0 mask 128.0.0.0` and `128.0.0.0 mask 128.0.0.0`
      via the WinTun adapter's interface index (W1 + W2a `with_windows_params`).
- [ ] `netsh interface ipv4 show dnsservers` shows the WinTun adapter's DNS pointed at the tunnel
      resolver (the tun's IPv4) (W1 netsh DNS).
- [ ] Real traffic flows through the tunnel: browse / `curl https://ifconfig.me` shows the exit IP, not
      the local one. This exercises the whole data path **and** loop-prevention (W2b) — if the proxy's
      own dials weren't pinned to the physical NIC (`IP_UNICAST_IF`), connect would hang/loop.
- [ ] DNS resolves through the tunnel (no leak): `nslookup` / a DNS-leak test shows the tunnel resolver.

## 4. Kill-switch / fail-closed (W1 blackhole)
- [ ] While connected, simulate a data-path drop (e.g. kill the upstream / stop connectivity). The
      kill-switch should **blackhole** rather than leak: traffic stops (fail-closed), not fall back to direct.
- [ ] The GUI reflects the failure state.

## 5. Disconnect + uninstall (W1 restore)
- [ ] Click **Disconnect**. `route print` shows the covers removed and the physical default route
      restored; `netsh … show dnsservers` shows the adapter back to DHCP. Traffic is direct again.
- [ ] Uninstall the MSI. The `spark` service is stopped + removed (`sc query spark` → not found);
      `wintun.dll` + binaries removed.

## Notes for whoever runs this
- The pipe DACL is **Option A** (interactive user granted connect). If §2 fails with access-denied, the
  `IU` mask is the first suspect (see `service/src/pipe.rs` module doc).
- `route.exe`/`netsh` argv + the tun ifindex form were only cross-compiled, never run — §3 is their
  first real exercise. Capture exact errors (with `route print` before/after) if anything misbehaves.
- File findings back into the relevant milestone (W1/W2/W3) — these are the deferred-validation items
  called out in each merged PR.
