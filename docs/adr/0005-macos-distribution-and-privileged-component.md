# ADR 0005 — macOS distribution & the privileged-component model

- **Status:** Proposed — 2026-06-18. Research + recommendation for review. Decides how the macOS
  *product* ships (notarized release) and, by consequence, which privileged-component model the
  macOS GUI drives. Does not change Linux/Windows (daemon) or the CLI/Homebrew channel.
- **Scope:** macOS only. How the tunnel runs with privilege, how it's delivered + notarized, and how
  the Flutter GUI controls it. Extends `docs/process-architecture-and-ipc.md` §"macOS — two
  distribution paths" with researched specifics and a decision.
- **Prompted by:** the request to "create a release build that's notarized and everything," and the
  follow-up to compare **an app bundle containing the system extension (DMG install)** vs **a `.pkg`
  install with launchd**.

## TL;DR

The real question is **which privileged component runs the tunnel**, not "DMG vs pkg" — because the
modern `SMAppService` (macOS 13+) lets the *daemon* model also ship in a drag-installed app bundle,
so **both** live options are DMG-deliverable and `.pkg` is only the legacy daemon-install fallback.

- **Model A — Network Extension *system extension*, embedded in the app, DMG install.** This is
  **already built, Developer-ID-signed, notarized, and live-gated** (`platforms/apple`, M10
  2026-06-16). Apple-idiomatic; OS-managed; no always-on root daemon.
- **Model B — privileged `launchd` daemon** (`spark-service`), via `SMAppService` (DMG) or a `.pkg`.
  This is the cross-platform daemon model that the **`FrbBackend` + `spark-bridge` we just built**
  already talks to over `/var/run/spark.sock`.

**Recommendation: Model A for the macOS consumer product**; keep the daemon model (+ `FrbBackend`)
for **Linux/Windows desktop** and the **CLI/Homebrew/enterprise** channel. This matches the doc's
"pick one path per distribution channel" and reuses the work already done on both sides. The cost is
explicit: the macOS GUI's backend becomes a NetworkExtension adapter, **not** `FrbBackend` (see
Consequences).

## Context

spark already has two privileged-component implementations, one per model:

1. **`platforms/apple/` — a Network Extension system extension.** The data path runs *inside* the
   sysext via the fd-trick (`spark_tunnel_run(fd, mtu)` → `spark-core::fd_tunnel`). It is a
   `*.systemextension` (not an NE app-extension), signed manual *Developer ID Application* under team
   `ACZRKC3LQ9`, **notarized and live-gated** on macOS (default route → utun → netstack → forwarder →
   internet, 2026-06-16). The recipe (archive → `notarytool` → `stapler` → `/Applications` → approve)
   is documented and works.
2. **`spark-service` — a privileged process** owning the tun + routes, with the `spark-ipc` control
   protocol over a unix socket. The desktop **Flutter GUI's `FrbBackend`** (via the `spark-bridge`
   frb crate, built 2026-06-18) drives exactly this. On Linux this is a `systemd` daemon; on macOS it
   would be a `launchd` daemon.

A non-App-Store (Developer ID) constraint forces the shape of Model A: **NE app-extensions are
App-Store-only; outside the App Store you must use a *system extension*** ([Tailscale][ts]). spark
already did this correctly.

## Reframing: "DMG vs pkg" → "which privileged component"

| Privileged component | Modern delivery | Legacy delivery |
|---|---|---|
| NE **system extension** (Model A) | **DMG** → drag to `/Applications`; app activates via `OSSystemExtensionManager` | (n/a) |
| **launchd daemon** (Model B) | **`SMAppService.daemon`** (macOS 13+): daemon bundled in the app, **DMG** install, `register()` from the app | **`.pkg`**: daemon + `/Library/LaunchDaemons` plist, `postinstall` loads it |

So a `.pkg` is **not required** for the daemon model anymore. `SMAppService` ([Apple][sm]) registers a
LaunchDaemon whose plist lives in the app's `Contents/Library/LaunchDaemons` and whose executable is a
bundle-relative `BundleProgram` — drag-installed, no installer. The `.pkg` path remains useful only
for enterprise/MDM mass-deploy or pre-macOS-13 support.

## The two models, concretely for spark

### Model A — NE system extension, DMG
- **Tunnel:** runs in the `SparkTunnel` sysext (already built). The Flutter `spark_gui` app becomes
  the **controlling app**: embeds `SparkTunnel.systemextension` in `Contents/Library/SystemExtensions`,
  activates it via `OSSystemExtensionManager`, and drives it with `NETunnelProviderManager` +
  `NETunnelProviderSession.sendProviderMessage`.
- **GUI ↔ tunnel control:** a Swift **platform channel** under a `SparkBackend` Dart impl
  (`NEBackend`), reusing the `ipc/` message enum as the `sendProviderMessage` payload (per the
  process-arch doc). **Not** `FrbBackend`/`spark-ipc`/unix-socket.
- **Delivery:** DMG. App must be in `/Applications` or activation fails
  (`unsupportedParentBundleLocation` [Apple][ext]). Auto-uninstalls the sysext when the app is deleted.

### Model B — launchd daemon (SMAppService or pkg)
- **Tunnel:** `spark-service` as a root `launchd` daemon owning a `utun` (the `sudo spark-service`
  path already live-gated on macOS at M7). No system extension.
- **GUI ↔ daemon control:** **`FrbBackend` → `spark-bridge` → `spark-ipc`** over the socket (built,
  runtime-verified). The doc prefers **XPC with peer code-signing** over a raw unix socket on macOS
  for the authz check — a hardening delta if we go this way.
- **Delivery:** DMG via `SMAppService` (daemon in the app bundle), or a `.pkg`.

## Comparison

| Dimension | Model A — NE sysext (DMG) | Model B — launchd daemon (SMAppService/pkg) |
|---|---|---|
| **Already built for spark** | ✅ sysext built, notarized, **live-gated** | ✅ daemon live-gated at M7; `FrbBackend` built + runtime-verified |
| **GUI backend reuse** | ❌ needs a new NE/platform-channel adapter; `FrbBackend` unused on macOS | ✅ reuses `FrbBackend`/`spark-bridge` directly |
| **Privilege model** | OS-managed sysext; no persistent root daemon we own | **always-on root daemon** = larger attack surface (cf. Mullvad's repeated audits) |
| **Routing / tun** | OS provides the tunnel context (NEPacketTunnelProvider) | we manage `utun` + routes ourselves (manual route restore, kill-switch) |
| **Idiomatic / precedent** | ✅ the standard non-App-Store consumer-VPN model (Tailscale standalone [ts]) | daemon model (Mullvad, Cloudflare WARP [wp]) — common but heavier |
| **Signing certs** | Developer ID Application + hardened runtime; staple the DMG | **also** needs a **Developer ID *Installer*** cert for a `.pkg` ([Apple][ns]); SMAppService avoids that but still needs Developer ID Application on the daemon |
| **Notarization** | notarize app, staple DMG (already proven) | notarize daemon **and** the `.pkg` separately (no recursion); SMAppService notarizes the one app |
| **First-run UX** | sysext approval (System Settings → *Login Items & Extensions* on macOS 15+) **+** VPN-config consent — two gates; 30-min approval window; sometimes a reboot | `.pkg`: admin password at install. `SMAppService`: `register()` → admin auth + approval buried in Login Items |
| **Update** | bump `CFBundleVersion`, app relaunch re-activates; can need a reboot (`willCompleteAfterReboot`) | replace app (SMAppService) / new `.pkg`; daemon restart |
| **Uninstall** | ✅ delete app → sysext auto-removed | ❌ `.pkg` has **no native uninstall** (ship a script); SMAppService `unregister()` is clean |
| **App Store future** | ✅ sysext provider code is reusable for an App-Store NE app-extension build later | ❌ daemon model can't go to the App Store |
| **OS-version risk** | ⚠️ macOS 26 (Tahoe) has a **live, unresolved** sysext-activation regression (multiple 2026 forum reports) | `SMAppService` Login-Items discoverability + a Ventura disable bug; less severe |

## Decision (recommended)

**Ship the macOS consumer product as Model A** — the Flutter GUI as the controlling app embedding the
already-notarized `SparkTunnel` system extension, delivered as a **notarized, stapled DMG**. **Retain
Model B** (`spark-service` daemon + `FrbBackend`) for **Linux and Windows desktop** and for the
**CLI / Homebrew / enterprise** macOS channel.

Why A for the product:
1. **Lowest remaining risk:** the sysext is built, signed, notarized, and live-gated. We extend proven
   work rather than stand up a new root-daemon install path.
2. **Right privilege posture for a VPN:** OS-managed extension, no persistent root daemon of ours to
   secure/audit; OS provides the tunnel + routing context (no manual route restore on macOS).
3. **Industry norm** for non-App-Store consumer VPNs (Tailscale standalone is exactly this [ts]).
4. **Cleaner lifecycle:** DMG drag-install; delete-to-uninstall (vs the `.pkg` no-uninstall wart).
5. **Future-proofs the App Store**: the NEPacketTunnelProvider code ports to an App-Store NE
   app-extension build with the same core.

When Model B would win instead (decision inputs for the reviewer): if **cross-platform GUI uniformity
and reusing `FrbBackend` on macOS** outweigh Apple-idiomaticity, ship Model B via `SMAppService`
(still DMG-installable). It maximizes code reuse and gives one control path across all desktops, at the
cost of an always-on root daemon, manual route management, no App-Store path, and the macOS-specific
XPC-authz work.

## Consequences

- **The macOS GUI backend is a NetworkExtension adapter, not `FrbBackend`.** We add a `SparkBackend`
  Dart impl backed by a Swift platform channel (`NETunnelProviderManager` + `sendProviderMessage`),
  reusing the `ipc/` message enum as the payload. `FrbBackend`/`spark-bridge` remain the
  **Linux/Windows** desktop backend (and were the fastest path to a working GUI) — not wasted, but
  **not the macOS production path**. The `SparkBackend` seam is exactly what makes this swap clean.
- **Integration work (new):** make the Flutter `spark_gui` app the controlling app that embeds
  `SparkTunnel.systemextension`, runs the `OSSystemExtensionRequest` activation flow, and exposes the
  NE control surface to Dart. Today `platforms/apple` has a *SwiftUI* harness app; that role moves to
  the Flutter app (or the harness stays for the sysext and Flutter wraps it — to be designed).
- **Packaging (the original ask):** a `packaging/macos/` script (source of truth, also called by CI —
  per the chosen "both" answer) that does `flutter build macos --release` of the controlling app with
  the embedded sysext → archive/export with the Developer-ID `ExportOptions.plist` → DMG
  (`create-dmg`/`hdiutil`) → `notarytool submit --wait` → `stapler staple` → `spctl` verify. Reuses
  the `platforms/apple` recipe. The app ships **unsandboxed + hardened runtime** (the chosen entitlement
  posture; sysext entitlements already sandbox-off, hardened runtime satisfies notarization).
- **Manual prerequisites (one-time, human):** the Developer-ID provisioning profiles already noted in
  `platforms/apple/README.md` (`Spark macOS App`, `Spark macOS Tunnel`), plus notarization creds
  (`AC_USERNAME`/`AC_PASSWORD`) as local env / CI secrets. No notarytool profile is stored on this box.
- **OS-version watch item:** validate against macOS 26 (Tahoe) given the open sysext-activation
  regression before declaring GA there.

## Verify at implementation time (Apple specifics drift)

- `OSSystemExtensionManager` `/Applications` requirement + activation/replacement delegate flow.
- `SMAppService.daemon` plist location (`Contents/Library/LaunchDaemons`) + `BundleProgram` (only if B).
- Developer ID **Installer** cert is required for a `.pkg`, distinct from Developer ID Application
  (only if B via pkg).
- macOS-15 approval-pane rename (*Login Items & Extensions*) and the macOS-26 activation regression.

## References

- [ts]: Tailscale — standalone macOS variant uses a system extension; NE app-extension is App-Store-only
  while generic system extensions are for non-App-Store apps. https://tailscale.com/blog/standalone-macos ,
  https://tailscale.com/kb/1065/macos-variants
- [ext]: Apple — Installing System Extensions and Drivers (`/Applications` requirement;
  ship-in-app-bundle; auto-uninstall on delete).
  https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers ;
  `unsupportedParentBundleLocation`.
- [sm]: Apple — `SMAppService` / `SMAppService.daemon(plistName:)` (macOS 13+); updating helper
  executables (`BundleProgram`, authorization). https://developer.apple.com/documentation/servicemanagement/smappservice
- [ns]: Apple — Notarizing macOS software; resolving notarization issues (Developer ID **Installer**
  for `.pkg`). https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- [wp]: Cloudflare WARP macOS (privileged service via `.pkg`).
  https://developers.cloudflare.com/warp-client/get-started/macos/
- spark internal: `platforms/apple/README.md` (sysext build/notarize recipe, live gate),
  `docs/process-architecture-and-ipc.md` §"macOS — two distribution paths", `docs/STATE.md` (M10).
