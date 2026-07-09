# W4 packaging — ready-to-apply workflow patches (maintainer)

These are the W4 packaging changes that the **workflow-edit security hook blocks** from being applied
by the agent tooling (any `.github/workflows/*` edit). They are injection-free (all `${{ }}` values go
through `env:`, never inlined into `run:`). A maintainer applies them by hand, then validates the
build/packaging via a `release.yml` **`workflow_dispatch`** dry-run. Install + tunnel remain on-device
(`docs/windows-on-device-validation.md`).

Companion work already landed / in flight:
- **Task 3 (plugin CI job)** — applied in `ci.yml` (PR #72).
- **Task 0 (DACL)** — done in #64.
- The `spark.wxs` wintun component below is **coupled** to the `release.yml` wintun step (the MSI
  references `$(var.BinDir)\wintun.dll`, which the workflow places), so apply BOTH together.

---

## Patch 1 — `packaging/windows/spark.wxs`: install `wintun.dll`

Add the component (after the `SparkService` component, before `ConfigExample`):

```xml
        <!-- The WinTun redistributable DLL, loaded at runtime by the service (via tun-rs) to open
             the tunnel adapter, so it must sit next to spark-service.exe. Not committed to the repo:
             the release workflow downloads the official signed zip, verifies its SHA-256, and places
             wintun.dll (amd64) in BinDir before this MSI is built. -->
        <Component Id="WinTun">
          <File Id="wintun.dll" Source="$(var.BinDir)\wintun.dll" KeyPath="yes" />
        </Component>
```

And reference it in the `Main` feature:

```xml
      <ComponentRef Id="WinTun" />
```

---

## Patch 2 — `release.yml`: fetch WinTun (Task 1)

In the `build` job's steps, right **after** `- name: Build release`, add (Windows-only):

```yaml
      # WinTun ships as a signed redistributable DLL (not committed); the service loads it at runtime
      # via tun-rs, so it must sit next to spark-service.exe. Download the official zip, verify its
      # pinned SHA-256, and drop the amd64 DLL into the bindir for the zip + MSI steps below.
      - name: Fetch WinTun (Windows)
        if: matrix.os == 'windows'
        shell: pwsh
        env:
          TARGET: ${{ matrix.target }}
        run: |
          $ver = "0.14.1"
          $sha = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
          $zip = "$env:RUNNER_TEMP\wintun.zip"
          Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-$ver.zip" -OutFile $zip
          $got = (Get-FileHash -Algorithm SHA256 $zip).Hash
          if ($got -ne $sha) { throw "WinTun SHA-256 mismatch: got $got, expected $sha" }
          Expand-Archive -Path $zip -DestinationPath "$env:RUNNER_TEMP\wintun" -Force
          Copy-Item "$env:RUNNER_TEMP\wintun\wintun\bin\amd64\wintun.dll" `
            "target/$env:TARGET/release/wintun.dll"
```

(SHA-256 verified against the official `wintun-0.14.1.zip`; amd64 DLL is at `wintun/bin/amd64/wintun.dll`.)

Then add `wintun.dll` to the zip artifact — in the `Package zip (Windows)` step, change the `$items`
line to include it:

```powershell
          $items = @("$bindir/spark.exe", "$bindir/spark-service.exe", "$bindir/wintun.dll", "$bindir/config.example.toml")
```

---

## Patch 3 — `release.yml`: build the Tauri GUI for Windows (Task 2)

Add a new job (put it after `package-macos-app`, before `publish`). Tauri's `bundle.targets: "all"`
produces both NSIS `.exe` and WiX `.msi`. The GUI installer is **separate** from the service MSI
(Patch 1/2): the service MSI is the privileged installer (LocalSystem service + wintun); the Tauri
installer is the unprivileged app. Both are required on a box — document that in the release notes.

```yaml
  package-windows-app:
    name: package Windows app (NSIS + MSI)
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-msvc
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Install frontend deps
        working-directory: gui-tauri
        run: npm ci
      # `tauri build` runs the `beforeBuildCommand` (npm run build) to build the SvelteKit frontend,
      # compiles the app + the tauri-plugin-spark-vpn workspace, and bundles NSIS + MSI.
      - name: Build Tauri app (NSIS + MSI)
        working-directory: gui-tauri
        run: npm run tauri build -- --target x86_64-pc-windows-msvc
      - name: Upload Windows app artifacts
        uses: actions/upload-artifact@v4
        with:
          name: spark-windows-app
          path: |
            gui-tauri/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/*.exe
            gui-tauri/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/msi/*.msi
```

Then wire it into `publish` so its artifacts are released — change:

```yaml
    needs: [build, package-macos-app]
```
to:
```yaml
    needs: [build, package-macos-app, package-windows-app]
```
(The `publish` step already downloads all run artifacts with `merge-multiple: true` and uploads
`dist/*`, so no other change is needed. `if: always() && needs.build.result == 'success'` still gates
on the core build; the Windows app job has no signing gate, so it always runs.)

---

## Validate (Task 4)

After applying Patches 1–3, trigger a `release.yml` **`workflow_dispatch`** dry-run (it uses the branch
name as the version; no real release is published unless pushed on a `v*` tag). Confirm on the
`windows-latest` legs:
1. **Fetch WinTun** downloads + SHA-verifies + places `wintun.dll`.
2. **Build MSI** succeeds with the new `WinTun` component (fails loudly if `wintun.dll` is missing).
3. **package-windows-app** produces an NSIS `.exe` + an MSI under the bundle path and uploads them.

Expect 1–2 iterations for the Tauri Windows build (first-time NSIS/WiX toolchain quirks). Signing the
Windows installers (Authenticode) is a separate, later concern — the dry-run validates the *unsigned*
build/packaging only.

## Remaining after this
- **Task 5** — on-device validation of the whole W1–W4 stack (`docs/windows-on-device-validation.md`).
- The three hardening items in `core/src/routing.rs` flagged in that checklist (gateway form, blackhole
  null-route, fail-closed leak window — PR #71) confirm during Task 5.
