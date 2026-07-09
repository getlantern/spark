# Windows Support — Autonomous Goal Prompt

GOAL: Ship Windows support for Spark autonomously (user is asleep). Repo:
/Users/afisk/go/src/github.com/getlantern/spark-app-split-tunneling (host: macOS).
Approved design: docs/superpowers/specs/2026-07-09-windows-support-design.md.
Progress log: docs/superpowers/windows-progress.md (update after every step).

WHAT: Make the Windows Tauri app a working VPN using the SAME tauri-plugin-spark-vpn and the SAME
Tauri GUI that macOS/Android use — implement the plugin's desktop ServiceControl as the real
named-pipe IPC client (do NOT invent a parallel mechanism). An MSI-installed LocalSystem
spark-service owns WinTun + routes + spark-core; the unprivileged GUI drives it over an
SDDL-hardened named pipe using the existing `ipc` crate.

MILESTONES (one PR each, in order):
- W1 core Windows RouteManager (core/src/routing.rs, cfg windows): route.exe split-default covers
  (0.0.0.0/1 + 128.0.0.0/1), proxy-IP bypass, netsh adapter DNS, route-blackhole kill-switch;
  unit-test by asserting emitted commands. Confirm tun-rs WinTun.
- W2 live spark-service: real TunnelEngine (WinTun up -> W1 routes -> run core), pipe.rs named-pipe
  accept + SDDL, winsvc.rs SCM, auth.rs Windows peer authz. Unit-test over in-memory duplex.
- W3 tauri-plugin-spark-vpn ServiceControl -> real named-pipe ipc client (connect/disconnect/status/
  routing-mode/ad-block/split-tunnel/servers + Push). Same plugin macOS/Android use.
- W4 Windows Tauri build (NSIS+MSI) in release.yml; MSI bundles wintun.dll + registers/starts
  spark-service (WiX service element) + pipe SDDL; add windows-latest CI unit-test job; write
  docs/windows-on-device-validation.md manual checklist.

PER-MILESTONE WORKFLOW:
1. Branch off latest origin/main (fisk/windows-W#-<slug>); the W1 PR also carries the spec + this
   goal prompt + the progress log. Rebase onto main after each merge (main advances per PR).
2. superpowers:writing-plans -> save plan. Then superpowers:subagent-driven-development (fresh
   subagent per task, spec-compliance + code-quality review between). Strict TDD.
3. Gate EVERY task: cargo fmt --all --check; cargo clippy --all-targets --target
   x86_64-pc-windows-msvc -D warnings AND host clippy; cargo test (WHOLE workspace — cli+service
   depend on core); for gui-tauri changes, npm test + npm run check. (Install the windows target
   once: rustup target add x86_64-pc-windows-msvc.)
4. Open PR (title ends " (#NN)" squash style). Body: summary + test plan; mermaid sequenceDiagram
   when call flow crosses layers. State clearly that on-Windows runtime is NOT validated (macOS host).
5. Run the review-pr skill: request Copilot + ensure CodeRabbit; VERIFY each comment before acting;
   fix or push back with rationale; reply then resolve threads; re-request; loop until a clean round
   or ~4 rounds. Background-poll (run_in_background bash) for reviews + CI; ScheduleWakeup for longer
   idle waits.
6. Merge (gh pr merge --squash) when: review converged AND all CI green AND 0 unresolved threads.
   Then next milestone.

CONSTRAINTS:
- Deliver code-complete + cross-compiles (x86_64-pc-windows-msvc) + unit-tested. NEVER claim
  on-Windows verification; note the deferral in each PR.
- Never commit secrets (/Users/Shared/Lantern/config_raw.json). Never git add -A/. (untracked
  src-tauri/target). Branch first. Commit trailer: Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>.
- No new crates unless necessary; prefer route.exe/netsh shell-out + tokio named_pipe + the
  windows-service pattern already in service/.
- If GENUINELY blocked (a decision only the user can make, a design contradiction, or CI you can't
  fix after 3 tries), STOP: write the blocker + options to windows-progress.md and wait — do NOT guess.

CADENCE: proceed W1->W2->W3->W4 without waiting for the user. Between PRs, keep going. After all four
merge, update windows-progress.md with a final summary + the deferred on-Windows validation checklist
status, and stop.
