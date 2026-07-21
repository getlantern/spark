<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import {
    MockBackend,
    type SparkBackend,
    type UnboundedStatus,
    type UnboundedPeer,
  } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import { listen } from "@tauri-apps/api/event";
  import Globe from "$lib/Globe.svelte";
  import BottomTabs from "$lib/BottomTabs.svelte";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let status = $state<UnboundedStatus>({ enabled: false, helpingNow: 0, totalHelped: 0, peers: [] });
  let autoEnable = $state(false);
  let showWelcome = $state(false);
  let busy = $state(false);
  // The VPN tab's status dot must reflect the real tunnel state on THIS screen too —
  // switching tabs doesn't disconnect the VPN, so the dot mustn't go grey here.
  let vpnConnected = $state(false);
  let poll: ReturnType<typeof setInterval>;
  let unlistenUnbounded: Promise<() => void> | undefined; // spark://unbounded subscription (Tauri only)

  // The active peer list, kept live from status. Task 6.1 binds this into <Globe {peers} />.
  const peers = $derived<UnboundedPeer[]>(status.peers);

  async function refresh() {
    try { status = await backend.unboundedStatus(); } catch { /* keep last-known */ }
    try { vpnConnected = (await backend.status()).state === "connected"; } catch { /* keep last-known */ }
  }

  async function toggle() {
    if (busy) return;
    busy = true;
    try {
      if (status.enabled) {
        await backend.unboundedStop();
      } else {
        await backend.unboundedStart();
      }
      await refresh();
    } catch { /* leave the toggle reflecting the last-known status */ } finally {
      busy = false;
    }
  }

  async function toggleAutoEnable() {
    const prev = autoEnable;
    autoEnable = !autoEnable;
    try {
      await backend.unboundedSetSettings({ autoEnable });
    } catch {
      autoEnable = prev;
    }
  }

  async function dismissWelcome() {
    showWelcome = false;
    try { await backend.unboundedSetSettings({ welcomeSeen: true }); } catch { /* best-effort */ }
  }

  onMount(() => {
    refresh();
    (async () => {
      try {
        const settings = await backend.unboundedGetSettings();
        autoEnable = settings.autoEnable;
        showWelcome = !settings.welcomeSeen;
      } catch { /* keep defaults */ }
    })();
    poll = setInterval(refresh, 2000);
    // Keep the stats live between polls: the plugin emits spark://unbounded with the full status
    // shape on every peer/enable change. Tauri-only (`listen` rejects in a plain browser), matching
    // the home screen's guard.
    if (isTauri()) {
      unlistenUnbounded = listen<UnboundedStatus>(
        "spark://unbounded",
        (e) => (status = e.payload),
      );
    }
  });
  onDestroy(() => {
    clearInterval(poll);
    unlistenUnbounded?.then((f) => f()).catch(() => {});
  });
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("menu")} onclick={() => goto("/settings")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
    </button>
    <span class="title">{$_("unbounded_title")}</span>
    <span class="iconbtn spacer" aria-hidden="true"></span>
  </header>

  <div class="scroll">
    <div class="banner">
      <span class="ic" aria-hidden="true">ⓘ</span>
      <p>{$_("unbounded_help_banner")}</p>
    </div>

    <div class="globe-mount">
      <Globe {peers} />
    </div>

    <div class="card">
      <div class="row toggle-row">
        <span class="ic">{@render globeIcon()}</span>
        <div class="meta">
          <div class="name">{$_("unbounded_status")}: <span class="state" class:on={status.enabled}>{status.enabled ? $_("unbounded_state_enabled") : $_("unbounded_state_disabled")}</span></div>
        </div>
        <button class="switch" class:on={status.enabled} role="switch" aria-checked={status.enabled} aria-busy={busy} aria-label={$_("unbounded_status")} onclick={toggle}><span class="knob"></span></button>
      </div>
      <div class="divider"></div>
      <div class="row stat-row">
        <span class="ic">{@render personIcon()}</span>
        <div class="meta"><div class="name">{$_("unbounded_helping_now")}</div></div>
        <span class="stat">{status.helpingNow}</span>
      </div>
      <div class="divider"></div>
      <div class="row stat-row">
        <span class="ic">{@render peopleIcon()}</span>
        <div class="meta"><div class="name">{$_("unbounded_total_helped")}</div></div>
        <span class="stat">{status.totalHelped}</span>
      </div>
    </div>

    <div class="card" style="margin-top:12px">
      <div class="row toggle-row">
        <span class="ic">{@render autoIcon()}</span>
        <div class="meta">
          <div class="name">{$_("unbounded_auto_enable")}</div>
          <div class="sub">{$_("unbounded_auto_enable_sub")}</div>
        </div>
        <button class="checkbox" class:on={autoEnable} role="checkbox" aria-checked={autoEnable} aria-label={$_("unbounded_auto_enable")} onclick={toggleAutoEnable}>
          {#if autoEnable}<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>{/if}
        </button>
      </div>
    </div>
  </div>

  <BottomTabs current="unbounded" vpnOn={vpnConnected} unboundedOn={status.enabled} />
</main>

{#snippet globeIcon()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></svg>
{/snippet}
{#snippet personIcon()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.2"/><path d="M5.5 20a6.5 6.5 0 0 1 13 0"/></svg>
{/snippet}
{#snippet peopleIcon()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3"/><path d="M2.5 19a6.5 6.5 0 0 1 13 0"/><path d="M16 5.5a3 3 0 0 1 0 5.8"/><path d="M18 19a6 6 0 0 0-3.2-5.3"/></svg>
{/snippet}
{#snippet autoIcon()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11.4A8 8 0 1 0 18 17.5"/><polyline points="20 4 20 9.5 14.5 9.5"/><path fill="currentColor" stroke="none" d="M11 7.4 11.85 9.65 14.1 10.5 11.85 11.35 11 13.6 10.15 11.35 7.9 10.5 10.15 9.65Z"/></svg>
{/snippet}

{#if showWelcome}
  <div class="overlay" role="dialog" aria-modal="true" aria-labelledby="unbounded-welcome-title">
    <div class="dialog">
      <h2 id="unbounded-welcome-title">{$_("unbounded_welcome_title")}</h2>
      <p>{$_("unbounded_welcome_body")}</p>
      <button class="primary" onclick={dismissWelcome}>{$_("unbounded_welcome_dismiss")}</button>
    </div>
  </div>
{/if}

<style>
  .app { height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  .appbar {
    height: 56px; flex-shrink: 0; display: flex; align-items: center; gap: 4px; padding: 0 8px;
    background: var(--bg);
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  .spacer { visibility: hidden; }
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  /* Centered, bold, uppercase title flanked by the menu button + an equal-width spacer. */
  .title {
    flex: 1; text-align: center; font-size: 20px; font-weight: 800; letter-spacing: 1px;
    text-transform: uppercase; color: var(--text-primary);
  }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }

  .banner { display: flex; gap: 12px; align-items: flex-start; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; }
  .banner .ic { color: var(--text-tertiary); }
  .banner p { margin: 0; font-size: 14px; font-weight: 500; line-height: 1.4; color: var(--text-secondary); }

  /* The globe is the hero of the screen — it floats directly on the page background (no card),
     tall and centered, matching the design. */
  .globe-mount {
    margin-top: 4px;
    height: 330px;
    overflow: hidden;
  }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden; margin-top: 12px;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px 16px;
    background: none; border: none; font-family: var(--font); text-align: start;
  }
  .toggle-row, .stat-row { justify-content: space-between; }
  .row .ic { width: 24px; display: inline-flex; justify-content: center; color: var(--text-secondary); flex-shrink: 0; }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  /* "Status: Enabled" — the state word turns green when sharing is on. */
  .state { font-weight: 700; color: var(--text-tertiary); }
  .state.on { color: #2fa84f; }
  .sub {
    margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary);
    letter-spacing: 0.01em;
  }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  /* Stat values: prominent teal numbers, right-aligned (no pill). */
  .stat { font-size: 16px; font-weight: 800; color: #1a8a9c; white-space: nowrap; }

  .switch {
    width: 46px; height: 28px; border-radius: 999px; border: none; background: var(--switch-off);
    position: relative; cursor: pointer; transition: background 0.15s ease; flex-shrink: 0;
  }
  /* Enabled state is green per the design (not the app brand cyan). */
  .switch.on { background: #34b759; }
  .knob {
    position: absolute; top: 3px; left: 3px; width: 22px; height: 22px;
    border-radius: 50%; background: #fff; transition: transform 0.15s ease;
  }
  .switch.on .knob { transform: translateX(18px); }

  /* Auto-enable is a checkbox in the design, not a switch: an outlined square that fills
     dark-teal with a white check when on. */
  .checkbox {
    width: 26px; height: 26px; flex-shrink: 0; border-radius: 7px; cursor: pointer;
    display: grid; place-items: center; color: #fff;
    background: transparent; border: 1.5px solid var(--border);
    transition: background 0.15s ease, border-color 0.15s ease;
  }
  .checkbox.on { background: #0e5563; border-color: #0e5563; }

  /* One-time onboarding dialog, styled off the app's surface/card tokens. */
  .overlay {
    position: fixed; inset: 0; z-index: 10;
    display: grid; place-items: center; padding: 24px;
    background: rgba(0, 0, 0, 0.45);
  }
  .dialog {
    width: 100%; max-width: 340px;
    background: var(--surface); border-radius: 16px; padding: 24px;
    box-shadow: 0 12px 48px rgba(0, 0, 0, 0.35);
  }
  .dialog h2 { margin: 0 0 10px; font-size: 20px; font-weight: 700; color: var(--text-primary); }
  .dialog p { margin: 0 0 20px; font-size: 14px; font-weight: 500; line-height: 1.5; color: var(--text-secondary); }
  .primary {
    width: 100%; padding: 12px 16px; border: none; border-radius: 10px; cursor: pointer;
    background: var(--brand, #1f9d55); color: #fff; font-family: var(--font);
    font-size: 15px; font-weight: 600;
  }
</style>
