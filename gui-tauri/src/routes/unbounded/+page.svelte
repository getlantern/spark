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

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let status = $state<UnboundedStatus>({ enabled: false, helpingNow: 0, totalHelped: 0, peers: [] });
  let autoEnable = $state(false);
  let showWelcome = $state(false);
  let busy = $state(false);
  let poll: ReturnType<typeof setInterval>;
  let unlistenUnbounded: Promise<() => void> | undefined; // spark://unbounded subscription (Tauri only)

  // The active peer list, kept live from status. Task 6.1 binds this into <Globe {peers} />.
  const peers = $derived<UnboundedPeer[]>(status.peers);

  async function refresh() {
    try { status = await backend.unboundedStatus(); } catch { /* keep last-known */ }
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
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("unbounded_title")}</span>
  </header>

  <div class="scroll">
    <div class="banner">
      <span class="ic" aria-hidden="true">ⓘ</span>
      <p>{$_("unbounded_help_banner")}</p>
    </div>

    <!-- TODO(Task 6.1): mount <Globe {peers} /> here -->
    <div class="globe-placeholder">
      <span class="sphere" aria-hidden="true"></span>
      <span class="ph-label">{$_("unbounded_globe_placeholder")}</span>
    </div>

    <div class="card">
      <div class="row toggle-row">
        <div class="meta"><div class="name">{$_("unbounded_status")}</div></div>
        <button class="switch" class:on={status.enabled} role="switch" aria-checked={status.enabled} aria-busy={busy} aria-label={$_("unbounded_status")} onclick={toggle}><span class="knob"></span></button>
      </div>
      <div class="divider"></div>
      <div class="row stat-row">
        <div class="meta"><div class="name">{$_("unbounded_helping_now")}</div></div>
        <span class="pill">{status.helpingNow}</span>
      </div>
      <div class="divider"></div>
      <div class="row stat-row">
        <div class="meta"><div class="name">{$_("unbounded_total_helped")}</div></div>
        <span class="pill">{status.totalHelped}</span>
      </div>
    </div>

    <div class="card" style="margin-top:12px">
      <div class="row toggle-row">
        <div class="meta">
          <div class="name">{$_("unbounded_auto_enable")}</div>
          <div class="sub">{$_("unbounded_auto_enable_sub")}</div>
        </div>
        <button class="switch" class:on={autoEnable} role="switch" aria-checked={autoEnable} aria-label={$_("unbounded_auto_enable")} onclick={toggleAutoEnable}><span class="knob"></span></button>
      </div>
    </div>
  </div>
</main>

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
    background: var(--bg); border-bottom: 1px solid var(--border);
    box-shadow: 0 4px 12px rgba(0, 97, 98, 0.06);
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  .title { font-size: 19px; font-weight: 700; letter-spacing: -0.2px; color: var(--text-primary); }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }

  .banner { display: flex; gap: 12px; align-items: flex-start; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; }
  .banner .ic { color: var(--text-tertiary); }
  .banner p { margin: 0; font-size: 14px; font-weight: 500; line-height: 1.4; color: var(--text-secondary); }

  /* Placeholder for the WebGL globe (Task 6.1). A neutral, sized area so layout is stable. */
  .globe-placeholder {
    margin-top: 12px;
    height: 220px;
    border-radius: 16px;
    background: var(--surface);
    box-shadow: 0 4px 32px var(--shadow);
    display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 14px;
  }
  .globe-placeholder .sphere {
    width: 120px; height: 120px; border-radius: 50%;
    border: 2px solid var(--border);
    background: radial-gradient(circle at 35% 30%, var(--hover), transparent 65%);
  }
  .globe-placeholder .ph-label { font-size: 13px; font-weight: 500; color: var(--text-tertiary); }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden; margin-top: 12px;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px 16px;
    background: none; border: none; font-family: var(--font); text-align: start;
  }
  .toggle-row, .stat-row { justify-content: space-between; }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  .sub {
    margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary);
    letter-spacing: 0.01em;
  }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .pill {
    font-size: 14px; font-weight: 700; padding: 3px 10px; border-radius: 999px; white-space: nowrap;
    color: var(--text-secondary); background: var(--pill-bg);
  }

  .switch {
    width: 46px; height: 28px; border-radius: 999px; border: none; background: var(--switch-off);
    position: relative; cursor: pointer; transition: background 0.15s ease; flex-shrink: 0;
  }
  .switch.on { background: var(--brand, #1f9d55); }
  .knob {
    position: absolute; top: 3px; left: 3px; width: 22px; height: 22px;
    border-radius: 50%; background: #fff; transition: transform 0.15s ease;
  }
  .switch.on .knob { transform: translateX(18px); }

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
