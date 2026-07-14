<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import { _, locale } from "$lib/i18n";
  import { SUPPORTED } from "$lib/i18n/locales";
  import { theme } from "$lib/theme";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  // Ad-block defaults on (persisted flag defaults true); load the real value on mount.
  let adBlock = $state(true);
  let snack = $state<string | null>(null);
  let snackTimer: ReturnType<typeof setTimeout> | undefined;

  // Unbounded settings row: gated on server availability only (NOT on `hidden`). The home
  // switcher tab uses unboundedVisible(serverEnabled, hidden), but this row must stay
  // reachable when hidden=true so the user can un-hide — otherwise "Hide Unbounded" is
  // irreversible from the UI. Availability comes from the backend (server `features.unbounded`
  // gate + a config block with the endpoints — Task 7.1); defaults false (row hidden) until the
  // async check resolves.
  let unboundedServerEnabled = $state(false);
  const showUnbounded = $derived(unboundedServerEnabled);

  onMount(async () => {
    try { adBlock = await backend.getAdBlockEnabled(); } catch {}
    try { unboundedServerEnabled = await backend.unboundedAvailable(); } catch {}
  });

  function showSnack(msg: string) {
    snack = msg;
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => (snack = null), 2500);
  }
  // Clear a pending snackbar timeout on unmount so it can't fire after navigation away (matches
  // the split-tunneling/apps screen).
  onDestroy(() => clearTimeout(snackTimer));

  // Optimistic toggle with revert-on-failure (matches the apps screen).
  async function toggleAdBlock() {
    const prev = adBlock;
    adBlock = !adBlock;
    try {
      await backend.setAdBlockEnabled(adBlock);
    } catch {
      adBlock = prev;
      showSnack($_("err_ad_block"));
    }
  }

  const languageLabel = $derived(
    SUPPORTED.find((l) => l.code === $locale)?.nativeName ?? ($locale ?? "English"),
  );
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("settings")}</span>
  </header>

  <div class="scroll">
    <div class="card">
      <button class="row nav" onclick={() => goto("/settings/appearance")}>
        <span class="ic">{@render gear()}</span>
        <div class="meta"><div class="name">{$_("appearance")}</div></div>
        <!-- Literal $_() per value (not $_($theme)) so the i18n key-coverage guard protects these keys. -->
        <span class="value">{$theme === "light" ? $_("light") : $theme === "dark" ? $_("dark") : $_("system")}</span>
        <span class="chev">{@render chevron()}</span>
      </button>
      <div class="divider"></div>
      <button class="row nav" onclick={() => goto("/settings/language")}>
        <span class="ic">{@render globe()}</span>
        <div class="meta"><div class="name">{$_("language")}</div></div>
        <span class="value">{languageLabel}</span>
        <span class="chev">{@render chevron()}</span>
      </button>
      {#if showUnbounded}
        <div class="divider"></div>
        <button class="row nav" onclick={() => goto("/settings/unbounded")}>
          <span class="ic">{@render bridge()}</span>
          <div class="meta"><div class="name">{$_("unbounded_title")}</div></div>
          <span class="chev">{@render chevron()}</span>
        </button>
      {/if}
    </div>

    <div class="card" style="margin-top:12px">
      <div class="row toggle-row">
        <span class="ic">{@render shield()}</span>
        <div class="meta"><div class="name">{$_("built_in_ad_blocking")}</div></div>
        <button class="switch" class:on={adBlock} role="switch" aria-checked={adBlock} aria-label={$_("built_in_ad_blocking")} onclick={toggleAdBlock}><span class="knob"></span></button>
      </div>
    </div>
  </div>

  {#if snack}<div class="snack">{snack}</div>{/if}
</main>

{#snippet chevron()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
{/snippet}
{#snippet gear()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
{/snippet}
{#snippet globe()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></svg>
{/snippet}
{#snippet shield()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>
{/snippet}
{#snippet bridge()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 9v9"/><path d="M22 9v9"/><path d="M2 12a6 6 0 0 1 6-6h8a6 6 0 0 1 6 6"/><path d="M7 12v6"/><path d="M12 10v8"/><path d="M17 12v6"/></svg>
{/snippet}

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
  .title { font-size: 19px; font-weight: 700; letter-spacing: -0.2px; color: var(--text-primary); }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px 16px;
    background: none; border: none; font-family: var(--font); text-align: start;
    transition: background 0.12s ease;
  }
  .row.nav { cursor: pointer; }
  .row.nav:hover { background: var(--hover); }
  .toggle-row { cursor: default; }
  .ic { width: 24px; display: inline-flex; justify-content: center; color: var(--text-secondary); flex-shrink: 0; }
  .meta { flex: 1; min-width: 0; }
  .name {
    font-size: 15px; font-weight: 600; color: var(--text-primary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .value { font-size: 14px; font-weight: 500; color: var(--text-tertiary); white-space: nowrap; }
  .chev { color: var(--text-tertiary); display: inline-flex; }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .snack { position: fixed; left: 16px; right: 16px; bottom: 20px; background: var(--snack-bg); color: #fff; padding: 12px 16px; border-radius: 10px; font-size: 14px; text-align: center; box-shadow: 0 6px 24px rgba(0,0,0,.25); }

  /* Small toggle, matched to the split-tunnel screen. */
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

  /* RTL: flip the back-arrow and the nav chevrons; leave the toggle knob LTR (calibrated). */
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  :global([dir="rtl"]) .chev { transform: scaleX(-1); }
</style>
