<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import { MockBackend, type SparkBackend, type SplitTunnel } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  let st = $state<SplitTunnel>({ enabled: false, domains: [], ips: [] });
  let appCount = $state(0);
  // App-based split tunneling is impossible on iOS — hide that option there. Resolve the platform
  // via a dynamic import inside onMount (the repo's convention for @tauri-apps/plugin-os, see
  // lib/i18n/index.ts) so the plugin isn't loaded eagerly in web/MockBackend mode.
  let isIos = $state(false);

  onMount(async () => {
    if (isTauri()) {
      try {
        const os = await import("@tauri-apps/plugin-os");
        isIos = os.platform() === "ios";
      } catch {}
    }
    try { st = await backend.getSplitTunnel(); } catch {}
    // The Apps row is hidden on iOS, so skip the excluded-apps round-trip there (appCount unused).
    if (!isIos) {
      try { appCount = (await backend.getExcludedApps()).length; } catch {}
    }
  });

  async function toggle() {
    st = { ...st, enabled: !st.enabled };
    try { await backend.setSplitTunnel(st); } catch {}
  }
  const siteCount = $derived(st.domains.length + st.ips.length);
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("split_tunneling")}</span>
  </header>

  <div class="scroll">
    <div class="card">
      <div class="row toggle-row">
        <div class="meta"><div class="name">{$_("split_tunneling")}</div><div class="sub">{$_("add_apps_websites_bypass_vpn")}</div></div>
        <button class="switch" class:on={st.enabled} role="switch" aria-checked={st.enabled} aria-label={$_("toggle_split_tunneling")} onclick={toggle}><span class="knob"></span></button>
      </div>
    </div>

    {#if st.enabled}
      <div class="card" style="margin-top:12px">
        {#if !isIos}
        <button class="row" onclick={() => goto("/split-tunneling/apps")}>
          <span class="ic" aria-hidden="true">▦</span>
          <div class="meta"><div class="name">{$_("apps")}</div></div>
          <span class="pill">{$_("apps_count", { values: { count: appCount } })}</span>
          <span class="chev">›</span>
        </button>
        <div class="divider"></div>
        {/if}
        <button class="row" onclick={() => goto("/split-tunneling/websites")}>
          <span class="ic" aria-hidden="true">🌐</span>
          <div class="meta"><div class="name">{$_("websites")}</div></div>
          <span class="pill">{$_("sites_count", { values: { count: siteCount } })}</span>
          <span class="chev">›</span>
        </button>
      </div>
    {/if}
  </div>
</main>

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

  .scroll { flex: 1; overflow-y: auto; padding: 0 16px 20px; }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden; margin-top: 12px;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 12px 16px;
    background: none; border: none; cursor: pointer; font-family: var(--font); text-align: start;
    transition: background 0.12s ease;
  }
  .row:hover { background: var(--hover); }
  .meta { flex: 1; min-width: 0; }
  .name {
    font-size: 15px; font-weight: 600; color: var(--text-primary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .sub {
    margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary);
    letter-spacing: 0.01em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  .pill {
    font-size: 12px; font-weight: 700; padding: 3px 8px; border-radius: 999px; white-space: nowrap;
    color: var(--text-secondary); background: var(--pill-bg);
  }

  .chev {
    color: var(--text-tertiary); font-size: 20px; line-height: 1; display: inline-block;
    transition: transform 0.2s ease;
  }
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  :global([dir="rtl"]) .chev { transform: scaleX(-1); }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  /* Split-tunneling specific */
  .toggle-row { justify-content: space-between; cursor: default; }
  .ic { font-size: 20px; width: 24px; text-align: center; }
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
</style>
