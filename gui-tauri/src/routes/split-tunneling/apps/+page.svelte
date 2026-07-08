<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend, type InstalledApp } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import Spinner from "$lib/Spinner.svelte";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let apps = $state<InstalledApp[]>([]);
  let excluded = $state<Set<string>>(new Set());
  let loading = $state(true);
  let query = $state("");
  let snack = $state<string | null>(null);
  let snackTimer: ReturnType<typeof setTimeout> | undefined;

  function showSnack(msg: string) {
    snack = msg;
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => (snack = null), 2500);
  }
  onDestroy(() => clearTimeout(snackTimer));

  onMount(async () => {
    try {
      const [list, ex] = await Promise.all([backend.listInstalledApps(), backend.getExcludedApps()]);
      apps = [...list].sort((a, b) => a.name.localeCompare(b.name));
      excluded = new Set(ex);
    } catch {}
    loading = false;
  });

  // Reassign a NEW Set each toggle so the $state proxy re-renders (mutating in place wouldn't).
  async function toggle(id: string) {
    const prev = excluded;
    const next = new Set(excluded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    excluded = next; // optimistic
    try {
      await backend.setExcludedApps([...next]);
    } catch {
      excluded = prev; // revert so the toggle reflects the actual persisted state
      showSnack("Couldn't update excluded apps");
    }
  }

  const filtered = $derived(
    query.trim()
      ? apps.filter((a) => a.name.toLowerCase().includes(query.trim().toLowerCase()))
      : apps,
  );
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/split-tunneling")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">App Split Tunneling</span>
  </header>

  <div class="scroll">
    <div class="seclabel">Search apps</div>
    <div class="addrow">
      <input class="input" placeholder="Search apps" bind:value={query} />
    </div>

    <div class="header">Apps bypassing the VPN ({excluded.size}):</div>
    <div class="card">
      {#if loading}
        <div class="loading"><Spinner /></div>
      {:else if filtered.length === 0}
        <div class="row empty">{query.trim() ? "No matching apps" : "No apps found"}</div>
      {:else}
        {#each filtered as app, i (app.id)}
          {#if i > 0}<div class="divider"></div>{/if}
          <div class="row">
            {#if app.icon}
              <img class="icon" src={app.icon} alt="" />
            {:else}
              <span class="icon placeholder" aria-hidden="true"></span>
            {/if}
            <div class="meta"><div class="name">{app.name}</div></div>
            <button
              class="switch"
              class:on={excluded.has(app.id)}
              role="switch"
              aria-checked={excluded.has(app.id)}
              aria-label={`Toggle ${app.name}`}
              onclick={() => toggle(app.id)}
            ><span class="knob"></span></button>
          </div>
        {/each}
      {/if}
    </div>
  </div>
  {#if snack}<div class="snack">{snack}</div>{/if}
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

  .seclabel { font-size: 13px; font-weight: 600; color: var(--text-secondary); padding: 14px 4px 6px; }
  .header {
    font-size: 12px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
    color: var(--text-tertiary); padding: 20px 4px 8px;
  }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 12px 16px;
    background: none; border: none; font-family: var(--font); text-align: left;
    transition: background 0.12s ease;
  }
  .meta { flex: 1; min-width: 0; }
  .name {
    font-size: 15px; font-weight: 600; color: var(--text-primary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  /* Apps-screen additions */
  .addrow { display: flex; align-items: center; gap: 12px; }
  .input { flex: 1; height: 48px; border: 1px solid var(--border); border-radius: 12px; padding: 0 14px; font-family: var(--font); font-size: 15px; background: var(--surface); color: var(--text-primary); }
  .row.empty { color: var(--text-tertiary); }
  .loading { display: flex; justify-content: center; align-items: center; padding: 48px 0; }
  .snack { position: fixed; left: 16px; right: 16px; bottom: 20px; background: var(--snack-bg); color: #fff; padding: 12px 16px; border-radius: 10px; font-size: 14px; text-align: center; box-shadow: 0 6px 24px rgba(0,0,0,.25); }

  .icon { width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0; object-fit: cover; }
  .icon.placeholder { background: var(--pill-bg); border: 1px solid var(--border); }

  /* Small toggle, matched to the split-tunnel parent screen. */
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
