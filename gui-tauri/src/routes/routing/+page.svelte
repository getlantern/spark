<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  let mode = $state<"smart" | "full">("smart");
  onMount(async () => { try { mode = await backend.getRoutingMode(); } catch {} });

  async function choose(m: "smart" | "full") {
    mode = m;
    try { await backend.setRoutingMode(m); } catch {}
    goto("/");
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">Routing Mode</span>
  </header>

  <div class="scroll">
    <div class="card" role="radiogroup" aria-label="Routing mode">
      <button class="row" role="radio" aria-checked={mode === "smart"} onclick={() => choose("smart")}>
        <div class="meta"><div class="name">Smart Routing</div><div class="sub">Rule-based routing optimized for your region</div></div>
        <span class="radio" class:on={mode === "smart"} aria-hidden="true"></span>
      </button>
      <div class="divider"></div>
      <button class="row" role="radio" aria-checked={mode === "full"} onclick={() => choose("full")}>
        <div class="meta"><div class="name">Full Tunnel</div><div class="sub">Routes all traffic through VPN</div></div>
        <span class="radio" class:on={mode === "full"} aria-hidden="true"></span>
      </button>
    </div>
    <div class="note">
      <span class="ic" aria-hidden="true">ⓘ</span>
      <p>Smart Routing uses region-specific rules to automatically send traffic that needs the VPN through Spark. All other traffic goes direct for speed and reliability.</p>
    </div>
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
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 15px 16px;
    background: none; border: none; cursor: pointer; font-family: var(--font); text-align: left;
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
    letter-spacing: 0.01em;
  }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--text-tertiary); flex-shrink: 0; position: relative; }
  .radio.on { border-color: var(--brand); }
  .radio.on::after { content: ""; position: absolute; inset: 4px; border-radius: 50%; background: var(--brand); }

  .note { display: flex; gap: 12px; align-items: flex-start; margin-top: 12px; padding: 12px 16px; border: 1px solid var(--border); border-radius: 8px; }
  .note .ic { color: var(--text-tertiary); }
  .note p { margin: 0; font-size: 14px; font-weight: 500; line-height: 1.4; color: var(--text-secondary); }
</style>
