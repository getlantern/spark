<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend, type SparkStatus, type ServerInfo } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import { selectedIndex } from "$lib/selection";
  import { flagEmoji, serverLabel } from "$lib/format";
  // Fonts + global design tokens live in +layout.svelte (shared across home ↔ server selection).

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let status = $state<SparkStatus>({
    state: "disconnected",
    protocol: "AnyTLS",
    failOpen: false,
  });
  let busy = $state(false);
  let errorMsg = $state<string | null>(null);
  let servers = $state<ServerInfo[]>([]);
  let poll: ReturnType<typeof setInterval>;
  let refreshing = false; // re-entrancy guard: status() can block ~3s, longer than the 2s poll

  const connected = $derived(status.state === "connected");
  const connecting = $derived(status.state === "connecting");
  // The server shown in the Smart-location tile: the user's pick if any, else the live current
  // (the auto-ranked best, marked by the snapshot).
  const current = $derived(
    $selectedIndex != null
      ? servers.find((s) => s.index === $selectedIndex)
      : servers.find((s) => s.isCurrent),
  );

  // Capitalized status value, matching the VpnStatus row (vpnStatus.name.capitalize).
  const statusValue = $derived(
    status.state === "connected" ? "Connected"
    : status.state === "connecting" ? "Connecting"
    : status.state === "failed" ? "Failed"
    : "Disconnected",
  );

  async function refresh() {
    // status() can block ~3s (longer than the 2s poll), so skip a tick if one is
    // still in-flight — avoids overlapping calls racing status/errorMsg and stacking
    // pending invoke()s. Failures are caught so a rejected poll isn't an unhandled
    // rejection every interval.
    if (refreshing) return;
    refreshing = true;
    try {
      status = await backend.status();
      // The list is config-sourced (available offline); latency overlays when connected. Cheap to
      // fetch every tick — the Rust side only hits the NE channel when actually connected.
      try {
        servers = await backend.servers();
      } catch {
        servers = [];
      }
      errorMsg = null; // clear a prior (transient) error once the backend recovers
    } catch (e) {
      errorMsg = String(e);
    } finally {
      refreshing = false;
    }
  }
  async function toggle() {
    if (busy || connecting) return;
    busy = true;
    errorMsg = null;
    try {
      if (connected) {
        await backend.disconnect();
      } else {
        await backend.connect();
        // Apply the user's server pick (if any) now that the tunnel is up — so "pick offline →
        // connect" actually routes through the chosen relay. Best-effort.
        if ($selectedIndex != null) {
          try {
            await backend.selectServer($selectedIndex);
          } catch {
            /* pool may not be ready yet; the pick still shows in the UI */
          }
        }
      }
      await refresh();
    } catch (e) {
      errorMsg = String(e);
    } finally {
      busy = false;
    }
  }
  let splitEnabled = $state(false);
  // Best-effort refresh of the Home row's split-tunnel state; polled alongside status so the row
  // doesn't go stale after the list is toggled/edited elsewhere in the app.
  async function loadSplit() {
    try {
      splitEnabled = (await backend.getSplitTunnel()).enabled;
    } catch {
      /* leave the last-known value */
    }
  }

  let routingMode = $state<"smart" | "full">("smart");
  async function loadRouting() {
    try { routingMode = await backend.getRoutingMode(); } catch { /* keep last */ }
  }
  const routingModeLabel = $derived(routingMode === "full" ? "Full Tunnel" : "Smart Routing");

  onMount(() => {
    refresh();
    loadSplit();
    loadRouting();
    poll = setInterval(() => {
      refresh();
      loadSplit();
      loadRouting();
    }, 2000);
  });
  onDestroy(() => clearInterval(poll));
</script>

<main class="app">
  <!-- AppBar: menu · SPARK wordmark · account avatar. -->
  <header class="appbar">
    <button class="iconbtn" aria-label="Menu">{@render menu()}</button>
    <span class="wordmark">SPARK</span>
    <button class="iconbtn" aria-label="Account">{@render account()}</button>
  </header>

  <div class="body">
    <section class="hero">
      <!-- VPNSwitch: rounded track (brand when connected, grey otherwise), white knob that slides
           right on connect, spinner while transitioning. -->
      <button
        class="track"
        class:on={connected}
        aria-label="Toggle VPN connection"
        role="switch"
        aria-checked={connected}
        aria-busy={connecting || busy}
        onclick={toggle}
      >
        {#if connecting || busy}
          <span class="spinner"></span>
        {:else}
          <span class="knob"></span>
        {/if}
      </button>
      {#if errorMsg}
        <p class="error">{errorMsg}</p>
      {/if}
    </section>

    <!-- Settings card: white, 16-radius, teal elevation shadow. -->
    <div class="card">
      <!-- VPN status row -->
      <div class="tile">
        <div class="tile-head">
          <span class="ic">{@render globe()}</span>
          <span class="label">VPN status</span>
        </div>
        <div class="tile-body">
          <span class="value" class:ok={connected}>{statusValue}{#if connecting}…{/if}</span>
          <span class="dot" class:on={connected} class:mid={connecting}></span>
        </div>
      </div>
      <div class="divider"></div>
      <!-- Smart-location row → server selection screen -->
      <button class="tile nav" onclick={() => goto("/servers")}>
        <div class="tile-head">
          <span class="ic">
            {#if current}<span class="emoji">{flagEmoji(current.countryCode)}</span>{:else}{@render pin()}{/if}
          </span>
          <span class="label">{$selectedIndex === null ? "Smart location" : "Selected location"}</span>
        </div>
        <div class="tile-body">
          <span class="value">{current ? serverLabel(current) : "Fastest server"}</span>
          {#if $selectedIndex === null}<span class="locbolt" aria-label="Auto">⚡</span>{/if}
          <span class="chev">{@render chevron()}</span>
        </div>
        {#if current?.latencyMs != null}
          <div class="locsub">{current.latencyMs} ms</div>
        {/if}
      </button>
      <div class="divider"></div>
      <!-- Routing Mode row → /routing -->
      <button class="tile nav" onclick={() => goto("/routing")}>
        <div class="tile-head">
          <span class="ic">{@render route()}</span>
          <span class="label">Routing Mode</span>
        </div>
        <div class="tile-body">
          <span class="value">{routingModeLabel}</span>
          <span class="chev">{@render chevron()}</span>
        </div>
      </button>
      <div class="divider"></div>
      <!-- Split Tunneling row -->
      <button class="tile nav" onclick={() => goto("/split-tunneling")}>
        <div class="tile-head">
          <span class="ic">{@render split()}</span>
          <span class="label">Split Tunneling</span>
        </div>
        <div class="tile-body">
          <span class="value">{splitEnabled ? "Enabled" : "Disabled"}</span>
          <span class="chev">{@render chevron()}</span>
        </div>
      </button>
    </div>
  </div>
</main>

{#snippet menu()}
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
{/snippet}
{#snippet account()}
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="10" r="3"/><path d="M6.5 19a5.5 5.5 0 0 1 11 0"/></svg>
{/snippet}
{#snippet globe()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></svg>
{/snippet}
{#snippet route()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M8.5 19H14a4 4 0 0 0 0-8H10a4 4 0 0 1 0-8h5.5"/></svg>
{/snippet}
{#snippet chevron()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
{/snippet}
{#snippet pin()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21s-6-5.3-6-10a6 6 0 0 1 12 0c0 4.7-6 10-6 10z"/><circle cx="12" cy="11" r="2.2"/></svg>
{/snippet}
{#snippet split()}
  <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3v6a4 4 0 0 0 4 4h8"/><path d="M6 21v-6"/><polyline points="15 9 19 13 15 17"/></svg>
{/snippet}

<style>
  /* Design tokens + html/body base live in +layout.svelte (shared across routes). */
  .app { height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

  /* AppBar */
  .appbar {
    height: 56px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 10px;
    background: var(--bg);
    border-bottom: 1px solid var(--border);
    box-shadow: 0 4px 12px rgba(0, 97, 98, 0.06); /* AppBar elevation */
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  .wordmark { font-size: 20px; font-weight: 700; letter-spacing: 1.5px; color: var(--text-primary); }

  .body { flex: 1; display: flex; flex-direction: column; padding: 0 16px; min-height: 0; }

  /* Hero with the toggle vertically centered above the card */
  .hero { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 18px; }

  /* VPNSwitch — 140×70 track, 60px knob, 5px inset, 70px travel (Flutter vpn_switch.dart:
     indicatorSize 60 + spacing 10 + wrapper padding 5 ⇒ symmetric 5px gaps both ends). */
  .track {
    position: relative;
    width: 140px; height: 70px;
    border: none; padding: 0; cursor: pointer;
    border-radius: 35px;
    background: var(--off);
    transition: background 0.32s ease;
  }
  .track.on { background: var(--brand); }
  .knob {
    position: absolute; top: 5px; left: 5px;
    width: 60px; height: 60px; border-radius: 50%;
    background: var(--knob);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    transition: transform 0.32s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .track.on .knob { transform: translateX(70px); }
  /* Spinner replaces the knob while (dis)connecting: 44px ring (8px stroke) centered in 70px track. */
  .spinner {
    box-sizing: border-box;
    position: absolute; top: 13px; left: 13px;
    width: 44px; height: 44px; border-radius: 50%;
    border: 8px solid rgba(255, 255, 255, 0.35);
    border-top-color: var(--knob);
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .error {
    margin: 0; max-width: 300px; text-align: center;
    font-size: 13px; font-weight: 500; line-height: 1.4; color: #d92d20;
  }

  /* Settings card */
  .card {
    margin: 0 0 10px;
    background: var(--surface);
    border-radius: 16px;
    box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
    flex-shrink: 0;
  }
  .tile { padding: 10px 16px; }
  /* Nav tiles are full-width buttons (navigate to sub-routes). */
  .tile.nav {
    display: block; width: 100%; text-align: left; border: none; cursor: pointer;
    background: none; font-family: var(--font);
  }
  .tile.nav:hover { background: var(--hover); }
  .tile-head { display: flex; align-items: center; gap: 8px; }
  .ic { width: 24px; display: inline-flex; justify-content: center; color: var(--text-secondary); }
  .emoji { font-size: 18px; line-height: 1; }
  .label { font-size: 14px; font-weight: 500; color: var(--text-tertiary); }
  .tile-body { display: flex; align-items: center; gap: 6px; padding-left: 32px; margin-top: 2px; }
  .value { flex: 1; font-size: 16px; font-weight: 600; color: var(--text-primary); }
  .value.ok { color: var(--success); }
  .locbolt { color: var(--bolt); font-size: 16px; }
  .locsub { padding-left: 32px; font-size: 12px; color: var(--text-tertiary); margin-top: 1px; }
  .chev { color: var(--text-tertiary); display: inline-flex; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--indicator-off); }
  .dot.on { background: var(--success); }
  .dot.mid { background: var(--brand); }

  .divider { height: 1px; background: var(--border); margin: 0 16px; }
</style>
