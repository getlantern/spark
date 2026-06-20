<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { MockBackend, type SparkBackend, type SparkStatus } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  // Real backend inside the Tauri app (drives the NE command surface); the mock
  // in a plain browser (`npm run dev`). The UI is identical either way.
  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let status = $state<SparkStatus>({
    state: "disconnected",
    protocol: "AnyTLS",
    routing: "Full tunnel",
    failOpen: true,
  });
  let busy = $state(false);
  let errorMsg = $state<string | null>(null);
  let poll: ReturnType<typeof setInterval>;

  const connected = $derived(status.state === "connected");
  const connecting = $derived(status.state === "connecting");

  const heading = $derived(
    status.state === "connected" ? "Connected"
    : status.state === "connecting" ? "Connecting…"
    : status.state === "failed" ? "Failed"
    : "Disconnected",
  );
  const sub = $derived(
    status.state === "connected" ? "Your traffic is protected via the relay."
    : status.state === "connecting" ? "Negotiating gambit-shaped AnyTLS…"
    : status.state === "failed" ? "Couldn't establish the tunnel."
    : "You are not protected. Tap to connect.",
  );
  const pillLabel = $derived(connected ? "Connected" : connecting ? "Connecting…" : "Tap to connect");
  const vpnState = $derived(connected ? "On" : connecting ? "Connecting" : "Off");

  async function refresh() {
    status = await backend.status();
  }

  async function toggle() {
    if (busy || connecting) return;
    busy = true;
    errorMsg = null;
    try {
      if (connected) await backend.disconnect();
      else await backend.connect();
      await refresh();
    } catch (e) {
      errorMsg = String(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    refresh();
    poll = setInterval(refresh, 2000); // poll the live NE status (Flutter app's cadence)
  });
  onDestroy(() => clearInterval(poll));
</script>

<main class="app" class:connected>
  <header class="appbar">
    <div class="wordmark"><span class="dot"></span><span class="name">Spark</span></div>
    <button class="gear" aria-label="Settings">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    </button>
  </header>

  <section class="hero">
    <div class="orb-wrap">
      <div class="orb-ring"></div>
      <div class="orb">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
    </div>
    <div class="status-line">
      <div class="status">{heading}</div>
      <div class="substatus" class:error={errorMsg}>{errorMsg ?? sub}</div>
    </div>
    <button class="pill" role="switch" aria-checked={connected} aria-busy={connecting} onclick={toggle}>
      <span class="pill-label">{pillLabel}</span>
      <span class="knob">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>
      </span>
    </button>
  </section>

  <div class="card">
    <div class="row">
      <span class="label">VPN status</span>
      <span class="value"><span class="badge"></span>{vpnState}</span>
    </div>
    <div class="row">
      <span class="label">Protocol</span>
      <span class="value">{status.protocol}
        <span class="chev"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></span>
      </span>
    </div>
    <div class="row">
      <span class="label">Routing</span>
      <span class="value">{status.routing}
        <span class="chev"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg></span>
      </span>
    </div>
  </div>

  {#if status.failOpen}
    <div class="failopen">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      Fail-open: traffic flows unprotected if the tunnel drops.
    </div>
  {/if}
</main>

<style>
  /* Lantern light look — tokens verbatim from gui/lib/main.dart (_Palette).
     Sora ships as a bundled @font-face at U1; the system stack stands in for now. */
  :global(:root) {
    --bg: #f8fafb;
    --surface: #ffffff;
    --brand: #00bdd6;
    --off: #616569;
    --off-light: #a2a2a2;
    --knob: #ffffff;
    --text-primary: #1b1c1d;
    --text-secondary: #616569;
    --border: #edefef;
    --danger: #d92d20;
    --font: "Sora", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  :global(html),
  :global(body) {
    margin: 0;
    height: 100%;
    background: var(--bg);
    font-family: var(--font);
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
    user-select: none;
  }

  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .appbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 22px 4px;
    flex-shrink: 0;
  }
  .wordmark { display: flex; align-items: center; gap: 9px; }
  .wordmark .dot {
    width: 22px; height: 22px; border-radius: 7px;
    background: linear-gradient(150deg, var(--brand), #00a7bd);
    box-shadow: 0 3px 8px rgba(0, 189, 214, 0.4);
  }
  .wordmark .name { font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }
  .gear {
    width: 34px; height: 34px; border-radius: 10px;
    display: grid; place-items: center;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    background: var(--surface);
    cursor: pointer;
  }

  .hero {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 26px;
    padding: 8px 26px;
  }
  .orb-wrap { position: relative; width: 168px; height: 168px; display: grid; place-items: center; }
  .orb {
    width: 132px; height: 132px; border-radius: 50%;
    display: grid; place-items: center;
    background: var(--surface);
    border: 1px solid var(--border);
    transition: all 0.45s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .orb-ring {
    position: absolute; inset: 0; border-radius: 50%;
    border: 2px solid var(--border);
    transition: all 0.45s ease;
  }
  .orb svg { width: 52px; height: 52px; color: var(--off-light); transition: color 0.45s ease; }

  .status-line { text-align: center; }
  .status { font-size: 20px; font-weight: 700; letter-spacing: -0.2px; }
  .substatus { margin-top: 6px; font-size: 14px; line-height: 1.4; color: var(--text-secondary); }
  .substatus.error { color: var(--danger); }

  .pill {
    width: 230px; height: 60px; border-radius: 30px;
    background: var(--off);
    position: relative; cursor: pointer; border: none; padding: 0;
    transition: background 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    flex-shrink: 0;
  }
  .pill-label {
    position: absolute; inset: 0;
    display: flex; align-items: center; justify-content: flex-end;
    font-size: 14px; font-weight: 600; color: #fff;
    font-family: var(--font);
    padding: 0 24px;
    transition: all 0.4s ease;
  }
  .knob {
    position: absolute; top: 5px; left: 5px;
    width: 50px; height: 50px; border-radius: 50%;
    background: var(--knob);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    display: grid; place-items: center;
    color: var(--off);
    transition: transform 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .knob svg { width: 22px; height: 22px; }

  .card {
    margin: 0 22px 16px;
    background: var(--surface);
    border-radius: 16px;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
    overflow: hidden;
    flex-shrink: 0;
  }
  .row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 15px 18px;
  }
  .row + .row { border-top: 1px solid var(--border); }
  .label { font-size: 12px; font-weight: 500; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
  .value { display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 600; }
  .chev { color: var(--off-light); display: inline-flex; }
  .badge { width: 8px; height: 8px; border-radius: 50%; background: var(--off-light); transition: background 0.4s ease; }

  .failopen {
    margin: 0 22px 22px;
    display: flex; align-items: center; gap: 8px;
    padding: 10px 12px; border-radius: 10px;
    background: rgba(217, 45, 32, 0.07);
    color: var(--danger);
    font-size: 12px; font-weight: 600;
  }

  /* connected state */
  .app.connected .orb { background: rgba(0, 189, 214, 0.1); border-color: rgba(0, 189, 214, 0.35); }
  .app.connected .orb svg { color: var(--brand); }
  .app.connected .orb-ring { border-color: rgba(0, 189, 214, 0.25); box-shadow: 0 0 0 10px rgba(0, 189, 214, 0.06), 0 0 40px rgba(0, 189, 214, 0.25); }
  .app.connected .pill { background: var(--brand); }
  .app.connected .pill-label { justify-content: flex-start; }
  .app.connected .knob { transform: translateX(170px); color: var(--brand); }
  .app.connected .badge { background: var(--brand); }
</style>
