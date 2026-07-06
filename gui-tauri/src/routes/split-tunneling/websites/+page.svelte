<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend, type SplitTunnel } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();
  let st = $state<SplitTunnel>({ enabled: true, domains: [], ips: [] });
  let entry = $state("");
  let snack = $state<string | null>(null);
  let snackTimer: ReturnType<typeof setTimeout> | undefined;

  onMount(async () => { try { st = await backend.getSplitTunnel(); } catch {} });

  // Displayed rows: domains then ips, stable order.
  const rows = $derived([...st.domains, ...st.ips]);

  // A bare IPv4 (octets bounded 0-255) / IPv6 address, no CIDR suffix. Kept in step with core's
  // is_ip_or_cidr so the client doesn't report "added" for entries core will drop.
  const isV4 = (a: string): boolean =>
    /^\d{1,3}(\.\d{1,3}){3}$/.test(a) && a.split(".").every((o) => Number(o) <= 255);
  const isV6 = (a: string): boolean => a.includes(":") && /^[0-9a-f:]+$/.test(a);

  function normalize(raw: string): string {
    let e = raw.trim().toLowerCase().replace(/^https?:\/\//, "");
    // Strip query/fragment always.
    const qf = e.search(/[?#]/);
    if (qf >= 0) e = e.slice(0, qf);
    // Strip a path `/…` unless the part before it is a bare IP — then it's a CIDR (10.0.0.0/8),
    // which we preserve (matches core's normalize_one).
    const slash = e.indexOf("/");
    if (slash >= 0 && !isV4(e.slice(0, slash)) && !isV6(e.slice(0, slash))) e = e.slice(0, slash);
    // Strip a :port on a hostname/IPv4 (single colon); IPv6 literals have >=2 colons.
    if ((e.match(/:/g) || []).length === 1) e = e.replace(/:\d+$/, "");
    return e.trim();
  }
  function classify(h: string): "domain" | "ip" | null {
    if (!h) return null;
    const slash = h.indexOf("/");
    const addr = slash >= 0 ? h.slice(0, slash) : h;
    const prefix = slash >= 0 ? h.slice(slash + 1) : null;
    // A CIDR prefix (if present) must be numeric and in range for the family (v4 ≤ 32, v6 ≤ 128).
    const prefixOk = (max: number) => prefix === null || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= max);
    if (isV4(addr)) return prefixOk(32) ? "ip" : null;
    if (isV6(addr)) return prefixOk(128) ? "ip" : null;
    // Domain: valid label chars, has a dot AND at least one letter (rejects numeric junk like
    // 999.999.999.999), no leading/trailing/adjacent dots.
    if (/^[a-z0-9.-]+$/.test(h) && /[a-z]/.test(h) && h.includes(".") && !h.startsWith(".") && !h.endsWith(".") && !h.includes(".."))
      return "domain";
    return null;
  }

  function showSnack(msg: string) {
    snack = msg;
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => (snack = null), 2500);
  }
  onDestroy(() => clearTimeout(snackTimer));

  async function persist(msg: string) {
    try {
      await backend.setSplitTunnel(st);
      showSnack(msg);
    } catch {
      showSnack("Couldn't save changes");
    }
  }
  async function add() {
    let added = 0;
    for (const tok of entry.split(",")) {
      const h = normalize(tok);
      const kind = classify(h);
      if (kind === "domain" && !st.domains.includes(h)) { st.domains = [...st.domains, h]; added++; }
      else if (kind === "ip" && !st.ips.includes(h)) { st.ips = [...st.ips, h]; added++; }
    }
    entry = "";
    if (added) await persist(`Added ${added} ${added === 1 ? "site" : "sites"}`);
  }
  async function remove(host: string) {
    st.domains = st.domains.filter((d) => d !== host);
    st.ips = st.ips.filter((i) => i !== host);
    await persist("Removed");
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/split-tunneling")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">Website Split Tunneling</span>
  </header>

  <div class="scroll">
    <div class="seclabel">Enter URL or IP Address</div>
    <div class="addrow">
      <input class="input" placeholder="Enter URL" bind:value={entry} onkeydown={(e) => e.key === "Enter" && add()} />
      <button class="addbtn" onclick={add}>Add</button>
    </div>
    <p class="helper">Use commas to separate multiple URLs</p>

    <div class="header">Websites bypassing the VPN ({rows.length}):</div>
    <div class="card">
      {#if rows.length === 0}
        <div class="row empty">No websites selected</div>
      {:else}
        {#each rows as host, i (host)}
          {#if i > 0}<div class="divider"></div>{/if}
          <div class="row">
            <div class="meta"><div class="name">{host}</div></div>
            <button class="x" aria-label={`Remove ${host}`} onclick={() => remove(host)}>✕</button>
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
  .helper { margin: 6px 4px 0; font-size: 13px; color: var(--text-secondary); line-height: 1.4; }
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

  /* Websites-screen additions */
  .addrow { display: flex; align-items: center; gap: 12px; }
  .input { flex: 1; height: 48px; border: 1px solid var(--border); border-radius: 12px; padding: 0 14px; font-family: var(--font); font-size: 15px; background: var(--surface); color: var(--text-primary); }
  .addbtn { border: none; background: none; color: var(--brand); font-weight: 700; font-size: 15px; cursor: pointer; text-decoration: underline; padding: 8px; }
  .row .x { border: none; background: none; color: var(--text-tertiary); font-size: 16px; cursor: pointer; padding: 6px; }
  .row.empty { color: var(--text-tertiary); }
  .snack { position: fixed; left: 16px; right: 16px; bottom: 20px; background: #23282b; color: #fff; padding: 12px 16px; border-radius: 10px; font-size: 14px; text-align: center; box-shadow: 0 6px 24px rgba(0,0,0,.25); }
</style>
