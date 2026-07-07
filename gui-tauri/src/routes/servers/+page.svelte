<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { MockBackend, type SparkBackend, type ServerInfo } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import { selectedIndex } from "$lib/selection";
  import { flagEmoji, serverLabel, latencyClass, protocolLabel } from "$lib/format";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let servers = $state<ServerInfo[]>([]);
  let loaded = $state(false);
  let errorMsg = $state<string | null>(null);
  let busy = $state(false);
  let expanded = $state<Set<string>>(new Set());
  let poll: ReturnType<typeof setInterval>;
  let refreshing = false;

  // The member new flows currently dial (auto-best or pinned) — drives the Smart Location card.
  const current = $derived(servers.find((s) => s.isCurrent));

  // Countries in display order (alphabetical), each with its members. A country with one member
  // renders as a single row; multiple members expand to per-city rows (Lantern's desktop pattern).
  type Group = { country: string; countryCode?: string | null; members: ServerInfo[]; best: number | null };
  const groups = $derived.by<Group[]>(() => {
    const byCountry = new Map<string, ServerInfo[]>();
    for (const s of servers) {
      const key = s.country || s.name || "—";
      const list = byCountry.get(key) ?? [];
      list.push(s);
      byCountry.set(key, list);
    }
    return [...byCountry.entries()]
      .map(([country, members]) => {
        const lats = members.map((m) => m.latencyMs).filter((l): l is number => l != null);
        return {
          country,
          countryCode: members[0]?.countryCode,
          members,
          best: lats.length ? Math.min(...lats) : null,
        };
      })
      .sort((a, b) => a.country.localeCompare(b.country));
  });

  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      servers = await backend.servers();
      errorMsg = null;
    } catch (e) {
      // Disconnected / no pool: surface an empty state, not an error toast.
      servers = [];
      errorMsg = String(e);
    } finally {
      loaded = true;
      refreshing = false;
    }
  }

  async function choose(index: number | null) {
    if (busy) return;
    busy = true;
    // Reflect the choice immediately and pop home (Lantern's popUntilRoot). The pin takes effect
    // live when connected; when not, it's stored as the UI preference and applied on connect — so a
    // failed live pin (disconnected / no pool yet) must not block the pick.
    selectedIndex.set(index);
    try {
      await backend.selectServer(index);
    } catch {
      // best-effort: applied on the next connect
    }
    goto("/");
  }

  function toggle(country: string) {
    const next = new Set(expanded);
    if (next.has(country)) next.delete(country);
    else next.add(country);
    expanded = next;
  }

  onMount(() => {
    refresh();
    poll = setInterval(refresh, 3000); // keep latency pills fresh
  });
  onDestroy(() => clearInterval(poll));
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label="Back" onclick={() => goto("/")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">Server selection</span>
  </header>

  <div class="scroll">
    <!-- Smart Location (auto) -->
    <div class="seclabel">Smart location</div>
    <div class="card">
      <button class="row" class:sel={$selectedIndex === null} onclick={() => choose(null)}>
        {#if current}
          <span class="flag">{flagEmoji(current.countryCode)}</span>
          <div class="meta">
            <div class="name">{serverLabel(current)}</div>
            {#if current.protocol}<div class="sub">{protocolLabel(current.protocol)}</div>{/if}
          </div>
          {#if current.latencyMs != null}
            <span class="pill {latencyClass(current.latencyMs)}">{current.latencyMs} ms</span>
          {/if}
        {:else}
          <span class="flag" aria-hidden="true">🌐</span>
          <div class="meta"><div class="name">Fastest server</div></div>
        {/if}
        <span class="bolt" class:on={$selectedIndex === null} aria-label="Auto">⚡</span>
      </button>
    </div>
    <p class="helper">Automatically chooses the fastest location.</p>

    {#if loaded && servers.length === 0}
      <p class="empty">No servers available. Connect first to choose a location.</p>
    {:else if servers.length > 0}
      <div class="header">All locations</div>
      <div class="card">
        {#each groups as g, gi (g.country)}
          {#if gi > 0}<div class="divider"></div>{/if}
          {#if g.members.length === 1}
            {@const s = g.members[0]}
            <button class="row" class:sel={$selectedIndex === s.index} onclick={() => choose(s.index)}>
              <span class="flag">{flagEmoji(s.countryCode)}</span>
              <div class="meta">
                <div class="name">{serverLabel(s)}</div>
                {#if s.protocol}<div class="sub">{protocolLabel(s.protocol)}</div>{/if}
              </div>
              {#if s.latencyMs != null}
                <span class="pill {latencyClass(s.latencyMs)}">{s.latencyMs} ms</span>
              {/if}
              {#if $selectedIndex === s.index}<span class="check" aria-label="Selected">✓</span>{/if}
            </button>
          {:else}
            <!-- Multi-city country: expandable header + indented city rows -->
            <button class="row" onclick={() => toggle(g.country)} aria-expanded={expanded.has(g.country)}>
              <span class="flag">{flagEmoji(g.countryCode)}</span>
              <div class="meta"><div class="name">{g.country}</div></div>
              {#if g.best != null}
                <span class="pill {latencyClass(g.best)}">{g.best} ms</span>
              {/if}
              <span class="chev" class:open={expanded.has(g.country)}>›</span>
            </button>
            {#if expanded.has(g.country)}
              {#each g.members as s (s.index)}
                <button class="row city" class:sel={$selectedIndex === s.index} onclick={() => choose(s.index)}>
                  <div class="meta">
                    <div class="name">{s.city || serverLabel(s)}</div>
                    {#if s.protocol}<div class="sub">{protocolLabel(s.protocol)}</div>{/if}
                  </div>
                  {#if s.latencyMs != null}
                    <span class="pill {latencyClass(s.latencyMs)}">{s.latencyMs} ms</span>
                  {/if}
                  {#if $selectedIndex === s.index}<span class="check" aria-label="Selected">✓</span>{/if}
                </button>
              {/each}
            {/if}
          {/if}
        {/each}
      </div>
    {/if}

    {#if errorMsg && servers.length > 0}
      <p class="err">{errorMsg}</p>
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

  .seclabel { font-size: 13px; font-weight: 600; color: var(--text-secondary); padding: 14px 4px 6px; }
  .helper { margin: 6px 4px 0; font-size: 13px; color: var(--text-secondary); line-height: 1.4; }
  .header {
    font-size: 12px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
    color: var(--text-tertiary); padding: 20px 4px 8px;
  }
  .empty { margin: 20px 4px; font-size: 14px; color: var(--text-tertiary); text-align: center; }
  .err { margin: 12px 4px 0; font-size: 12px; color: #d92d20; }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 12px 16px;
    background: none; border: none; cursor: pointer; font-family: var(--font); text-align: left;
    transition: background 0.12s ease;
  }
  .row:hover { background: var(--hover); }
  .row.sel { background: rgba(0, 189, 214, 0.08); }
  .row.city { padding-left: 53px; }
  .meta { flex: 1; min-width: 0; }
  .name {
    font-size: 15px; font-weight: 600; color: var(--text-primary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .sub {
    margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary);
    letter-spacing: 0.01em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .flag { font-size: 21px; line-height: 1; }

  .pill {
    font-size: 12px; font-weight: 700; padding: 3px 8px; border-radius: 999px; white-space: nowrap;
  }
  .pill.good { color: var(--lat-good); background: rgba(31, 157, 85, 0.12); }
  .pill.amber { color: var(--lat-amber); background: rgba(124, 160, 6, 0.12); }
  .pill.slow { color: var(--lat-slow); background: rgba(201, 138, 0, 0.12); }

  .bolt { font-size: 17px; opacity: 0.28; }
  .bolt.on { opacity: 1; color: var(--bolt); }
  .check { color: var(--brand); font-size: 18px; font-weight: 700; }
  .chev {
    color: var(--text-tertiary); font-size: 20px; line-height: 1; display: inline-block;
    transition: transform 0.2s ease;
  }
  .chev.open { transform: rotate(90deg); }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }
</style>
