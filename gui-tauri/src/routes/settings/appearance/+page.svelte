<script lang="ts">
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import { theme, setTheme, type Theme } from "$lib/theme";

  const OPTIONS: Theme[] = ["system", "light", "dark"];

  function choose(t: Theme) {
    setTheme(t);
    // replaceState so the picker doesn't linger in history — Back from /settings goes to the
    // previous screen, not back into this picker.
    goto("/settings", { replaceState: true });
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/settings")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("appearance")}</span>
  </header>

  <div class="scroll">
    <div class="card" role="radiogroup" aria-label={$_("appearance")}>
      {#each OPTIONS as opt, i (opt)}
        {#if i > 0}<div class="divider"></div>{/if}
        <button class="row" role="radio" aria-checked={$theme === opt} onclick={() => choose(opt)}>
          <div class="meta"><div class="name">{$_(opt)}</div></div>
          <span class="radio" class:on={$theme === opt} aria-hidden="true"></span>
        </button>
      {/each}
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

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }
  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 15px 16px;
    background: none; border: none; cursor: pointer; font-family: var(--font); text-align: start;
    transition: background 0.12s ease;
  }
  .row:hover { background: var(--hover); }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .radio { width: 22px; height: 22px; border-radius: 50%; border: 2px solid var(--text-tertiary); flex-shrink: 0; position: relative; }
  .radio.on { border-color: var(--brand); }
  .radio.on::after { content: ""; position: absolute; inset: 4px; border-radius: 50%; background: var(--brand); }

  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
</style>
