<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import Icon from "$lib/Icon.svelte";
  import { MockBackend, type SparkBackend } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let autoEnable = $state(false);
  let hidden = $state(false);

  onMount(async () => {
    try {
      const settings = await backend.unboundedGetSettings();
      autoEnable = settings.autoEnable;
      hidden = settings.hidden;
    } catch { /* keep defaults */ }
  });

  async function toggleAutoEnable() {
    const prev = autoEnable;
    autoEnable = !autoEnable;
    try {
      await backend.unboundedSetSettings({ autoEnable });
    } catch {
      autoEnable = prev;
    }
  }

  async function toggleHidden() {
    const prev = hidden;
    hidden = !hidden;
    try {
      await backend.unboundedSetSettings({ hidden });
    } catch {
      hidden = prev;
    }
  }
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("back")} onclick={() => goto("/settings")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
    </button>
    <span class="title">{$_("unbounded_settings_title")}</span>
  </header>

  <div class="scroll">
    <div class="card">
      <div class="row toggle-row">
        <!-- Both rows were iconless. #3844 flags the Lantern equivalents as carrying the WRONG
             Material icons, so these are the right ones and they come from the shared component: the
             same auto glyph the Unbounded screen uses for auto-enable, and visibility_off for hiding. -->
        <span class="ic"><Icon name="autoMode" /></span>
        <div class="meta">
          <div class="name">{$_("unbounded_auto_enable")}</div>
          <div class="sub">{$_("unbounded_auto_enable_sub")}</div>
        </div>
        <button class="switch" class:on={autoEnable} role="switch" aria-checked={autoEnable} aria-label={$_("unbounded_auto_enable")} onclick={toggleAutoEnable}><span class="knob"></span></button>
      </div>
      <div class="divider"></div>
      <div class="row toggle-row">
        <span class="ic"><Icon name="visibilityOff" /></span>
        <div class="meta">
          <div class="name">{$_("unbounded_hide")}</div>
          <div class="sub">{$_("unbounded_hide_sub")}</div>
        </div>
        <button class="switch" class:on={hidden} role="switch" aria-checked={hidden} aria-label={$_("unbounded_hide")} onclick={toggleHidden}><span class="knob"></span></button>
      </div>
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
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  .title { font-size: 19px; font-weight: 700; letter-spacing: -0.2px; color: var(--text-primary); }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px 16px;
    background: none; border: none; font-family: var(--font); text-align: start;
  }
  .toggle-row { justify-content: space-between; }
  .row .ic { width: 24px; display: inline-flex; justify-content: center; color: var(--text-secondary); flex-shrink: 0; }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  .sub {
    margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary);
    letter-spacing: 0.01em;
  }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  .switch {
    width: 46px; height: 28px; border-radius: 999px; border: none; background: var(--switch-off);
    position: relative; cursor: pointer; transition: background 0.15s ease; flex-shrink: 0;
  }
  .switch.on { background: var(--toggle-on); }
  .knob {
    position: absolute; top: 3px; left: 3px; width: 22px; height: 22px;
    border-radius: 50%; background: #fff; transition: transform 0.15s ease;
  }
  .switch.on .knob { transform: translateX(18px); }
</style>
