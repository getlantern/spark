<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import {
    MockBackend,
    type SparkBackend,
    type UnboundedStatus,
    type UnboundedPeer,
  } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";
  import { listen } from "@tauri-apps/api/event";
  import Globe from "$lib/Globe.svelte";
  import Tabs from "$lib/Tabs.svelte";
  import Icon from "$lib/Icon.svelte";
  import Note from "$lib/Note.svelte";
  import HeartsBurst from "$lib/HeartsBurst.svelte";
  import { arrivals, newArrivalTracker } from "$lib/unbounded";
  import { vpnState } from "$lib/vpn_state.svelte";

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let status = $state<UnboundedStatus>({ enabled: false, helpingNow: 0, totalHelped: 0, peers: [] });
  let autoEnable = $state(false);
  // Consent state. `settingsLoaded` is a safety concern, not just UX: whether the disclosure has been
  // acknowledged is only known after an async round trip, and until it lands the user must not be able
  // to turn sharing on. Previously the page painted with a live toggle during that window, so a fast
  // click could start relaying other people's traffic before the disclosure had appeared. (The plugin
  // also refuses `unbounded_start` without consent — that backstop covers the tray, which has no
  // dialog of its own.)
  let settingsLoaded = $state(false);
  let welcomeSeen = $state(false);
  const showWelcome = $derived(settingsLoaded && !welcomeSeen);
  const consentGiven = $derived(settingsLoaded && welcomeSeen);
  let busy = $state(false);
  // Transient error banner (same shape as the settings page). Without it every failure below was
  // swallowed, so a refused start looked exactly like "I chose not to".
  let snack = $state<string | null>(null);
  let snackTimer: ReturnType<typeof setTimeout> | undefined;

  function showSnack(msg: string) {
    snack = msg;
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => (snack = null), 2500);
  }
  let poll: ReturnType<typeof setInterval>;
  let unlistenUnbounded: Promise<() => void> | undefined; // spark://unbounded subscription (Tauri only)

  // The active peer list, kept live from status. Task 6.1 binds this into <Globe {peers} />.
  const peers = $derived<UnboundedPeer[]>(status.peers);

  // Arrival detection, driving the hearts burst. A monotonic counter rather than a boolean so two
  // arrivals in quick succession produce two bursts instead of one; `seenPeers` is what makes it an
  // ARRIVAL rather than "the list changed", so a peer leaving does not celebrate.
  const tracker = newArrivalTracker();
  /**
   * Set once `status` holds a real snapshot rather than the placeholder above. Both writers set it:
   * the poll and the event stream, either of which can be first.
   */
  let statusLoaded = false;
  let burstTrigger = $state(0);
  let burstCountry = $state<string | null>(null);
  $effect(() => {
    // Reading `peers` here is what subscribes this effect to it. The decision itself lives in
    // `arrivals` — see there for why it is a pure function and not three flags inlined here.
    const fresh = arrivals(tracker, peers, statusLoaded);
    if (fresh.length === 0) return;
    // The newest arrival names the pill. Peers without geo still burst — we know someone arrived,
    // we just cannot say where from, and silence would under-report the thing the screen exists
    // to show.
    burstCountry = fresh[fresh.length - 1].geo?.countryCode ?? null;
    burstTrigger += 1;
  });

  async function refresh() {
    try {
      status = await backend.unboundedStatus();
      statusLoaded = true;
    } catch { /* keep last-known */ }
    // Switching tabs doesn't disconnect the VPN — keep the shared dot state live so the
    // tab bar's VPN dot stays green here while the tunnel is connected.
    try { vpnState.connected = (await backend.status()).state === "connected"; } catch { /* keep last-known */ }
  }

  async function toggle() {
    if (busy) return;
    // Never start sharing before the disclosure has been shown and acknowledged (stopping is always
    // allowed). Belt-and-braces with the plugin-side check.
    if (!status.enabled && !consentGiven) return;
    busy = true;
    try {
      if (status.enabled) {
        await backend.unboundedStop();
      } else {
        await backend.unboundedStart();
      }
      await refresh();
    } catch {
      // Surface it: a start can legitimately fail (feature not available for this client, bad
      // signaling endpoint, persist error), and a silent snap-back is indistinguishable from a
      // deliberate decline.
      showSnack($_("unbounded_err_toggle"));
      await refresh();
    } finally {
      busy = false;
    }
  }

  async function toggleAutoEnable() {
    const prev = autoEnable;
    autoEnable = !autoEnable;
    try {
      await backend.unboundedSetSettings({ autoEnable });
    } catch {
      autoEnable = prev;
      showSnack($_("err_save_changes"));
    }
  }

  async function dismissWelcome() {
    try {
      await backend.unboundedSetSettings({ welcomeSeen: true });
      welcomeSeen = true;
    } catch {
      // Keep the dialog up rather than letting a failed write leave the user "consented" in this
      // session only — the plugin would refuse the start anyway, which would be baffling.
      showSnack($_("err_save_changes"));
    }
  }

  onMount(() => {
    refresh();
    (async () => {
      try {
        const settings = await backend.unboundedGetSettings();
        autoEnable = settings.autoEnable;
        welcomeSeen = settings.welcomeSeen;
        settingsLoaded = true;
      } catch {
        // Leave `settingsLoaded` false: consent is unknown, so the toggle stays inert rather than
        // assuming consent was given.
        showSnack($_("unbounded_err_settings"));
      }
    })();
    poll = setInterval(refresh, 2000);
    // Keep the stats live between polls: the plugin emits spark://unbounded with the full status
    // shape on every peer/enable change. Tauri-only (`listen` rejects in a plain browser), matching
    // the home screen's guard.
    if (isTauri()) {
      unlistenUnbounded = listen<UnboundedStatus>("spark://unbounded", (e) => {
        status = e.payload;
        statusLoaded = true;
      });
    }
  });
  onDestroy(() => {
    clearInterval(poll);
    clearTimeout(snackTimer);
    unlistenUnbounded?.then((f) => f()).catch(() => {});
  });
</script>

<main class="app">
  <header class="appbar">
    <button class="iconbtn" aria-label={$_("menu")} onclick={() => goto("/settings")}>
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
    </button>
    <span class="title">{$_("unbounded_title")}</span>
    <span class="iconbtn spacer" aria-hidden="true"></span>
  </header>

  <Tabs current="unbounded" vpnOn={vpnState.connected} unboundedOn={status.enabled} />

  <div class="scroll">
    <Note text={$_("unbounded_help_banner")} />

    <div class="globe-mount">
      <Globe {peers} />
      <HeartsBurst trigger={burstTrigger} countryCode={burstCountry} waiting={status.enabled && peers.length === 0} />
    </div>

    <div class="card">
      <div class="row toggle-row">
        <span class="ic status-ic"><Icon name="language" /></span>
        <div class="meta">
          <div class="name">{$_("unbounded_status")}: <span class="state" class:on={status.enabled}>{status.enabled ? $_("unbounded_state_enabled") : $_("unbounded_state_disabled")}</span></div>
        </div>
        <button class="switch" class:on={status.enabled} role="switch" aria-checked={status.enabled} aria-busy={busy} aria-label={$_("unbounded_status")} disabled={!status.enabled && !consentGiven} onclick={toggle}><span class="knob"></span></button>
      </div>
      <div class="divider"></div>
      <div class="row stat-row">
        <span class="ic"><Icon name="person" /></span>
        <div class="meta"><div class="name">{$_("unbounded_helping_now")}</div></div>
        <span class="stat">{status.helpingNow}</span>
      </div>
      <div class="divider"></div>
      <div class="row stat-row">
        <span class="ic"><Icon name="group" /></span>
        <div class="meta"><div class="name">{$_("unbounded_total_helped")}</div></div>
        <span class="stat">{status.totalHelped}</span>
      </div>
    </div>

    <div class="card" style="margin-top:12px">
      <div class="row toggle-row">
        <span class="ic"><Icon name="autoMode" /></span>
        <div class="meta">
          <div class="name">{$_("unbounded_auto_enable")}</div>
          <div class="sub">{$_("unbounded_auto_enable_sub")}</div>
        </div>
        <button class="checkbox" class:on={autoEnable} role="checkbox" aria-checked={autoEnable} aria-label={$_("unbounded_auto_enable")} onclick={toggleAutoEnable}>
          {#if autoEnable}<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>{/if}
        </button>
      </div>
    </div>
  </div>
</main>


{#if showWelcome}
  <div class="overlay" role="dialog" aria-modal="true" aria-labelledby="unbounded-welcome-title">
    <div class="dialog">
      <h2 id="unbounded-welcome-title">{$_("unbounded_welcome_title")}</h2>
      <p>{$_("unbounded_welcome_body")}</p>
      <p class="risks">{$_("unbounded_welcome_risks")}</p>
      <button class="primary" onclick={dismissWelcome}>{$_("unbounded_welcome_dismiss")}</button>
    </div>
  </div>
{/if}

{#if snack}<div class="snack">{snack}</div>{/if}

<style>
  .snack { position: fixed; left: 16px; right: 16px; bottom: 20px; background: var(--snack-bg); color: #fff; padding: 12px 16px; border-radius: 10px; font-size: 14px; text-align: center; box-shadow: 0 6px 24px rgba(0,0,0,.25); z-index: 10; }
  .switch:disabled { opacity: .5; cursor: not-allowed; }
  .risks { font-size: 13px; opacity: .85; }
  .app { height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  .appbar {
    height: 56px; flex-shrink: 0; display: flex; align-items: center; gap: 4px; padding: 0 8px;
    background: var(--bg);
  }
  .iconbtn {
    width: 40px; height: 40px; border: none; background: none; cursor: pointer;
    display: grid; place-items: center; color: var(--text-tertiary); border-radius: 8px;
  }
  .spacer { visibility: hidden; }
  :global([dir="rtl"]) .iconbtn svg { transform: scaleX(-1); }
  /* Centered, bold, uppercase title flanked by the menu button + an equal-width spacer. */
  .title {
    flex: 1; text-align: center; font-size: 20px; font-weight: 800; letter-spacing: 1px;
    text-transform: uppercase; color: var(--text-primary);
  }

  .scroll { flex: 1; overflow-y: auto; padding: 12px 16px 20px; }


  /* The globe is the hero of the screen — it floats directly on the page background (no card),
     centered, matching the design.

     `overflow: hidden` used to live here and was the cause of "the globe drop shadow is cut off at
     the top" (getlantern/engineering#3844 round 2): a clipping box cannot show an effect that by
     definition extends past the element. It is gone, and the glow is drawn behind the canvas where
     it has room. `position: relative` makes this the containing block for the hearts overlay. */
  .globe-mount {
    position: relative;
    margin-top: 2px;
    height: 268px;
    display: grid;
    place-items: center;
  }
  /* A soft cyan halo hugging the sphere, which is what the Flutter build actually shows — not the
     ground shadow this once had. Sampled at ~#e8f0f0 where the halo meets the page, which is this
     colour at the falloff's outer edge; Figma's `Globe` effect is DROP_SHADOW #00616342 radius 64,
     and round 2 asked to halve its intensity, so the core alpha here is half of that ~0.26. */
  .globe-mount::before {
    content: "";
    grid-area: 1 / 1;
    /* Tighter than the sphere plus a wide margin: sampled off the recording, the page tint is gone
       by about a quarter of a radius past the rim (#E9F0F3 at 1.2 radii, page colour by 1.4). The
       globe is ~188px across here, so a 224px halo is that ring and no more — at 250 it read as a
       distinct disc sitting behind the globe. */
    width: 224px;
    height: 224px;
    border-radius: 50%;
    background: radial-gradient(
      circle at 50% 50%,
      rgba(0, 97, 99, 0.13) 0%,
      rgba(0, 150, 160, 0.10) 58%,
      rgba(0, 170, 180, 0.05) 76%,
      rgba(0, 170, 180, 0) 100%
    );
    pointer-events: none;
  }
  .globe-mount > :global(.globe) {
    grid-area: 1 / 1;
  }

  .card {
    background: var(--surface); border-radius: 16px; box-shadow: 0 4px 32px var(--shadow);
    overflow: hidden; margin-top: 12px;
  }
  .row {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px 16px;
    background: none; border: none; font-family: var(--font); text-align: start;
  }
  .toggle-row, .stat-row { justify-content: space-between; }
  .row .ic { width: 24px; display: inline-flex; justify-content: center; color: var(--text-secondary); flex-shrink: 0; }
  /* #3844 round 2: "the icon next to the toggle status is the incorrect color". It is the row that
     names the feature's state, so it carries the link tone rather than the generic row grey. */
  .row .ic.status-ic { color: var(--link); }
  .meta { flex: 1; min-width: 0; }
  .name { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  /* "Status: Enabled" — the state word turns green when sharing is on. */
  .state { font-weight: 700; color: var(--text-tertiary); }
  .state.on { color: var(--dot-success-bg); }
  .sub {
    margin-top: 2px; font-size: 12px; font-weight: 500; color: var(--text-tertiary);
    letter-spacing: 0.01em;
  }
  .divider { height: 1px; background: var(--border); margin: 0 16px; }

  /* Stat values: prominent teal numbers, right-aligned (no pill). */
  .stat { font-size: 16px; font-weight: 700; color: var(--link); white-space: nowrap; }

  .switch {
    width: 46px; height: 28px; border-radius: 999px; border: none; background: var(--switch-off);
    position: relative; cursor: pointer; transition: background 0.15s ease; flex-shrink: 0;
  }
  /* Enabled state is green per the design (not the app brand cyan). */
  .switch.on { background: var(--toggle-on); }
  .knob {
    position: absolute; top: 3px; left: 3px; width: 22px; height: 22px;
    border-radius: 50%; background: #fff; transition: transform 0.15s ease;
  }
  .switch.on .knob { transform: translateX(18px); }

  /* Auto-enable is a checkbox in the design, not a switch: an outlined square that fills
     dark-teal with a white check when on. */
  .checkbox {
    width: 26px; height: 26px; flex-shrink: 0; border-radius: 7px; cursor: pointer;
    display: grid; place-items: center; color: #fff;
    background: transparent; border: 1.5px solid var(--border);
    transition: background 0.15s ease, border-color 0.15s ease;
  }
  .checkbox.on { background: var(--link); border-color: var(--link); }

  /* One-time onboarding dialog, styled off the app's surface/card tokens. */
  .overlay {
    position: fixed; inset: 0; z-index: 10;
    display: grid; place-items: center; padding: 24px;
    background: rgba(0, 0, 0, 0.45);
  }
  .dialog {
    width: 100%; max-width: 340px;
    background: var(--surface); border-radius: 16px; padding: 24px;
    box-shadow: 0 12px 48px rgba(0, 0, 0, 0.35);
  }
  .dialog h2 { margin: 0 0 10px; font-size: 20px; font-weight: 700; color: var(--text-primary); }
  .dialog p { margin: 0 0 20px; font-size: 14px; font-weight: 500; line-height: 1.5; color: var(--text-secondary); }
  .primary {
    width: 100%; padding: 12px 16px; border: none; border-radius: 10px; cursor: pointer;
    background: var(--brand, #1f9d55); color: #fff; font-family: var(--font);
    font-size: 15px; font-weight: 600;
  }
</style>
