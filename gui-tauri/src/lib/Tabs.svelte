<script lang="ts">
  // The VPN / Unbounded tab strip, directly under the app title.
  //
  // Replaces the former `BottomTabs`, which was wrong in shape as well as in detail: the desktop
  // design (Figma `Lantern-VPN` 4734:5499 / 4734:5498) puts this strip at the TOP under the title,
  // with icon and label side by side, and a divider closing the whole header. The old component sat
  // at the bottom with a `border-top` and stacked the icon above the label.
  //
  // Every spec here is from the design or from the list of mistakes the Lantern implementation of
  // this same strip made (getlantern/engineering#3844), so the notes say which:
  //
  //   - 40px selected pill that HUGS its content with 24px side padding (not a stretched segment)
  //   - the pill (and the hover highlight) are pill-shaped, not squared
  //   - `Subtitle/Small` = Urbanist SemiBold 14/20
  //   - semantic tokens for the selected colours, so dark mode is not a guess
  //   - Material Symbols, outlined when unselected and FILLED when selected
  //   - a two-tone indicator light per tab, reusing `Indicator.svelte`
  //   - a divider below the strip, spanning the header
  //
  // Mobile gets a bottom bar in the design; spark's Unbounded surface is desktop-only today (the
  // sharing pool is `cfg(desktop)`), so that layout is deliberately not built here rather than
  // built blind — the Lantern equivalent shipped unverified on a simulator it never ran on.
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";
  import Icon from "$lib/Icon.svelte";
  import Indicator from "$lib/Indicator.svelte";

  let {
    current,
    vpnOn = false,
    unboundedOn = false,
  }: { current: "vpn" | "unbounded"; vpnOn?: boolean; unboundedOn?: boolean } = $props();

  const vpnSelected = $derived(current === "vpn");
  const unboundedSelected = $derived(current === "unbounded");
</script>

<nav class="tabs" aria-label={$_("tabs_primary")}>
  <button
    class="seg"
    class:active={vpnSelected}
    aria-current={vpnSelected ? "page" : undefined}
    onclick={() => !vpnSelected && goto("/")}
  >
    <Icon name={vpnSelected ? "vpnKeyFill" : "vpnKey"} size={22} />
    <span class="label">{$_("tab_vpn")}</span>
    <!-- Labelled, unlike the one in the VPN status panel. There the adjacent text already says
         "Connected"/"Disconnected"; here the tab text names the DESTINATION and nothing carries the
         state, and the strip is in fact the only place the OTHER tab's state is shown at all. -->
    <Indicator
      on={vpnOn}
      label={$_(vpnOn ? "indicator_on" : "indicator_off", { values: { feature: $_("tab_vpn") } })}
    />
  </button>

  <button
    class="seg"
    class:active={unboundedSelected}
    aria-current={unboundedSelected ? "page" : undefined}
    onclick={() => !unboundedSelected && goto("/unbounded")}
  >
    <Icon name={unboundedSelected ? "handshakeFill" : "handshake"} size={22} />
    <span class="label">{$_("tab_unbounded")}</span>
    <Indicator
      on={unboundedOn}
      label={$_(unboundedOn ? "indicator_on" : "indicator_off", {
        values: { feature: $_("tab_unbounded") },
      })}
    />
  </button>
</nav>

<style>
  .tabs {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    /* Extra bottom padding: #3844 round 2 asked for "more padding below the selected pill", which in
       the Lantern fix turned out to be a strip whose computed height was ~42px against the design's
       56px. 8px above + 40px pill + 8px below is that 56px exactly. */
    padding: 8px 16px;
    background: var(--surface);
    /* Closes the whole header, per "missing a dividing line below the tab bar". */
    border-bottom: 1px solid var(--border);
  }
  .seg {
    /* Hugs its content — deliberately NOT `flex: 1`. The design's pill wraps the icon+label+dot;
       stretching it to fill the row is what made the old one read as a segmented control. */
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 40px;
    padding: 0 24px;
    border: 1px solid transparent;
    border-radius: 9999px;
    background: transparent;
    color: var(--tabbar-text);
    font-family: var(--font);
    /* Subtitle/Small */
    font-size: 14px;
    font-weight: 600;
    line-height: 20px;
    cursor: pointer;
    transition:
      background 0.15s ease,
      color 0.15s ease,
      border-color 0.15s ease;
  }
  /* Pill-shaped, matching the selected pill — a squared highlight behind pill-shaped content was
     its own line item. `border-radius` is inherited from `.seg`, so this only needs the fill. */
  .seg:hover:not(.active) {
    background: var(--hover);
    color: var(--text-secondary);
  }
  .seg.active {
    background: var(--tabbar-bg);
    border-color: var(--tabbar-border);
    color: var(--tabbar-selected-text);
    cursor: default;
  }
  .label {
    white-space: nowrap;
  }
</style>
