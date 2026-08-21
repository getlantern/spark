<script lang="ts">
  // The status indicator light: a filled dot inside a lighter ring.
  //
  // ONE component, used by every place that shows on/off state — the tab bar's VPN and Unbounded
  // lights and the VPN status panel. The Lantern implementation of this feature grew a second,
  // flat-coloured dot for the tab bar, which is the first item on
  // getlantern/engineering#3844 ("should reuse the existing indicator light component from the VPN
  // status panel"). Two implementations of one visual cannot stay in step, and the ring is exactly
  // the part an ad-hoc copy leaves out.
  //
  // The ring is not decoration: Figma defines `status/*-border-dot` alongside `status/*-bg-dot` for
  // both states, and without it the dot reads as noticeably smaller and harsher than the design.
  let {
    on = false,
    size = 10,
    label,
  }: {
    on?: boolean;
    size?: number;
    /** Accessible name. Omit when an adjacent text label already carries the meaning. */
    label?: string;
  } = $props();
</script>

<span
  class="dot"
  class:on
  style="--dot-size: {size}px"
  role={label ? "img" : "presentation"}
  aria-label={label}
  aria-hidden={label ? undefined : "true"}
></span>

<style>
  .dot {
    width: var(--dot-size);
    height: var(--dot-size);
    border-radius: 50%;
    flex-shrink: 0;
    /* Figma: status/neutral-bg-dot on status/neutral-border-dot. The ring is drawn as a box-shadow
       rather than a border so the dot's own size stays exactly `--dot-size` — a border would grow
       the element and shift the text beside it. */
    background: var(--dot-neutral-bg);
    box-shadow: 0 0 0 2px var(--dot-neutral-border);
    transition:
      background 0.15s ease,
      box-shadow 0.15s ease;
  }
  .dot.on {
    background: var(--dot-success-bg);
    box-shadow: 0 0 0 2px var(--dot-success-border);
  }
</style>
