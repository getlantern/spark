<script lang="ts">
  // The hearts that burst out of the globe when a new person starts being helped, plus the
  // "Helping a new person in …" pill that names where they are.
  //
  // Modelled on a screen recording of the Flutter/Lantern build of this screen: a cluster of rose
  // hearts appears low on the globe, drifts up and outward while fading, and a white pill with a
  // filled heart announces the country. Everything below was measured off that recording — the
  // colour by un-blending the semi-transparent hearts against the globe grey (≈#ee6a7c at ~50%),
  // the count and the spread by frame-stepping a single burst.
  //
  // DOM + CSS, not WebGL. The globe canvas is the app's one real GPU cost and its render loop is
  // deliberately paused whenever the screen is off-tab or scrolled away; adding a particle system to
  // it would tie a decorative flourish to that budget. CSS keyframes run on the compositor, cost
  // nothing when no burst is live, and are trivially disabled for reduced-motion.
  import { onDestroy } from "svelte";
  import { _ } from "$lib/i18n";

  let { trigger, countryCode }: { trigger: number; countryCode: string | null } = $props();

  const HEART_COUNT = 18;
  /** How long a single heart lives. The pill outlives it slightly so it can be read. */
  const HEART_MS = 2600;
  const PILL_MS = 3200;

  interface Heart {
    key: number;
    /** Start offset from the burst origin, in px. */
    dx: number;
    /** Drift, in px — up and outward. */
    driftX: number;
    driftY: number;
    size: number;
    delay: number;
    opacity: number;
    rotate: number;
  }

  let hearts = $state<Heart[]>([]);
  let pill = $state<string | null>(null);
  let seq = 0;
  let heartTimer: ReturnType<typeof setTimeout> | undefined;
  let pillTimer: ReturnType<typeof setTimeout> | undefined;

  /** Country name for a code, localised. Falls back to the raw code. */
  function countryName(code: string | null): string | null {
    if (!code) return null;
    try {
      // `Intl.DisplayNames` is in every runtime this app targets, and gives a translated name
      // without shipping a country table.
      const dn = new Intl.DisplayNames(undefined, { type: "region" });
      return dn.of(code.toUpperCase()) ?? code;
    } catch {
      return code;
    }
  }

  function spawn() {
    const batch: Heart[] = [];
    for (let i = 0; i < HEART_COUNT; i++) {
      seq += 1;
      // Fan out mostly upward, biased outward from centre — the recording's hearts leave the globe
      // in a loose plume rather than a symmetric ring.
      const spreadX = -26 + (Math.random() - 0.5) * 96;
      batch.push({
        key: seq,
        dx: (Math.random() - 0.5) * 54,
        driftX: spreadX,
        driftY: -66 - Math.random() * 86,
        size: 17 + Math.random() * 16,
        delay: Math.random() * 800,
        // Mixed opacity is what produces the recording's two apparent tiers of pink: the pale hearts
        // are the same colour, thinned against the light globe. Floor kept high enough that the
        // strong ones read as clearly rose rather than washed out.
        opacity: 0.55 + Math.random() * 0.45,
        rotate: (Math.random() - 0.5) * 50,
      });
    }
    hearts = batch;
    clearTimeout(heartTimer);
    heartTimer = setTimeout(() => (hearts = []), HEART_MS + 800);
  }

  // Re-run whenever the trigger advances. `trigger` is a counter rather than a boolean so two
  // arrivals in quick succession each get their own burst instead of coalescing.
  let lastTrigger = -1;
  $effect(() => {
    if (trigger === lastTrigger) return;
    lastTrigger = trigger;
    if (trigger <= 0) return;
    spawn();
    const name = countryName(countryCode);
    pill = name ? $_("unbounded_helping_new_person", { values: { country: name } }) : null;
    clearTimeout(pillTimer);
    pillTimer = setTimeout(() => (pill = null), PILL_MS);
  });

  onDestroy(() => {
    clearTimeout(heartTimer);
    clearTimeout(pillTimer);
  });
</script>

<div class="layer" aria-hidden="true">
  {#each hearts as h (h.key)}
    <span
      class="heart"
      style="
        --dx: {h.dx}px; --drift-x: {h.driftX}px; --drift-y: {h.driftY}px;
        --size: {h.size}px; --delay: {h.delay}ms; --op: {h.opacity};
        --rot: {h.rotate}deg; --life: {HEART_MS}ms;"
    >
      <!-- Material Symbols `favorite`, filled. Inline rather than via Icon.svelte because this is
           the one glyph that needs its own colour and a per-instance size. -->
      <svg viewBox="0 -960 960 960" fill="currentColor" width="100%" height="100%">
        <path d="m480-120-58-52q-101-91-167-157T150-447.5Q111-500 95.5-544T80-634q0-94 63-157t157-63q52 0 99 22t81 62q34-40 81-62t99-22q94 0 157 63t63 157q0 46-15.5 90T810-447.5Q771-395 705-329T538-172l-58 52Z" />
      </svg>
    </span>
  {/each}
</div>

{#if pill}
  <div class="pill" role="status">
    <span class="pill-heart" aria-hidden="true">
      <svg viewBox="0 -960 960 960" fill="currentColor" width="18" height="18">
        <path d="m480-120-58-52q-101-91-167-157T150-447.5Q111-500 95.5-544T80-634q0-94 63-157t157-63q52 0 99 22t81 62q34-40 81-62t99-22q94 0 157 63t63 157q0 46-15.5 90T810-447.5Q771-395 705-329T538-172l-58 52Z" />
      </svg>
    </span>
    <span>{pill}</span>
  </div>
{/if}

<style>
  /* Fills the globe mount; the hearts are positioned relative to its centre-bottom, which is roughly
     where the recording's plume originates. */
  .layer {
    position: absolute;
    inset: 0;
    overflow: visible;
    pointer-events: none;
  }
  .heart {
    position: absolute;
    left: calc(50% + var(--dx));
    bottom: 18%;
    width: var(--size);
    height: var(--size);
    color: #ee6a7c;
    opacity: 0;
    animation: rise var(--life) ease-out var(--delay) forwards;
    will-change: transform, opacity;
  }
  @keyframes rise {
    0% {
      opacity: 0;
      transform: translate(0, 0) scale(0.4) rotate(0deg);
    }
    18% {
      opacity: var(--op);
      transform: translate(calc(var(--drift-x) * 0.18), calc(var(--drift-y) * 0.18)) scale(1)
        rotate(calc(var(--rot) * 0.3));
    }
    100% {
      opacity: 0;
      transform: translate(var(--drift-x), var(--drift-y)) scale(0.85) rotate(var(--rot));
    }
  }
  .pill {
    position: absolute;
    left: 50%;
    bottom: 6px;
    transform: translateX(-50%);
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: calc(100% - 24px);
    padding: 7px 14px;
    border-radius: 9999px;
    background: var(--surface);
    box-shadow: 0 4px 32px var(--shadow);
    /* Subtitle/Small */
    font-size: 14px;
    font-weight: 600;
    line-height: 20px;
    color: var(--text-primary);
    white-space: nowrap;
    animation: pop 0.25s ease-out;
    pointer-events: none;
  }
  .pill-heart {
    display: inline-flex;
    color: #ee6a7c;
  }
  @keyframes pop {
    from {
      opacity: 0;
      transform: translateX(-50%) translateY(6px);
    }
    to {
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }
  }
  /* A celebratory flourish is exactly the kind of motion this setting exists to suppress. The pill
     still appears — it carries information, not decoration. */
  @media (prefers-reduced-motion: reduce) {
    .heart {
      animation: none;
      opacity: 0;
    }
    .pill {
      animation: none;
    }
  }
</style>
