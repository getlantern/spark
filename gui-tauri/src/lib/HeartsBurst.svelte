<script lang="ts">
  // The hearts that burst out of the globe when a new person starts being helped, plus the
  // "Helping a new person in …" pill that names where they are.
  //
  // The reference (Flutter/Lantern) plays a Lottie file, `assets/unbounded/explosion.json`. Rather
  // than add a Lottie runtime to spark for one decorative flourish, the animation's data was read
  // out of that file and is reproduced here in CSS. Everything below is transcribed from it, not
  // guessed and not eyeballed off a video:
  //
  //   - a 420 x 502 canvas, and every heart starts at the SAME point on it: (121, 437.2), low-left
  //   - 14 hearts, each with a FIXED destination — the fan is authored, not random, which is why
  //     it reads as a designed plume rather than a scatter
  //   - 3.0s of motion (90 frames at 30fps), easing cubic-bezier(0, 0, .58, 1)
  //   - opacity 100 -> 0 over that same 3.0s, on the same curve
  //   - a small final rotation per heart, between -10 and +20 degrees
  //   - NO scale animation: the hearts do not pop in, they are full size from the first frame
  //   - fill #FF5A79 at full opacity on every heart
  //
  // Two details that a video alone would get wrong. The apparent two tiers of pink are NOT per-heart
  // alpha — every fill is opaque and every heart fades identically. They are OVERLAPPING BURSTS: a
  // new arrival spawns its batch while the previous batch is still fading, so a strong set and a
  // faint set are on screen together. Hence `spawn` appends rather than replaces. And the heart is
  // not a Material glyph but the `getlantern/unbounded` shape (viewBox 0 0 32 27), which is
  // noticeably wider and flatter than Material's `favorite`.
  //
  // CSS keyframes, not a particle system in the globe's WebGL context: the globe canvas is the app's
  // one real GPU cost and its render loop is deliberately paused when the screen is off-tab or
  // scrolled away. Keyframes run on the compositor, cost nothing when no burst is live, and are
  // trivially disabled for reduced-motion.
  import { onDestroy } from "svelte";
  import { _ } from "$lib/i18n";

  let {
    trigger,
    countryCode,
    waiting = false,
  }: {
    trigger: number;
    countryCode: string | null;
    /**
     * Show the idle pill — "Waiting for connections…" — when there is no arrival to announce.
     *
     * The reference switches one pill slot between an arrival card and a waiting card, so both live
     * here rather than in the page: they are the same chrome in the same place, and splitting them
     * is how they drift apart.
     */
    waiting?: boolean;
  } = $props();

  /** The Lottie composition's canvas. All coordinates below are in its units. */
  const CANVAS_W = 420;
  const CANVAS_H = 502;
  /** Where every heart is born. */
  const ORIGIN = { x: 121, y: 437.2 };
  /** The heart artwork's own size on that canvas. */
  const HEART_W = 32;
  const HEART_H = 27;
  /** Motion duration, and the fade, in ms — 90 frames at 30fps. */
  const FLY_MS = 3000;
  /** Lottie's `i: {x: .58, y: 1}` / `o: {x: 0, y: 0}` handles, i.e. a plain ease-out. */
  const EASE = "cubic-bezier(0, 0, 0.58, 1)";
  const PILL_MS = 3200;

  /** The 14 authored destinations, with each heart's final rotation. Straight from the Lottie. */
  const FAN: { x: number; y: number; rot: number }[] = [
    { x: 187.1, y: 388.0, rot: 12.8 },
    { x: 57.0, y: 292.3, rot: 13.6 },
    { x: 347.0, y: 349.7, rot: 0 },
    { x: 363.0, y: 193.7, rot: -10.2 },
    { x: 41.0, y: 180.9, rot: -7.6 },
    { x: 189.5, y: 216.9, rot: 0 },
    { x: 270.4, y: 139.3, rot: -8.3 },
    { x: 249.0, y: 317.9, rot: 19.7 },
    { x: 89.0, y: 96.6, rot: 0 },
    { x: 272.0, y: 46.7, rot: 0 },
    { x: 347.0, y: 71.0, rot: 0 },
    { x: 152.6, y: 62.9, rot: 20.2 },
    { x: 108.7, y: 186.6, rot: 20.4 },
    { x: 397.0, y: 264.0, rot: -9.8 },
  ];

  interface Heart {
    key: number;
    /** Start and end offsets, already in px and already centred on the heart. */
    fx: number;
    fy: number;
    tx: number;
    ty: number;
    size: number;
    rot: number;
  }

  let layer = $state<HTMLDivElement>();
  let hearts = $state<Heart[]>([]);
  let pill = $state<string | null>(null);
  let seq = 0;
  const timers = new Set<ReturnType<typeof setTimeout>>();

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

  /**
   * Where the burst's origin should land inside the mount, as a fraction of its box.
   *
   * The recording starts its plume at the globe's LOWER LEFT — not at the middle, and not below the
   * globe. Centring the canvas instead puts the origin about 30px below the mount's bottom edge (the
   * canvas is much taller than the mount), which buries the first second of every burst behind the
   * status card. Anchoring the origin itself is what keeps the plume on the sphere.
   */
  const ORIGIN_AT = { x: 0.35, y: 0.72 };

  /**
   * Map the Lottie canvas onto the mount.
   *
   * Fitted to WIDTH, not contained: at the mount's proportions a contain fit would letterbox to
   * about 60% scale, and the recording's hearts are ~30px across on a 398px-wide window, which is
   * the width fit (~0.87) and not the contain fit (~0.62). The canvas is taller than the mount, so it
   * deliberately overhangs top and bottom — that is what lets the plume rise past the globe, as it
   * does in the recording, where hearts reach up into the note above.
   */
  function mapping() {
    const w = layer?.clientWidth ?? 0;
    const h = layer?.clientHeight ?? 0;
    const scale = w / CANVAS_W;
    return {
      scale,
      offX: ORIGIN_AT.x * w - ORIGIN.x * scale,
      offY: ORIGIN_AT.y * h - ORIGIN.y * scale,
    };
  }

  function spawn() {
    const { scale, offX, offY } = mapping();
    if (!(scale > 0)) return;
    const size = HEART_W * scale;
    // Lottie positions are the heart's CENTRE (its layer anchor is 16, 12.78), so shift by half the
    // artwork to get a top-left offset for `translate`.
    const half = { x: size / 2, y: (HEART_H * scale) / 2 };
    const fx = offX + ORIGIN.x * scale - half.x;
    const fy = offY + ORIGIN.y * scale - half.y;
    const batch = FAN.map((f) => {
      seq += 1;
      return {
        key: seq,
        fx,
        fy,
        tx: offX + f.x * scale - half.x,
        ty: offY + f.y * scale - half.y,
        size,
        rot: f.rot,
      };
    });
    // APPEND, not replace: overlapping bursts are what produce the reference's two tiers of pink.
    hearts = [...hearts, ...batch];
    const keys = new Set(batch.map((b) => b.key));
    const t = setTimeout(() => {
      hearts = hearts.filter((h) => !keys.has(h.key));
      timers.delete(t);
    }, FLY_MS + 200);
    timers.add(t);
  }

  // Re-run whenever the trigger advances. `trigger` is a counter rather than a boolean so two
  // arrivals in quick succession each get their own burst instead of coalescing.
  let lastTrigger = -1;
  let pillTimer: ReturnType<typeof setTimeout> | undefined;
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
    clearTimeout(pillTimer);
    for (const t of timers) clearTimeout(t);
    timers.clear();
  });
</script>

<div class="layer" bind:this={layer} aria-hidden="true">
  {#each hearts as h (h.key)}
    <span
      class="heart"
      style="
        --fx: {h.fx.toFixed(1)}px; --fy: {h.fy.toFixed(1)}px;
        --tx: {h.tx.toFixed(1)}px; --ty: {h.ty.toFixed(1)}px;
        --size: {h.size.toFixed(1)}px; --rot: {h.rot}deg;
        --fly: {FLY_MS}ms; --ease: {EASE};"
    >
      <!-- The `getlantern/unbounded` heart, exact path coords. Inline rather than via Icon.svelte
           because that table is Material Symbols on a 0 -960 960 960 viewBox, and this is neither. -->
      <svg viewBox="0 0 32 27" fill="currentColor" width="100%" height="100%">
        <path
          d="M31.5035 5.87209C28.0938 -3.18494 17.0123 0.864084 16 5.3926C14.6148 0.597701 3.79965 -2.97183 0.496497 5.87209C-3.17959 15.7283 14.7214 24.5722 16 26.0107C17.2786 24.8386 35.1796 15.5684 31.5035 5.87209Z"
        />
      </svg>
    </span>
  {/each}
</div>

{#if pill}
  <div class="pill" role="status">
    <span class="pill-heart" aria-hidden="true">
      <svg viewBox="0 0 32 27" fill="currentColor" width="19" height="16">
        <path
          d="M31.5035 5.87209C28.0938 -3.18494 17.0123 0.864084 16 5.3926C14.6148 0.597701 3.79965 -2.97183 0.496497 5.87209C-3.17959 15.7283 14.7214 24.5722 16 26.0107C17.2786 24.8386 35.1796 15.5684 31.5035 5.87209Z"
        />
      </svg>
    </span>
    <span>{pill}</span>
  </div>
{:else if waiting}
  <div class="pill" role="status">
    <span>{$_("unbounded_waiting_for_connections")}</span>
  </div>
{/if}

<style>
  /* Fills the globe mount and measures it; the canvas is mapped onto it in `mapping()`. */
  .layer {
    position: absolute;
    inset: 0;
    overflow: visible;
    pointer-events: none;
  }
  .heart {
    position: absolute;
    left: 0;
    top: 0;
    width: var(--size);
    /* The artwork is 32 x 27, so let the box follow it rather than forcing a square. */
    aspect-ratio: 32 / 27;
    height: auto;
    color: #ff5a79;
    animation: fly var(--fly) var(--ease) forwards;
    will-change: transform, opacity;
  }
  /* Position lives in the transform, not in `left`/`top`, so the whole flight stays on the
     compositor. No scale term — the reference's hearts are full size from the first frame. */
  @keyframes fly {
    from {
      opacity: 1;
      transform: translate(var(--fx), var(--fy)) rotate(0deg);
    }
    to {
      opacity: 0;
      transform: translate(var(--tx), var(--ty)) rotate(var(--rot));
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
    /* Reference chrome: 16/10 padding, fully round, the surface at 92%, a hairline black border. */
    padding: 10px 16px;
    border-radius: 100px;
    background: color-mix(in srgb, var(--surface) 92%, transparent);
    border: 1px solid rgba(0, 0, 0, 0.12);
    box-shadow: 0 4px 32px var(--shadow);
    font-size: 13px;
    font-weight: 500;
    line-height: 18px;
    color: var(--text-secondary);
    white-space: nowrap;
    animation: pop 0.25s ease-out;
    pointer-events: none;
  }
  .pill-heart {
    display: inline-flex;
    color: #ff5a79;
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
