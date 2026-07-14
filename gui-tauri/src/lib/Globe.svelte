<script lang="ts">
  // WebGL globe for the Unbounded screen: draws a great-circle arc from a fixed HOME point to each
  // live volunteer peer. Perf is Lantern's #1 hotspot, so this component is deliberately quiet:
  //   - globe.gl (three.js) is loaded via a DYNAMIC import inside onMount, so it lands in a lazy
  //     chunk and never bloats the app's initial bundle.
  //   - the globe is STATIC at rest (no auto-rotation); it only animates when a NEW peer arrives.
  //   - the render loop is paused whenever the canvas is off-screen or the tab is hidden.
  //   - arcs are capped and cleared when the peer list empties.
  import { onMount, onDestroy } from "svelte";
  import type { UnboundedPeer } from "$lib/spark_backend";

  let { peers = [] }: { peers: UnboundedPeer[] } = $props();

  // Fixed origin for every arc. A neutral mid-Atlantic point (lat 20, lng 0) keeps both Europe/MENA
  // and the Americas in frame, and reads as "from the free internet" rather than any one country.
  const HOME = { lat: 20, lng: 0 };
  const MAX_ARCS = 50;

  interface Arc {
    id: string;
    startLat: number;
    startLng: number;
    endLat: number;
    endLng: number;
  }

  let el = $state<HTMLDivElement>();
  // globe.gl's instance is untyped here to avoid pulling three's types into this module's surface.
  let globe: any = null;
  let arcs: Arc[] = [];
  let rendered = false; // globe created and initial draw done
  let onScreen = true;
  let tabVisible = true;
  let io: IntersectionObserver | undefined;
  let ro: ResizeObserver | undefined;

  function accent(): string {
    if (typeof window === "undefined" || !el) return "#00bdd6";
    const v = getComputedStyle(el).getPropertyValue("--brand").trim();
    return v || "#00bdd6";
  }

  // The render loop should run only while both visible on-screen and on an active tab. globe.gl
  // exposes pause/resume for exactly this; gating on both signals keeps the GPU idle in the common
  // case (screen scrolled away, or app backgrounded).
  function syncAnimation() {
    if (!globe) return;
    if (onScreen && tabVisible) globe.resumeAnimation();
    else globe.pauseAnimation();
  }

  function onVisibility() {
    tabVisible = document.visibilityState === "visible";
    syncAnimation();
  }

  function resize() {
    if (!globe || !el) return;
    globe.width(el.clientWidth).height(el.clientHeight);
  }

  // Recompute the arc set from the current peers, capped at MAX_ARCS. Returns the ids that are new
  // since the last render so the caller can animate toward the freshest arrival.
  function rebuildArcs(prevIds: Set<string>): string[] {
    const next: Arc[] = [];
    const fresh: string[] = [];
    for (const p of peers) {
      if (!p.geo) continue;
      if (next.length >= MAX_ARCS) break;
      next.push({
        id: p.sessionId,
        startLat: HOME.lat,
        startLng: HOME.lng,
        endLat: p.geo.lat,
        endLng: p.geo.lon,
      });
      if (!prevIds.has(p.sessionId)) fresh.push(p.sessionId);
    }
    arcs = next;
    return fresh;
  }

  onMount(() => {
    if (typeof window === "undefined" || !el) return;

    let disposed = false;
    (async () => {
      const GlobeGl = (await import("globe.gl")).default;
      if (disposed || !el) return;

      const color = accent();
      const asArc = (o: object) => o as Arc;
      globe = new GlobeGl(el)
        .width(el.clientWidth)
        .height(el.clientHeight)
        .backgroundColor("rgba(0,0,0,0)")
        .showGlobe(true)
        .showAtmosphere(true)
        .atmosphereColor(color)
        .atmosphereAltitude(0.18)
        .arcStartLat((o: object) => asArc(o).startLat)
        .arcStartLng((o: object) => asArc(o).startLng)
        .arcEndLat((o: object) => asArc(o).endLat)
        .arcEndLng((o: object) => asArc(o).endLng)
        .arcColor(() => [`${color}00`, color])
        .arcStroke(0.5)
        .arcAltitudeAutoScale(0.4)
        .arcDashLength(0.5)
        .arcDashGap(1)
        .arcDashAnimateTime(1600);
      // A plain colored sphere (no image texture) keeps the lazy chunk lean.
      globe.globeImageUrl(null as unknown as string);

      // Static at rest: no auto-rotation. Users may still drag/zoom the orbit controls.
      globe.controls().autoRotate = false;
      globe.controls().enableZoom = false;
      globe.pointOfView({ lat: HOME.lat, lng: HOME.lng, altitude: 2.4 });

      rendered = true;
      // Draw whatever peers already exist at mount time.
      rebuildArcs(new Set());
      globe.arcsData(arcs);
      syncAnimation();

      io = new IntersectionObserver(
        (entries) => {
          onScreen = entries.some((e) => e.isIntersecting);
          syncAnimation();
        },
        { threshold: 0 },
      );
      io.observe(el);

      ro = new ResizeObserver(() => resize());
      ro.observe(el);
    })();

    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      disposed = true;
    };
  });

  // Diff peers on every change: add newly-arrived arcs, drop departed ones, clear on empty. The
  // scene is never rebuilt — we only hand globe.gl the freshly capped list. When a peer arrives,
  // pan toward it so the arrival reads as a deliberate, one-off motion (the only time we move).
  $effect(() => {
    // Track peers so this effect re-runs when the list changes.
    const current = peers;
    if (!rendered || !globe) return;

    const prevIds = new Set(arcs.map((a) => a.id));
    const fresh = rebuildArcs(prevIds);
    globe.arcsData(arcs);

    if (current.length === 0) return; // cleared; leave the globe parked
    const newest = fresh.length ? arcs.find((a) => a.id === fresh[fresh.length - 1]) : undefined;
    if (newest) {
      globe.pointOfView({ lat: newest.endLat, lng: newest.endLng, altitude: 2.4 }, 900);
    }
  });

  onDestroy(() => {
    document.removeEventListener("visibilitychange", onVisibility);
    io?.disconnect();
    ro?.disconnect();
    globe?.pauseAnimation?.();
    globe?._destructor?.();
    globe = null;
  });
</script>

<div class="globe" bind:this={el}></div>

<style>
  .globe {
    width: 100%;
    height: 100%;
    border-radius: 16px;
    overflow: hidden;
  }
</style>
