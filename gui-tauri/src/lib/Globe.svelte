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
  // Arc colors alternate teal / gold to match the design's multi-color arcs.
  const ARC_COLORS = ["#22c3d6", "#f0b429"];

  interface Arc {
    id: string;
    startLat: number;
    startLng: number;
    endLat: number;
    endLng: number;
    color: string;
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
        color: ARC_COLORS[next.length % ARC_COLORS.length],
      });
      if (!prevIds.has(p.sessionId)) fresh.push(p.sessionId);
    }
    arcs = next;
    return fresh;
  }

  // The green endpoint dots — one per current arc's peer location.
  function arcPoints(): { lat: number; lng: number }[] {
    return arcs.map((a) => ({ lat: a.endLat, lng: a.endLng }));
  }

  onMount(() => {
    if (typeof window === "undefined" || !el) return;

    let disposed = false;
    (async () => {
      const GlobeGl = (await import("globe.gl")).default;
      if (disposed || !el) return;

      const asArc = (o: object) => o as Arc;
      globe = new GlobeGl(el)
        .width(el.clientWidth)
        .height(el.clientHeight)
        .backgroundColor("rgba(0,0,0,0)")
        .showGlobe(true)
        .showAtmosphere(true)
        // Soft, near-white halo to match the light globe in the design.
        .atmosphereColor("#cfe4ef")
        .atmosphereAltitude(0.14)
        .arcStartLat((o: object) => asArc(o).startLat)
        .arcStartLng((o: object) => asArc(o).startLng)
        .arcEndLat((o: object) => asArc(o).endLat)
        .arcEndLng((o: object) => asArc(o).endLng)
        // Per-arc color (teal/gold), a solid gradient that stays visible along its whole length
        // and reads prominently over the light globe (matching the design's bold arcs).
        .arcColor((o: object) => {
          const c = asArc(o).color;
          return [`${c}66`, c];
        })
        .arcStroke(1.6)
        .arcAltitudeAutoScale(0.62)
        .arcDashLength(1)
        .arcDashGap(0)
        .arcDashAnimateTime(0)
        // A green dot at each peer endpoint, as in the design.
        .pointColor(() => "#33a852")
        .pointAltitude(0.012)
        .pointRadius(0.34);
      // Design palette: a GREY ocean sphere with WHITE continents drawn on top (no texture — keeps
      // the lazy chunk lean). Rendered effectively UNLIT: the scene lights ADD to the material's
      // color AND its emissive, so any lit nonzero color washes the sphere toward white (the
      // previous grey-color + grey-emissive combo clamped to near-white). Black color + emissive
      // carrying the design grey gives a flat, light-independent ocean tone.
      globe.globeImageUrl(null as unknown as string);
      const mat = globe.globeMaterial();
      mat?.color?.set?.("#000000");
      mat?.emissive?.set?.("#c3ccd4");
      if (mat && "shininess" in mat) mat.shininess = 0;

      // Static at rest: no auto-rotation, and zoom disabled. Users may still drag to rotate.
      globe.controls().autoRotate = false;
      globe.controls().enableZoom = false;
      // Lower altitude → the globe fills the frame like the design (it's the hero of the screen).
      globe.pointOfView({ lat: HOME.lat, lng: HOME.lng, altitude: 2.15 });

      rendered = true;
      // Draw whatever peers already exist at mount time.
      rebuildArcs(new Set());
      globe.arcsData(arcs).pointsData(arcPoints());
      syncAnimation();

      // Vector continents from a bundled TopoJSON (in this lazy chunk — no CDN, no raster earth
      // texture), rendered after the sphere/arcs so they progressively fill in. Lighter-teal land
      // over the dark-teal ocean makes peer arcs geographically legible. Cosmetic: a load failure
      // just leaves the plain sphere.
      try {
        const { feature } = await import("topojson-client");
        const topoMod = await import("world-atlas/countries-110m.json");
        if (!disposed && globe) {
          const topo: any = topoMod.default ?? topoMod;
          const countries = (feature as any)(topo, topo.objects.countries).features;
          globe
            .polygonsData(countries)
            // Continents: solid WHITE landmasses over the grey ocean, with NO country outlines
            // (transparent stroke) so they read as clean continent shapes, per the design.
            .polygonCapColor(() => "#fbfdff")
            .polygonSideColor(() => "rgba(0,0,0,0)")
            .polygonStrokeColor(() => "rgba(0,0,0,0)")
            .polygonAltitude(0.004);
        }
      } catch (e) {
        console.warn("globe: continents failed to load", e);
      }

      // Bail if the component was destroyed while the dynamic imports / TopoJSON fetch above were in
      // flight: `onDestroy` has already disconnected the (still-undefined) observers, so creating them
      // here would observe a detached node that nothing ever disconnects — leaking an observer pair
      // plus the element on every tab switch during load.
      if (disposed || !el) return;

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
    globe.arcsData(arcs).pointsData(arcPoints());

    if (current.length === 0) return; // cleared; leave the globe parked
    const newest = fresh.length ? arcs.find((a) => a.id === fresh[fresh.length - 1]) : undefined;
    if (newest) {
      globe.pointOfView({ lat: newest.endLat, lng: newest.endLng, altitude: 2.15 }, 900);
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
