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
  /**
   * How many arcs are DRAWN, regardless of how many peers there are.
   *
   * Purely about legibility: past a handful, arches stop reading as connections and become a picket
   * fence around the globe. The exact count is never inferred from the picture anyway — it is stated
   * as a number in the row directly below it, which stays authoritative. Kept separate from
   * `MAX_ARCS` (the data cap) so the two reasons are not conflated.
   */
  const ARC_DRAW_LIMIT = 3;
  // Arc colours, and the endpoint dot, sampled from a screen recording of the Flutter/Lantern build
  // of this same screen rather than eyeballed: the teal is a teal-GREEN (not the cyan brand), and the
  // gold is within a hair of the app's own `--bolt`.
  const ARC_COLORS = ["#20a89c", "#f0b820"];
  const ENDPOINT_GREEN = "#0e7a34";
  // Arc height, in globe radii. Large on purpose: an arc's crest clears the sphere's silhouette only
  // when `(1 + ARC_ALTITUDE) * sin(theta) > 1`, where theta is the angle between the camera's aim
  // point and the arc's midpoint. With feet near the middle of the visible disc — where the recording
  // puts them — theta is only ~20-30 degrees, so 0.42 could never crest no matter how the span or the
  // camera was tuned. That is why several rounds of adjusting those two knobs kept producing flat
  // loops.
  //
  // With the feet offset in longitude and the camera aimed `AIM_BELOW_DEG` south of them, the arc's
  // With the feet at the same latitude, they and the arc's midpoint all sit the same angle `theta`
  // from the aim point, so the projection is easy to reason about: the feet land at `sin(theta)` and
  // the crest at `(1 + ARC_ALTITUDE) * sin(theta)`, both in globe radii from the disc's centre.
  //
  // The recording wants BOTH — green feet on the visible face AND a crest past the silhouette. At
  // `theta = 35` the feet land at `sin(35) = 0.57` (clearly on the face) and the crest at
  // `1.85 * 0.57 = 1.05`, just clearing. That balance is narrow in both directions and every earlier
  // guess missed it: with altitude 0.42-0.72 the only way to lift a crest clear was to swing the
  // camera down until the feet slid off to the limb (flat loops, then antennae), and at 1.1 the
  // crests shot out of the frame entirely.
  //
  // Arcs rise high and thin over the sphere, cresting well above its top edge. A FIXED altitude, not
  // `arcAltitudeAutoScale`: auto-scaling ties the height to the arc's ground distance, so a nearby
  // peer draws a flat line hugging the surface — which is exactly how spark's arcs looked wrong
  // against the recording.
  const ARC_ALTITUDE = 0.85;
  /** Ground span between an arc's two feet, in degrees. Small, so the loop is tall and narrow. */
  const ARC_SPAN_DEG = 46;
  /** How far below the peers the camera aims, so their arcs read as arches. See `parkCamera`. */
  const AIM_BELOW_DEG = 35;

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
  //
  // Each peer draws a TALL NARROW arc anchored at its own location: both feet a few degrees apart,
  // cresting high above the sphere. That is what the Flutter build shows — two green dots close
  // together with a thin loop towering over them — and it is a deliberate change from the earlier
  // shape here, which ran every arc from a fixed mid-Atlantic HOME to the peer. Long great circles
  // read as flat ribbons smeared across the globe's face from any camera angle, which is exactly how
  // spark's arcs looked wrong against the recording. A short span with a fixed high altitude is
  // legible from every angle and still lands on the peer's real coordinates.
  function rebuildArcs(prevIds: Set<string>): string[] {
    const next: Arc[] = [];
    const fresh: string[] = [];
    for (const p of peers) {
      if (!p.geo) continue;
      if (next.length >= Math.min(MAX_ARCS, ARC_DRAW_LIMIT)) break;
      // Lean the span north/south alternately so neighbouring peers do not draw the same arch twice.
      const lean = next.length % 2 === 0 ? ARC_SPAN_DEG : -ARC_SPAN_DEG;
      next.push({
        id: p.sessionId,
        startLat: p.geo.lat,
        startLng: p.geo.lon,
        // Offset in LONGITUDE, same latitude, so the two feet sit SIDE BY SIDE on screen — and see
        // `parkCamera`, which aims well below them so the arc's radial bulge projects upward into an
        // arch above the feet. Both halves are required and that is what made this fiddly:
        //   - longitude offset with the camera aimed AT the arc  -> bulge comes at the viewer, flat loop
        //   - latitude offset (meridian plane) with any aim      -> tall narrow hairpin
        //   - longitude offset + camera aimed below              -> the recording's wide arch
        endLat: p.geo.lat,
        endLng: p.geo.lon + lean,
        color: ARC_COLORS[next.length % ARC_COLORS.length],
      });
      if (!prevIds.has(p.sessionId)) fresh.push(p.sessionId);
    }
    arcs = next;
    return fresh;
  }

  /** Signature of the arc set the camera is currently framed for. */
  let parkedOn: string | null = null;
  /**
   * Frame the peers. Aims at their CENTROID rather than at the newest arc.
   *
   * An arc only reads as the recording's tall arch when it is near the centre of the visible disc;
   * out at the limb the same geometry projects to a flat hook. Real peers cluster — they are people
   * in censored regions — so a centroid puts the whole cluster face-on. (Aiming at just the newest
   * arc instead makes every *other* arc a hook, which is what the mock's globally-scattered peers
   * exposed.) Longitude is averaged on the unit circle so a cluster straddling the ±180 meridian
   * does not average to the middle of the Atlantic.
   */
  function parkCamera(animateMs: number) {
    if (!globe || arcs.length === 0) return;
    const sig = arcs.map((a) => a.id).join("|");
    if (sig === parkedOn) return;
    parkedOn = sig;
    let x = 0;
    let y = 0;
    let lat = 0;
    for (const a of arcs) {
      const mLat = (a.startLat + a.endLat) / 2;
      const mLng = (a.startLng + a.endLng) / 2;
      lat += mLat;
      x += Math.cos((mLng * Math.PI) / 180);
      y += Math.sin((mLng * Math.PI) / 180);
    }
    // Aim BELOW the peers, not at them. An `arcAltitude` arc bulges radially outward from the
    // sphere, so when the camera looks straight at it the bulge comes toward the viewer and projects
    // as a flat loop — which is what it did at every span and altitude tried. Offsetting the aim
    // point southward puts the arcs in the upper part of the disc, where that same radial bulge reads
    // as an arch rising up the screen. It is how the recording is framed: the arcs' feet sit above
    // the disc's centre, cresting past the silhouette.
    //
    // Clamped so a peer set centred near a pole does not tip the camera into a polar projection.
    const centroidLat = lat / arcs.length;
    const aimLat = Math.max(-50, Math.min(38, centroidLat - AIM_BELOW_DEG));
    globe.pointOfView(
      {
        lat: aimLat,
        lng: (Math.atan2(y, x) * 180) / Math.PI,
        altitude: 3.15,
      },
      animateMs,
    );
  }

  // The green endpoint dots — one at each foot of every arc, as in the recording.
  function arcPoints(): { lat: number; lng: number }[] {
    return arcs.flatMap((a) => [
      { lat: a.startLat, lng: a.startLng },
      { lat: a.endLat, lng: a.endLng },
    ]);
  }

  onMount(() => {
    if (typeof window === "undefined" || !el) return;

    let disposed = false;
    (async () => {
      // globe.gl + three are a ~1.9 MB lazy chunk. Two distinct ways it can be absent, and BOTH must
      // degrade to the static placeholder rather than let a rejection escape this detached async
      // block — an unhandled rejection here is picked up by the webview error bridge and reported as
      // a diagnostics error:
      //   1. the import itself rejects (failed chunk fetch, cache miss)      → the catch below;
      //   2. it resolves but carries no renderer — the mobile stub exports
      //      `default undefined` (see vite.config.js)                        → the typeof guard.
      // The guard is load-bearing: without it the stub sails through the try and only blows up later
      // at `new GlobeGl(el)`, outside any handler.
      let GlobeGl: typeof import("globe.gl").default | undefined;
      try {
        GlobeGl = (await import("globe.gl")).default;
      } catch (e) {
        console.warn("globe: renderer failed to load, showing placeholder", e);
        return;
      }
      if (typeof GlobeGl !== "function") {
        console.warn("globe: renderer unavailable on this platform, showing placeholder");
        return;
      }
      if (disposed || !el) return;

      const asArc = (o: object) => o as Arc;
      globe = new GlobeGl(el)
        .width(el.clientWidth)
        .height(el.clientHeight)
        .backgroundColor("rgba(0,0,0,0)")
        .showGlobe(true)
        .showAtmosphere(true)
        // The recording shows a soft cyan halo hugging the rim — sampled at ~#e8f0f0 where it meets
        // the page, which is this colour thinned by the atmosphere falloff.
        .atmosphereColor("#b6e3e6")
        .atmosphereAltitude(0.18)
        .arcStartLat((o: object) => asArc(o).startLat)
        .arcStartLng((o: object) => asArc(o).startLng)
        .arcEndLat((o: object) => asArc(o).endLat)
        .arcEndLng((o: object) => asArc(o).endLng)
        // Solid, full-strength colour end to end. The recording's arcs do not fade toward their
        // origin; a gradient made the near end look like it was dissolving into the globe.
        .arcColor((o: object) => asArc(o).color)
        .arcStroke(2.6)
        .arcAltitude(ARC_ALTITUDE)
        .arcDashLength(1)
        .arcDashGap(0)
        .arcDashAnimateTime(0)
        // A green dot where each arc meets the sphere, as in the recording — sitting just proud of
        // the surface so it is not z-fought by the globe itself.
        .pointColor(() => ENDPOINT_GREEN)
        .pointAltitude(0.014)
        .pointRadius(0.62);
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
      // Pulled back enough that a 0.42-altitude arc crests inside the frame instead of being
      // clipped by the top edge. The globe is still the hero, just not pressed against the glass.
      globe.pointOfView({ lat: HOME.lat, lng: HOME.lng, altitude: 3.15 });

      rendered = true;
      // Draw whatever peers already exist at mount time.
      rebuildArcs(new Set());
      globe.arcsData(arcs).pointsData(arcPoints());
      parkCamera(0);
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
    // `fresh` is no longer consulted for the camera: parking on the newest arc covers both an
    // arrival and the first render, and keeps the arc face-on rather than at the limb.
    void fresh;
    parkCamera(900);
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
