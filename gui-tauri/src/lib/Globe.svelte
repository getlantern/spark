<script lang="ts">
  // WebGL globe for the Unbounded screen: draws a connection arc from each live peer to us.
  //
  // Perf is Lantern's #1 hotspot, so this component is deliberately quiet:
  //   - globe.gl (three.js) is loaded via a DYNAMIC import inside onMount, so it lands in a lazy
  //     chunk and never bloats the app's initial bundle.
  //   - the globe is STATIC at rest (no auto-rotation); it only animates when the peer set changes.
  //   - the render loop is paused whenever the canvas is off-screen or the tab is hidden.
  //   - arcs are capped and cleared when the peer list empties.
  //
  // THE ARCS ARE 2D, drawn as an SVG overlay rather than with globe.gl's `arcsData`. That is not a
  // shortcut, and it is the whole reason this looked wrong before. The Flutter/Lantern build of this
  // screen uses `flutter_earth_globe`, whose `PointConnection` (see its `line_helper.dart`) projects
  // both endpoints and then draws a QUADRATIC BÉZIER between them IN SCREEN SPACE.
  //
  // That is the load-bearing part. A 3D arc at altitude bulges radially outward in WORLD space, so
  // when it sits near the middle of the visible disc the bulge points at the camera and projects as a
  // flat loop; the only way to make it rise is to push the feet out toward the limb, where the same
  // geometry reads as a hook instead. That is the trap this component was stuck in — every
  // combination of altitude, ground span and camera aim traded one artefact for the other, because no
  // world-space bulge projects upward from every angle. A screen-space curve does, always.
  //
  // Where we DIVERGE from the reference: it puts the control point radially outward from the centre
  // of the disc, scaled by the endpoints' central angle. At its globe size and its data (a volunteer
  // and peers a continent apart) that reads as an arch, but at ours both feet usually land near the
  // middle of the disc, where "radially outward" is near-degenerate — the curve then leaves one foot,
  // swings past the limb and comes back, a lasso across the globe's face. We raise each arch
  // perpendicular to its own chord instead, which is well-conditioned for every pair and gives the
  // shape the recording actually shows. See `ARCH_RISE`.
  import { onMount, onDestroy } from "svelte";
  import type { UnboundedPeer } from "$lib/spark_backend";

  let { peers = [] }: { peers: UnboundedPeer[] } = $props();

  /**
   * Where the camera looks when there is nothing to frame. Neutral mid-Atlantic.
   */
  const HOME = { lat: 20, lng: 0 };
  /**
   * Angular distance between an arch's two feet, along the peer's own parallel.
   *
   * Each arch is anchored at ITS OWN PEER: one foot on the peer, the other the same latitude and
   * this many degrees of longitude away. Both feet are therefore real points on the sphere — the
   * green dots still occlude correctly behind the limb — and, being at the same latitude, they land
   * at nearly the same height on screen, which is what makes the arch stand UPRIGHT and narrow
   * instead of leaning.
   *
   * Running each arc to a single fixed origin instead is what the reference does, but it cannot look
   * like the reference here: its origin is the volunteer's real location, a moderate hop from the
   * peers it serves, whereas a fixed point in the Atlantic is a third of the globe from most peers.
   * Those long chords draw wide leaning ribbons across the face rather than the recording's arches.
   * 23 degrees is the separation measured in the recording: its arches share one foot and fan out to
   * the peers, with ~41px between adjacent feet on a ~200px globe, i.e. about 0.41 radii.
   */
  const ARCH_SPAN_DEG = 23;
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

  // Palette taken from the reference implementation's own tokens rather than sampled off a video:
  // `AppColors.blue4`/`yellow3` at 75% alpha for the arcs and `green6` for the endpoint dots. The
  // reference alternates the two arc colours per connection because its
  // line style exposes only a flat colour — the spec asks for a cyan-to-yellow gradient per arc — so
  // alternating is what the screen actually shows, and what we reproduce.
  const ARC_COLORS = ["rgba(0, 189, 214, 0.75)", "rgba(255, 193, 5, 0.75)"];
  const PEER_DOT = "#0a8638";
  const ARC_WIDTH = 3;
  /** Endpoint dot radius, px. The reference's size-6 point renders ~10px across. */
  const DOT_R = 5;
  /**
   * How tall each arch is, in globe radii of control-point offset from its chord.
   *
   * A quadratic Bézier reaches halfway to its control point, so the crest stands `ARCH_RISE / 2`
   * radii above the chord. Set by measuring both sides: the recording's crest is 1.08 radii above its
   * feet, and 2.2 here overshot that by about a quarter.
   */
  const ARCH_RISE = 1.8;
  /** Floor tied to the chord, so a very wide arch does not look squat next to a narrow one. */
  const ARCH_MIN = 0.55;
  /** Keep the crest this many px inside the top of the mount. See the clamp in `layoutArcs`. */
  const CREST_MARGIN = 10;
  /** How far from the camera's aim a foot may sit before its arch is dropped, in degrees. */
  const FOOT_MAX_DEG = 66;
  /**
   * Camera distance, in globe radii.
   *
   * Set by measuring: this puts the sphere's radius at ~95px in a 366px-wide mount, so its diameter
   * is a little over half the mount — the proportion the recording shows (a ~203px globe in a 398px
   * window). The previous 3.15 left it floating small inside its own halo.
   */
  const GLOBE_ALTITUDE = 2.05;

  /** One connection, as the two feet of an arch. */
  interface Arc {
    id: string;
    lat: number;
    lng: number;
    /** The far foot: same latitude, `ARCH_SPAN_DEG` away, leaning east or west by index. */
    endLng: number;
    color: string;
  }
  /** One arc, projected to screen space and ready to draw, with its two feet. */
  interface ArcPath {
    id: string;
    d: string;
    color: string;
    x1: number;
    y1: number;
    x2: number;
    y2: number;
  }

  let el = $state<HTMLDivElement>();
  let paths = $state<ArcPath[]>([]);
  // globe.gl's instance is untyped here to avoid pulling three's types into this module's surface.
  let globe: any = null;
  let arcs: Arc[] = [];
  let rendered = false; // globe created and initial draw done
  let onScreen = true;
  let tabVisible = true;
  let io: IntersectionObserver | undefined;
  let ro: ResizeObserver | undefined;
  let followRaf = 0;
  let themeObserver: MutationObserver | undefined;
  /** Whether the TopoJSON continents have been handed to globe.gl yet. See `paintSphere`. */
  let continentsLoaded = false;

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
    layoutArcs();
  }

  /** Great-circle separation between two lat/lng pairs, in degrees. */
  function angleDeg(aLat: number, aLng: number, bLat: number, bLng: number): number {
    const p = Math.PI / 180;
    const cos =
      Math.sin(aLat * p) * Math.sin(bLat * p) +
      Math.cos(aLat * p) * Math.cos(bLat * p) * Math.cos((bLng - aLng) * p);
    return Math.acos(Math.max(-1, Math.min(1, cos))) / p;
  }

  /**
   * Project every arc to a screen-space path. See the header for why this is 2D.
   *
   * Cheap enough to run per frame while the camera moves (a handful of arcs, no allocation beyond
   * the path strings), but it is NOT on a render loop: it runs when the arc set changes, when the
   * camera moves, and for the duration of a camera transition. At rest nothing recomputes.
   */
  function layoutArcs() {
    if (!globe || !el || arcs.length === 0) {
      paths = [];
      return;
    }
    const pov = globe.pointOfView();
    const c = globe.getScreenCoords(pov.lat, pov.lng);
    // The globe's radius on screen, measured rather than derived from the camera altitude so it stays
    // correct through a transition and after a resize: a point exactly 90 degrees from the aim sits on
    // the limb, so its distance from the disc's centre IS the radius. Stepped along the MERIDIAN, away
    // from the nearer pole — 90 degrees of longitude is only 90 degrees of arc on the equator, so
    // using that would under-measure the radius by more the further the camera is from it.
    const limb = globe.getScreenCoords(pov.lat > 0 ? pov.lat - 90 : pov.lat + 90, pov.lng);
    const R = Math.hypot(limb.x - c.x, limb.y - c.y);
    if (!(R > 0)) {
      paths = [];
      return;
    }
    const out: ArcPath[] = [];
    for (const a of arcs) {
      // Round the back, or so close to the limb that the arch would project as a flat spike. BOTH
      // feet have to pass: the far foot is `ARCH_SPAN_DEG` further round, so testing only the peer
      // let an arch whose far foot had already crossed the limb draw as a hairpin off the edge.
      if (
        angleDeg(pov.lat, pov.lng, a.lat, a.lng) >= FOOT_MAX_DEG ||
        angleDeg(pov.lat, pov.lng, a.lat, a.endLng) >= FOOT_MAX_DEG
      )
        continue;
      const s = globe.getScreenCoords(a.lat, a.lng);
      const far = globe.getScreenCoords(a.lat, a.endLng);
      // Raise the arch PERPENDICULAR TO ITS OWN CHORD, not radially outward from the disc's centre.
      //
      // Radially outward is what the reference's formula computes, and it is wrong at our globe's
      // proportions: both feet of a connection usually land near the middle of the visible disc,
      // where "outward" is a near-degenerate direction, so the curve leaves one foot, swings past the
      // limb and returns — a lasso across the globe's face rather than an arch over it. Perpendicular
      // to the chord is well-conditioned for every pair and gives the recording's shape: a tall
      // narrow arch standing on two feet.
      const chordX = far.x - s.x;
      const chordY = far.y - s.y;
      const chord = Math.hypot(chordX, chordY) || 1;
      // Of the two perpendiculars, take the one pointing UP the screen. An arch that hangs below its
      // feet reads as a swag, and the design has no downward arcs.
      let nx = -chordY / chord;
      let ny = chordX / chord;
      if (ny > 0) {
        nx = -nx;
        ny = -ny;
      }
      // A chord that is VERTICAL on screen has no upward perpendicular — `ny` collapses to 0 and the
      // clamp below would divide by it, sending the control point to infinity. Reachable for a peer
      // close to a pole, where both feet project to nearly the same x. There is no arch to draw
      // across a vertical chord, so skip it.
      if (!(Math.abs(ny) > 1e-3)) continue;
      const midX = (s.x + far.x) / 2;
      const midY = (s.y + far.y) / 2;
      // Height off the globe's RADIUS, not off the chord. The recording's arches crest about 1.1
      // radii above the disc's centre whether their feet are close together or far apart, so a
      // chord-proportional rise gets one case right and the other badly wrong: at our HOME-to-peer
      // separations it produced an arch three times too tall.
      let rise = Math.max(ARCH_RISE * R, ARCH_MIN * chord);
      // Then clamp so the crest lands just inside the top of the frame. A Bézier reaches halfway to
      // its control point, so the crest sits at `midY + rise * ny / 2`. Without this an arch whose
      // feet are already high on the disc crests off the top edge — the clamp is what frames every
      // arch the way the recording does, just clearing the sphere, rather than leaving it to the
      // peer's latitude.
      //
      // `room` is how far the chord's midpoint sits below the margin, and it is what makes the clamp
      // safe. `ny` is NEGATIVE (up the screen), so solving for the rise that lands the crest exactly
      // on the margin divides by a negative: if the midpoint is already at or above the margin that
      // yields a NEGATIVE rise, which flips the control point below the chord and draws the arch
      // upside down. There is no upward arch to draw in that case, so the connection is skipped.
      // `Math.min` also guarantees the clamp only ever REDUCES a rise, never inflates a small one.
      const room = midY - CREST_MARGIN;
      if (room <= 0) continue;
      rise = Math.min(rise, (2 * room) / -ny);
      const cx = midX + nx * rise;
      const cy = midY + ny * rise;
      out.push({
        id: a.id,
        color: a.color,
        d: `M ${s.x.toFixed(1)} ${s.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${far.x.toFixed(1)} ${far.y.toFixed(1)}`,
        x1: s.x,
        y1: s.y,
        x2: far.x,
        y2: far.y,
      });
    }
    paths = out;
  }

  /**
   * Re-project the arcs for `ms` while a camera transition plays out.
   *
   * `onZoom` covers user drags, but `pointOfView`'s own tween moves the camera without firing it, so
   * the arcs would sit frozen at their pre-transition positions until the next unrelated event. A
   * bounded rAF loop is the cheapest way to follow it: it stops on its own, so there is still no
   * standing per-frame cost.
   */
  function followCamera(ms: number) {
    cancelAnimationFrame(followRaf);
    if (ms <= 0) {
      layoutArcs();
      return;
    }
    const until = performance.now() + ms;
    const step = () => {
      layoutArcs();
      if (performance.now() < until) followRaf = requestAnimationFrame(step);
    };
    followRaf = requestAnimationFrame(step);
  }

  /** Recompute the arc set from the current peers, capped for both data and legibility. */
  function rebuildArcs() {
    const next: Arc[] = [];
    for (const p of peers) {
      if (!p.geo) continue;
      if (next.length >= Math.min(MAX_ARCS, ARC_DRAW_LIMIT)) break;
      next.push({
        id: p.sessionId,
        lat: p.geo.lat,
        lng: p.geo.lon,
        // Alternate the lean so two peers near each other do not draw the same arch twice.
        endLng: p.geo.lon + (next.length % 2 === 0 ? ARCH_SPAN_DEG : -ARCH_SPAN_DEG),
        color: ARC_COLORS[next.length % ARC_COLORS.length],
      });
    }
    arcs = next;
  }

  /** Signature of the arc set the camera is currently framed for. */
  let parkedOn: string | null = null;
  /**
   * Frame HOME together with the peers, by aiming at the midpoint of the two.
   *
   * Aiming at the peers alone pushes HOME — and therefore the end of every arc — out to the limb.
   * Longitude is averaged on the unit circle so a cluster straddling the ±180 meridian does not
   * average to the middle of the Atlantic.
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
      // Aim at the middle of each arch, so both of its feet sit on the visible face.
      const mLng = (a.lng + a.endLng) / 2;
      lat += a.lat;
      x += Math.cos((mLng * Math.PI) / 180);
      y += Math.sin((mLng * Math.PI) / 180);
    }
    globe.pointOfView(
      {
        // Clamped so a peer set centred near a pole does not tip the camera into a polar projection.
        lat: Math.max(-55, Math.min(55, lat / arcs.length)),
        lng: (Math.atan2(y, x) * 180) / Math.PI,
        altitude: GLOBE_ALTITUDE,
      },
      animateMs,
    );
    followCamera(animateMs + 120);
  }



  /** Resolve a CSS custom property off the host, so the palette stays in the layout's token block. */
  function token(name: string): string {
    if (!el) return "#000000";
    return getComputedStyle(el).getPropertyValue(name).trim() || "#000000";
  }

  /**
   * Paint the sphere from the theme's tokens.
   *
   * The reference ships TWO textures, `uv-map.png` and `uv-map-dark.png`, and swaps them by theme, so
   * a single light sphere is wrong in dark mode — it reads as a bright disc on a dark screen. We draw
   * the ocean as the material and the continents as polygons over it rather than loading either
   * texture (a 2048x1024 PNG each, against a lazy chunk we keep lean), which means both colours have
   * to be reapplied when the theme flips.
   *
   * Rendered effectively UNLIT: the scene lights ADD to the material's colour AND its emissive, so
   * any lit nonzero colour washes the sphere toward white. Black colour with the tone on emissive
   * gives a flat, light-independent sphere.
   */
  function paintSphere() {
    if (!globe) return;
    const mat = globe.globeMaterial();
    mat?.color?.set?.("#000000");
    mat?.emissive?.set?.(token("--globe-ocean"));
    if (mat && "shininess" in mat) mat.shininess = 0;
    // Re-run the polygon accessor so the land colour follows too. Gated on our OWN flag rather than
    // on reading `polygonsData()` back: globe.gl's kapsule props do double as getters, but that is
    // not in its type declarations, and this does not need to rely on it.
    if (continentsLoaded) globe.polygonCapColor(() => token("--globe-land"));
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

      globe = new GlobeGl(el)
        .width(el.clientWidth)
        .height(el.clientHeight)
        .backgroundColor("rgba(0,0,0,0)")
        .showGlobe(true)
        .showAtmosphere(true)
        // The reference's atmosphere colour, not a sample of the halo's faded tail: globe.gl applies
        // its own outward falloff, so handing it the source cyan reproduces the gradient instead of
        // flattening it to the pale edge tone.
        .atmosphereColor("#00bdd6")
        // Tight: a rim glow hugging the sphere, not a wide cyan disc around it. The mount draws its own
        // wider halo behind the canvas, so this only has to cover the last few pixels.
        .atmosphereAltitude(0.09)
;
      globe.globeImageUrl(null as unknown as string);
      paintSphere();

      // Static at rest: no auto-rotation, and zoom disabled. Users may still drag to rotate.
      globe.controls().autoRotate = false;
      globe.controls().enableZoom = false;
      // Re-project the arcs whenever the user moves the camera. Programmatic transitions do not come
      // through here — see `followCamera`.
      globe.onZoom(() => layoutArcs());
      globe.pointOfView({ lat: HOME.lat, lng: HOME.lng, altitude: GLOBE_ALTITUDE });

      rendered = true;
      // Draw whatever peers already exist at mount time.
      rebuildArcs();
      parkCamera(0);
      layoutArcs();
      syncAnimation();

      // Vector continents from a bundled TopoJSON (in this lazy chunk — no CDN, no raster earth
      // texture), rendered after the sphere so they progressively fill in. Cosmetic: a load failure
      // just leaves the plain sphere.
      try {
        const { feature } = await import("topojson-client");
        const topoMod = await import("world-atlas/countries-110m.json");
        if (!disposed && globe) {
          const topo: any = topoMod.default ?? topoMod;
          const countries = (feature as any)(topo, topo.objects.countries).features;
          globe
            .polygonsData(countries)
            // Continents, with NO country outlines (transparent stroke) so they read as clean
            // continent shapes, per the design. Colours come from `paintSphere`.
            .polygonCapColor(() => token("--globe-land"))
            .polygonSideColor(() => "rgba(0,0,0,0)")
            .polygonStrokeColor(() => "rgba(0,0,0,0)")
            .polygonAltitude(0.004);
          continentsLoaded = true;
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
    // `+layout.svelte` writes the RESOLVED theme to <html data-theme>, so watching that one attribute
    // covers all three settings and the OS changing underneath 'system'.
    themeObserver = new MutationObserver(() => paintSphere());
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });
    return () => {
      disposed = true;
    };
  });

  // Diff peers on every change: add newly-arrived arcs, drop departed ones, clear on empty. The
  // scene is never rebuilt — we only hand globe.gl the freshly capped dot list and re-project the
  // arcs ourselves.
  $effect(() => {
    // Track peers so this effect re-runs when the list changes.
    const current = peers;
    if (!rendered || !globe) return;

    rebuildArcs();
    layoutArcs();

    if (current.length === 0) return; // cleared; leave the globe parked
    parkCamera(900);
  });

  onDestroy(() => {
    document.removeEventListener("visibilitychange", onVisibility);
    themeObserver?.disconnect();
    cancelAnimationFrame(followRaf);
    io?.disconnect();
    ro?.disconnect();
    globe?.pauseAnimation?.();
    globe?._destructor?.();
    globe = null;
  });
</script>

<div class="globe">
  <!-- globe.gl takes over the element it is handed and clears it, so the overlay has to be a SIBLING
       of the canvas host rather than a child of it — as a child it is silently wiped on mount and no
       arc ever appears. Both are `inset: 0` in the same positioned box, which is what makes
       `getScreenCoords` (measured against the host) valid in the SVG's coordinate space. -->
  <div class="host" bind:this={el}></div>
  <!-- Over the canvas, not in it: see the header. `pointer-events: none` so dragging still rotates
       the globe underneath. -->
  <svg class="arcs" aria-hidden="true">
    {#each paths as p (p.id)}
      <path d={p.d} stroke={p.color} stroke-width={ARC_WIDTH} fill="none" stroke-linecap="round" />
      <!-- The feet, drawn here rather than through globe.gl's points layer. That layer renders a
           point as a 3D cylinder, and at the size the design wants (a ~10px dot) its facets show as
           a green blob with jagged edges. A circle in the overlay is exactly round, lands exactly on
           the foot, and needs no depth handling — the arch is culled well before its feet reach the
           limb, so there is nothing for the sphere to occlude. -->
      <circle cx={p.x1} cy={p.y1} r={DOT_R} fill={PEER_DOT} />
      <circle cx={p.x2} cy={p.y2} r={DOT_R} fill={PEER_DOT} />
    {/each}
  </svg>
</div>

<style>
  /* ABSOLUTE, not `width/height: 100%`.

     The mount centres its children, so this element's grid area is content-sized — which makes a
     percentage height resolve against an auto height, i.e. against the canvas globe.gl already sized
     from the LAST measurement. With `overflow: hidden` that was merely fragile; the moment the clip
     came off it became a ResizeObserver feedback loop (canvas grows -> clientHeight grows -> canvas
     grows) that inflated the globe until it covered the whole screen. Taking the box from the
     positioned mount instead removes the cycle: the size has one source and it is not the canvas.

     The clip has to come off, because an arc crests just past the globe's silhouette and the
     atmosphere halo extends past it too, both of which a clip cuts off flat. */
  .globe {
    position: absolute;
    inset: 0;
    border-radius: 16px;
    overflow: visible;
  }
  .host {
    position: absolute;
    inset: 0;
  }
  .arcs {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    overflow: visible;
    pointer-events: none;
  }
</style>
