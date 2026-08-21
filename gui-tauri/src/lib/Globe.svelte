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
  // The control point is the great-circle midpoint of the two feet, lifted clear of the sphere and
  // projected — the reference's own construction. An earlier pass here raised each arch perpendicular
  // to its chord in screen space instead, which always bulges UP THE SCREEN and so leaned the wrong
  // way for most pairs: the arcs read as bridges over the globe rather than paths lying on it. See
  // `ARC_LIFT`, whose value is matched against the recording's measured radial profile.
  import { onMount, onDestroy } from "svelte";
  import type { UnboundedGeo, UnboundedPeer } from "$lib/spark_backend";

  let {
    peers = [],
    origin = null,
  }: {
    peers: UnboundedPeer[];
    /**
     * Where WE are. `null` until the self lookup lands, and while sharing is off.
     *
     * Arcs run peer -> here, which is what the reference does and what makes the screen legible:
     * without it there is nothing on the globe representing the volunteer, so the camera parks on
     * whoever they happen to be helping and the map reads as though it were showing THEM in a
     * country they have never been to.
     */
    origin: UnboundedGeo | null;
  } = $props();

  /**
   * Where the camera looks when there is nothing to frame. Neutral mid-Atlantic.
   */
  const HOME = { lat: 20, lng: 0 };
  /** Colour of the dot marking US, distinct from a peer's. */
  const OWN_DOT = "#00bdd6";
  /**
   * How an arc arrives: it GROWS along its own length, from the peer towards us, while fading in.
   *
   * Both numbers are `PointConnectionStyle`'s defaults in the reference, which is what Lantern gets
   * by passing `animateOnAdd: true` and leaving the durations alone — 1000ms of growth and 500ms of
   * fade, both linear (its painter is a plain `elapsed / duration` clamp, with no curve). The
   * direction is not arbitrary either: the reference's path starts at the PEER and ends at the
   * volunteer, and its growth extracts the path from 0 forward, so the connection reaches out from
   * the person being helped towards whoever is helping them.
   */
  const GROW_MS = 1000;
  const FADE_MS = 500;
  /**
   * Continuous spin, in three.js `OrbitControls.autoRotateSpeed` units (2.0 is one turn per 30s).
   *
   * The reference spins on desktop — `isRotating: PlatformUtils.isDesktop, rotationSpeed: 0.04` —
   * and this globe was static, which is the most visible way it failed to look like the recording.
   *
   * Its figure does not transfer directly: the package subtracts a fixed angle PER FRAME, so its real
   * speed depends on the display's refresh rate — about 15 deg/s at 60Hz and double that on a 120Hz
   * panel. So the rate came from the recording instead, by cross-correlating a band of the sphere
   * between frames a second apart: the windows where a `focusOnCoordinates` turn is not overriding the
   * spin agree on ~21 deg/s, which sits between those two figures. At 2.0 OrbitControls turns once
   * per 30s, i.e. 12 deg/s, so this is 21.
   *
   * Measuring the same way against `npm run dev` reads LOWER, about 13-16 deg/s, and that is a mock
   * artifact rather than something to compensate for: the mock lands a peer every ~2s, every arrival
   * suspends the spin for ~1s (see `parkCamera`), so the average comes out near half of nominal. Real
   * arrivals are far rarer, so nominal is what a user sees. Do not raise this to make the dev numbers
   * match.
   */
  const ROTATE_SPEED = 3.5;
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
   * How far the arc rides ABOVE the great circle, in globe radii, once it is on it.
   *
   * The lift itself is not a constant, and treating it as one is what made the arcs' angle wrong. A
   * quadratic Bézier only LIES ON a circular arc when its control point is at `R / cos(omega / 2)`,
   * where omega is the central angle between the feet — so a single figure is correct at exactly one
   * separation and wrong at every other, bowing inside the surface for wide pairs and ballooning over
   * it for narrow ones. Solving per arc is what makes it track the surface at any separation, which
   * is the whole complaint.
   *
   * This is the extra on top, and it is what lifts the arc clear of the silhouette instead of grazing
   * the ground. Measured against the recording, whose arcs crest at ~1.15 radii with a median of 0.90:
   * at 0.14 the arc tracked the surface exactly and read as drawn ON the globe, medians around 0.6-0.9
   * but never rising past the edge; at 0.45 the crests land at 0.92-1.07 and the arcs lift over the
   * limb the way the recording's do, while still leaning along their own great circle.
   */
  const ARC_RIDE = 0.45;
  /**
   * Margin inside `FOOT_MAX_DEG` that the camera keeps our end within.
   *
   * The aim is chosen so our end is this much clear of the cull, rather than exactly on it, because
   * the spin keeps moving and an end sitting exactly at the threshold would flicker in and out.
   */
  const CULL_MARGIN_DEG = 8;
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

  /** One connection: a peer at one end, us at the other. */
  interface Arc {
    id: string;
    lat: number;
    lng: number;
    color: string;
  }
  /** One arc, projected to screen space and ready to draw. */
  interface ArcPath {
    id: string;
    d: string;
    color: string;
    /**
     * Whether it is currently drawable — both feet on the visible face, with a usable perpendicular.
     *
     * A culled arc stays in the list and is HIDDEN rather than removed, so its element survives and
     * its growth animation keeps running on time. Dropping it instead would restart the growth every
     * time the camera swung a peer past the cull threshold, and an arc added while off-face would
     * animate from scratch when it came into view instead of already being drawn — where the
     * reference, whose growth is a function of elapsed time since the connection was added, shows it
     * finished.
     */
    visible: boolean;
  }
  /** A dot on the sphere, already projected. */
  interface Dot {
    id: string;
    x: number;
    y: number;
  }

  let el = $state<HTMLDivElement>();
  let paths = $state<ArcPath[]>([]);
  let peerDots = $state<Dot[]>([]);
  let ownDot = $state<Dot | null>(null);
  // globe.gl's instance is untyped here to avoid pulling three's types into this module's surface.
  let globe: any = null;
  let arcs: Arc[] = [];
  let rendered = false; // globe created and initial draw done
  let onScreen = true;
  let tabVisible = true;
  let io: IntersectionObserver | undefined;
  let ro: ResizeObserver | undefined;
  let followRaf = 0;
  let spinResume: ReturnType<typeof setTimeout> | undefined;
  let themeObserver: MutationObserver | undefined;
  /** Whether the TopoJSON continents have been handed to globe.gl yet. See `paintSphere`. */
  let continentsLoaded = false;

  // The render loop should run only while both visible on-screen and on an active tab. globe.gl
  // exposes pause/resume for exactly this; gating on both signals keeps the GPU idle in the common
  // case (screen scrolled away, or app backgrounded).
  function syncAnimation() {
    if (!globe) return;
    if (onScreen && tabVisible) {
      globe.resumeAnimation();
      startProjection();
    } else {
      globe.pauseAnimation();
      stopProjection();
    }
  }

  /** Turn the continuous spin on or off. Never on under `prefers-reduced-motion`. */
  function setSpin(on: boolean) {
    if (!globe) return;
    const reduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
    globe.controls().autoRotate = on && !reduced;
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

  /**
   * The point halfway along the great circle between two lat/lng pairs.
   *
   * Averaged as 3D unit vectors and renormalised, which is both the standard construction and what
   * the reference does. Averaging latitude and longitude separately would not give a point on the
   * great circle at all.
   */
  function greatCircleMid(
    aLat: number,
    aLng: number,
    bLat: number,
    bLng: number,
  ): { lat: number; lng: number } {
    const p = Math.PI / 180;
    const ax = Math.cos(aLat * p) * Math.cos(aLng * p);
    const ay = Math.cos(aLat * p) * Math.sin(aLng * p);
    const az = Math.sin(aLat * p);
    const bx = Math.cos(bLat * p) * Math.cos(bLng * p);
    const by = Math.cos(bLat * p) * Math.sin(bLng * p);
    const bz = Math.sin(bLat * p);
    const x = ax + bx;
    const y = ay + by;
    const z = az + bz;
    const n = Math.hypot(x, y, z);
    // Antipodal feet have no unique midpoint; any great circle through them is as good, so pick the
    // one through the first foot's meridian rather than dividing by zero.
    if (n < 1e-9) return { lat: 0, lng: aLng + 90 };
    return {
      lat: Math.asin(Math.max(-1, Math.min(1, z / n))) / p,
      lng: (Math.atan2(y, x) * 180) / Math.PI,
    };
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
   * This DOES run every frame — see `startProjection`. It has to: the globe spins continuously, and
   * an overlay that is not part of the scene has nothing else to move it. The cost is a handful of
   * arcs and the path strings for them, alongside a renderer that is already drawing every frame for
   * the spin. It stops with the renderer when the screen is off-tab or scrolled away, so an unwatched
   * globe still costs nothing.
   */
  function layoutArcs() {
    if (!globe || !el || arcs.length === 0) {
      paths = [];
      peerDots = [];
      ownDot = null;
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
      peerDots = [];
      ownDot = null;
      return;
    }
    // Us: one end of every arc, so projected once. The self lookup is a network round trip that can
    // be slow or fail, and when it has not landed there is nothing to connect a peer TO.
    // Captured as a local so the loop below narrows: `far` being non-null implies we have an origin,
    // but that is not something the compiler can infer from a derived value.
    const own = origin;
    const ownVisible = own != null && angleDeg(pov.lat, pov.lng, own.lat, own.lon) < FOOT_MAX_DEG;
    const far = own ? globe.getScreenCoords(own.lat, own.lon) : null;
    ownDot = ownVisible && far ? { id: "own", x: far.x, y: far.y } : null;

    // Peer dots are computed INDEPENDENTLY of the arcs, so a failed or pending self lookup leaves the
    // people being helped on the map instead of a bare sphere. Losing the arcs to a geo failure is
    // bad enough; losing the peers as well would make the screen look like nothing was happening.
    const dots: Dot[] = [];
    const out: ArcPath[] = [];
    for (const a of arcs) {
      // Round the back, or so close to the limb that a foot projects onto the disc while facing away.
      const peerVisible = angleDeg(pov.lat, pov.lng, a.lat, a.lng) < FOOT_MAX_DEG;
      const s = globe.getScreenCoords(a.lat, a.lng);
      if (peerVisible) dots.push({ id: a.id, x: s.x, y: s.y });
      // Both feet have to be on the face — an arc with one foot past the limb draws as a hairpin off
      // the edge — so no origin, or an origin round the back, means dots without arcs. The arc is
      // still emitted, just not drawable: see `ArcPath.visible`.
      if (!far || !own) continue;
      const drawable = peerVisible && ownVisible;
      // The control point is the GREAT-CIRCLE MIDPOINT of the two feet, lifted clear of the sphere
      // and projected — which is what the reference computes (`line_helper.dart` normalises the mean
      // of the two endpoint vectors, scales it past the surface, and projects that).
      //
      // This is the part that was wrong. Raising the arch perpendicular to its own chord, in screen
      // space, always bulges UP THE SCREEN, and for most pairs that is not the direction the
      // connection actually runs: the bulge has to lean the way the great circle leans, or the arc
      // stops looking like it lies on the earth and starts looking like a bridge over it. Taking the
      // direction from the great-circle midpoint gets that for free, because that midpoint is where
      // the real path is furthest from the chord.
      //
      // Lifted by `ARC_LIFT` radii. Perspective does most of the work: a point this far out is much
      // closer to the camera than the surface is, so a modest angular offset from the view axis
      // projects a long way from the disc's centre — which is how the reference's crest reaches ~1.15
      // radii while both feet sit inside half a radius of the middle.
      const mid = greatCircleMid(a.lat, a.lng, own.lat, own.lon);
      // Put the control point where a quadratic Bézier actually interpolates the great circle: at
      // `1 / cos(omega / 2)` radii, omega being the separation of the feet. Then ride `ARC_RIDE`
      // above that. Solved per arc, so a peer next door and a peer a third of the world away both get
      // a curve that follows the ground rather than one of them bowing through it.
      const omega = angleDeg(a.lat, a.lng, own.lat, own.lon) * (Math.PI / 180);
      const onSurface = 1 / Math.max(0.2, Math.cos(omega / 2));
      const ctrl = globe.getScreenCoords(mid.lat, mid.lng, onSurface - 1 + ARC_RIDE);
      const cx = ctrl.x;
      const cy = ctrl.y;
      out.push({
        id: a.id,
        color: a.color,
        d: `M ${s.x.toFixed(1)} ${s.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${far.x.toFixed(1)} ${far.y.toFixed(1)}`,
        visible: drawable,
      });
    }
    paths = out;
    peerDots = dots;
  }

  /**
   * Re-project the arcs every frame for as long as the globe is on screen.
   *
   * The arcs are an SVG overlay, not part of the scene, so nothing moves them when the camera does —
   * and now that the globe spins continuously they would visibly detach from the sphere and float.
   * A standing loop is therefore required rather than the bounded one that used to follow a
   * transition, and it also subsumes the `onZoom` hook and drag handling: one place recomputes.
   *
   * Gated on exactly the same visibility signal as the WebGL renderer, so when the screen is off-tab
   * or scrolled away this stops with it. While it runs the renderer is running anyway for the spin,
   * and re-projecting a handful of arcs beside that is marginal.
   */
  function startProjection() {
    if (followRaf) return;
    const step = () => {
      layoutArcs();
      followRaf = requestAnimationFrame(step);
    };
    followRaf = requestAnimationFrame(step);
  }

  function stopProjection() {
    if (followRaf) cancelAnimationFrame(followRaf);
    followRaf = 0;
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
        color: ARC_COLORS[next.length % ARC_COLORS.length],
      });
    }
    arcs = next;
  }

  /** Signature of the arc set the camera is currently framed for. */
  let parkedOn: string | null = null;
  /**
   * Frame the peers together with US, so both feet of every arc are on the visible face.
   *
   * See the body for how the aim is averaged and why our end is weighted; `HOME` is only the idle aim
   * for a globe with nothing on it.
   */
  function parkCamera(animateMs: number) {
    if (!globe || arcs.length === 0) return;
    // The origin is part of the signature: it arrives AFTER the first peers (a network round trip),
    // and the camera has to re-frame when it does or our end stays off the visible face.
    const sig = [...arcs.map((a) => a.id), origin ? `${origin.lat},${origin.lon}` : "-"].join("|");
    if (sig === parkedOn) return;
    parkedOn = sig;
    // Frame us together with the peers by aiming at a point BETWEEN the two, walking along the great
    // circle from our end towards the peers' centroid.
    //
    // The obvious rule — average every endpoint as unit vectors, weighting ours — is what was here,
    // and it fails in the common case. Points spread across half the globe are all in the northern
    // hemisphere, so their z components add while x and y cancel: the mean drifts towards the POLE,
    // and clamping the latitude back down then leaves a longitude belonging to none of them. Aiming
    // there put our end round the back and every arc was culled, which is a blank globe while the user
    // is actively helping people.
    //
    // Walking the great circle cannot do that: the aim lies between two real points by construction.
    // And the distance walked is chosen so OUR end is always on the visible face — it is one foot of
    // every arc, so if it is hidden nothing draws at all, whereas a peer being hidden costs one arc.
    const p = Math.PI / 180;
    const unit = (lat: number, lng: number): [number, number, number] => [
      Math.cos(lat * p) * Math.cos(lng * p),
      Math.cos(lat * p) * Math.sin(lng * p),
      Math.sin(lat * p),
    ];
    // The peers' centroid. They are usually clustered, so a plain vector mean is well behaved here in
    // a way it is not across a whole hemisphere.
    let px = 0;
    let py = 0;
    let pz = 0;
    for (const a of arcs) {
      const [x, y, z] = unit(a.lat, a.lng);
      px += x;
      py += y;
      pz += z;
    }
    const pn = Math.hypot(px, py, pz);
    if (pn < 1e-9) return;
    const peersMid: [number, number, number] = [px / pn, py / pn, pz / pn];
    const us = origin ? unit(origin.lat, origin.lon) : peersMid;

    const dot = Math.max(-1, Math.min(1, us[0] * peersMid[0] + us[1] * peersMid[1] + us[2] * peersMid[2]));
    const omega = Math.acos(dot);
    // Halfway when both ends fit inside the cull from the midpoint; otherwise only as far as keeps our
    // end inside it, and the far peers cull instead.
    const reach = (FOOT_MAX_DEG - CULL_MARGIN_DEG) * p;
    const t = omega < 1e-6 ? 0 : Math.min(0.5, reach / omega);
    let aim: [number, number, number];
    if (omega < 1e-6) {
      aim = us;
    } else {
      // Slerp. Antipodal ends have no unique great circle, but `t` is capped well below 0.5 by then,
      // so sin(omega) is never the degenerate case that would divide by zero.
      const s0 = Math.sin((1 - t) * omega) / Math.sin(omega);
      const s1 = Math.sin(t * omega) / Math.sin(omega);
      aim = [
        us[0] * s0 + peersMid[0] * s1,
        us[1] * s0 + peersMid[1] * s1,
        us[2] * s0 + peersMid[2] * s1,
      ];
    }
    const an = Math.hypot(aim[0], aim[1], aim[2]) || 1;
    const aimLat = Math.asin(Math.max(-1, Math.min(1, aim[2] / an))) / p;
    const aimLng = (Math.atan2(aim[1], aim[0]) * 180) / Math.PI;
    globe.pointOfView(
      {
        // No clamp: the aim is a point on the great circle between two real endpoints, so it cannot
        // wander to a pole the way an unconstrained mean could.
        lat: aimLat,
        lng: aimLng,
        altitude: GLOBE_ALTITUDE,
      },
      animateMs,
    );
    // Suspend the spin for the duration of the turn. `pointOfView` animates the camera directly while
    // autoRotate advances the azimuth every frame, so leaving both on has them fighting over the same
    // camera and the turn arrives somewhere neither intended.
    setSpin(false);
    clearTimeout(spinResume);
    spinResume = setTimeout(() => setSpin(true), animateMs + 120);
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
        // A SOFT WIDE BLOOM, not a rim. The reference is explicit about this — `atmosphereOpacity:
        // 0.18, atmosphereBlur: 22`, commented "Soft bloom, not a rim: a small blur reads as a hard
        // teal ring" — and this had been narrowed to a rim, which is the thing that comment warns
        // against. globe.gl gives no opacity control, so the faintness has to come from the colour:
        // a pale cyan spread wide, rather than the saturated brand cyan held tight.
        .atmosphereColor("#8fd9e6")
        .atmosphereAltitude(0.22)
;
      globe.globeImageUrl(null as unknown as string);
      paintSphere();

      // A slow continuous spin, as the reference has. Zoom stays disabled; users may still drag.
      globe.controls().autoRotateSpeed = ROTATE_SPEED;
      globe.controls().enableZoom = false;
      setSpin(true);
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
    clearTimeout(spinResume);
    stopProjection();
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
      <!-- `pathLength="1"` normalises the dash maths, so one dash of length 1 covers the whole arc
           however long it is on screen and the growth is a straight 1 -> 0 on the offset. That also
           makes the animation independent of `d`: the camera can move mid-growth, changing the path
           entirely, and the same fraction stays drawn. -->
      <path
        class="arc"
        class:hidden={!p.visible}
        d={p.d}
        stroke={p.color}
        stroke-width={ARC_WIDTH}
        fill="none"
        stroke-linecap="round"
        pathLength="1"
        style="--grow: {GROW_MS}ms; --fade: {FADE_MS}ms"
      />
    {/each}
    <!-- The dots are drawn here rather than through globe.gl's points layer. That layer renders a
         point as a 3D cylinder, and at the size the design wants (a ~10px dot) its facets show as a
         green blob with jagged edges. A circle in the overlay is exactly round, lands exactly on the
         foot, and needs no depth handling — a foot is culled well before it reaches the limb, so
         there is nothing for the sphere to occlude. -->
    {#each peerDots as d (d.id)}
      <circle cx={d.x} cy={d.y} r={DOT_R} fill={PEER_DOT} />
    {/each}
    {#if ownDot}
      <!-- Us, drawn last so it sits on top where several arcs converge, and a size up in the brand
           cyan rather than the peers' green so the two ends of a connection are never confused. The
           reference draws its own end almost transparent; ours is solid, because "where am I on this
           map" is the question this screen kept failing to answer. -->
      <circle cx={ownDot.x} cy={ownDot.y} r={DOT_R + 1} fill={OWN_DOT} />
    {/if}
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
  /* Arriving arcs grow from the peer towards us while fading in — see `GROW_MS`. The element is
     keyed by arc id and survives both a camera move and a spell of being culled, so the growth runs
     once, on time, from when the connection first appeared. */
  .arc {
    stroke-dasharray: 1;
    stroke-dashoffset: 1;
    animation:
      grow var(--grow) linear forwards,
      appear var(--fade) linear forwards;
  }
  /* Culled, not gone: hidden so the element (and its running animation) survive. */
  .arc.hidden {
    visibility: hidden;
  }
  @keyframes grow {
    from {
      stroke-dashoffset: 1;
    }
    to {
      stroke-dashoffset: 0;
    }
  }
  @keyframes appear {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
  /* Motion is the point of this animation, so there is nothing to preserve at reduced motion beyond
     the arc itself: draw it complete. */
  @media (prefers-reduced-motion: reduce) {
    .arc {
      animation: none;
      stroke-dashoffset: 0;
    }
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
