// The UI talks only to this abstract backend — the same small shape as
// spark-ffi's `Backend` and the Flutter `SparkBackend` (status / connect /
// disconnect). That seam is the point: the screen never changes as the binding
// underneath it does. U0 ships the mock; U1 adds a TauriBackend over invoke().

export type ConnState = "disconnected" | "connecting" | "connected" | "failed";

export interface SparkStatus {
  state: ConnState;
  /** Active transport, e.g. "AnyTLS". */
  protocol: string;
  /** True while the tunnel fails open (traffic flows unprotected if it drops). */
  failOpen: boolean;
}

// One server in the latency-selected pool, as the server-selection screen renders it. Mirrors the
// Rust `MemberStatus` JSON (see core `snapshot_to_json`): optional location metadata, last-probe
// latency, health, and whether new flows currently dial it.
export interface ServerInfo {
  /** The handle passed back to selectServer(). Stable only WITHIN one list: a config refresh reorders
   *  the tunnel's pool, and the pre-connect list is built from a separate config fetch again. Never
   *  cache it to mean "the server the user chose" — use `isPinned`, or `$lib/selection`, which records
   *  the picked location so it can be resolved in whichever pool it is applied to. */
  index: number;
  name?: string | null;
  country?: string | null;
  countryCode?: string | null;
  city?: string | null;
  /** Transport protocol kind, e.g. "hysteria2"; shown beneath the location. */
  protocol?: string | null;
  /** Last measured probe latency in ms; null if never measured / unhealthy. */
  latencyMs?: number | null;
  healthy: boolean;
  /** Whether new flows currently dial this member first (pinned, or the auto-ranked best). */
  isCurrent: boolean;
  /** Whether this is the member the user manually pinned, as the tunnel sees it. Unlike `index`, this
   *  survives a config refresh that reorders the pool — see `$lib/selection`. Always false in a
   *  pre-connect list (no live snapshot to read a pin from). */
  isPinned: boolean;
}

export interface SplitTunnel {
  enabled: boolean;
  domains: string[];
  ips: string[];
}

/** An installed application the user can exclude from the VPN. `id` is the platform match key
 * (Android package name; macOS canonical bundle-root path, e.g. `/Applications/Google Chrome.app`).
 * `icon` is an optional data-URL for display. */
export interface InstalledApp {
  id: string;
  name: string;
  icon?: string | null;
}

export interface UnboundedGeo { countryCode: string; lat: number; lon: number; }
export interface UnboundedPeer { sessionId: string; geo: UnboundedGeo | null; }
export interface UnboundedStatus {
  enabled: boolean;
  helpingNow: number;
  totalHelped: number;
  peers: UnboundedPeer[];
  /**
   * Where WE are — the far end of every arc on the globe.
   *
   * `null` until the self lookup lands (and while sharing is off, when it is never asked for), which
   * the globe reads as "don't draw us yet" rather than pinning the volunteer at (0, 0).
   */
  origin: UnboundedGeo | null;
}
export interface UnboundedSettings { autoEnable: boolean; hidden: boolean; welcomeSeen: boolean; }

export interface SparkBackend {
  status(): Promise<SparkStatus>;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  /** The current pool's members (empty when no pool is active). */
  servers(): Promise<ServerInfo[]>;
  /** Pin a server by index, or pass null for auto (fastest). */
  selectServer(index: number | null): Promise<void>;
  /** Return the currently-pinned server index, or null for auto. */
  getSelectedServer(): Promise<number | null>;
  getSplitTunnel(): Promise<SplitTunnel>;
  setSplitTunnel(st: SplitTunnel): Promise<void>;
  getRoutingMode(): Promise<"smart" | "full">;
  setRoutingMode(mode: "smart" | "full"): Promise<void>;
  /** Whether ad-block is enabled (defaults on). */
  getAdBlockEnabled(): Promise<boolean>;
  /** Persist the ad-block toggle; applied live when connected, else on next connect. */
  setAdBlockEnabled(enabled: boolean): Promise<void>;
  /** Installed apps the user can choose to exclude (platform-enumerated; empty on platforms w/o support). */
  listInstalledApps(): Promise<InstalledApp[]>;
  /** The currently-excluded app match keys (package names / exe paths). */
  getExcludedApps(): Promise<string[]>;
  /** Persist the excluded set; applied live (Android rebuilds the tunnel, no reconnect). */
  setExcludedApps(ids: string[]): Promise<void>;
  /** Start the Unbounded volunteer proxy (this device helps censored users). */
  unboundedStart(): Promise<void>;
  /** Stop the Unbounded volunteer proxy. */
  unboundedStop(): Promise<void>;
  /** Current Unbounded view: enabled flag, live/total peers helped, and the active peer list. */
  unboundedStatus(): Promise<UnboundedStatus>;
  /** Durable Unbounded settings (auto-enable / hidden / welcome-seen). */
  unboundedGetSettings(): Promise<UnboundedSettings>;
  /** Persist any subset of the Unbounded settings (auto-enable / hidden / welcome-seen). */
  unboundedSetSettings(settings: Partial<UnboundedSettings>): Promise<void>;
  /** Whether Unbounded is available for this client (server `features.unbounded` gate + a config
   * block with the endpoints to dial). Gates whether the UI surfaces the feature at all. */
  unboundedAvailable(): Promise<boolean>;
  /** Forward a webview error (JS exception / unhandled rejection) to diagnostics.
   * Fire-and-forget safe: callers may ignore the promise. */
  reportError(message: string, source: string): Promise<void>;
  /** Whether the diagnostics opt-out toggle is on (defaults ON while under test). */
  diagnosticsEnabled(): Promise<boolean>;
  /** Persist the diagnostics toggle; takes effect on next launch (the sink installs once at startup). */
  setDiagnosticsEnabled(enabled: boolean): Promise<void>;
}

// MockBackend simulates the service for U0: connect → connecting → (≈900ms) →
// connected, disconnect → disconnected. The screen polls status() on an
// interval, exactly as it will against the real service, so swapping in the
// TauriBackend at U1 changes nothing in the UI.
// Dev-only shared state: every route constructs its own `new MockBackend()`, so per-instance fields
// wouldn't survive navigation in `npm run dev` (a mode chosen on /routing wouldn't show on Home).
// Module scope makes all mock instances share it; the real TauriBackend persists to disk / the NE.
const mockState: {
  state: ConnState;
  timer: ReturnType<typeof setTimeout> | null;
  pinned: number | null;
  split: SplitTunnel;
  routingMode: "smart" | "full";
  adBlockEnabled: boolean;
  excludedApps: string[];
  unbounded: UnboundedStatus;
  unboundedTimer: ReturnType<typeof setInterval> | null;
  autoEnable: boolean;
  hidden: boolean;
  welcomeSeen: boolean;
  diagnosticsEnabled: boolean;
} = { state: "disconnected", timer: null, pinned: null, split: { enabled: false, domains: [], ips: [] }, routingMode: "smart", adBlockEnabled: true, excludedApps: [], unbounded: { enabled: false, helpingNow: 0, totalHelped: 0, peers: [], origin: null }, unboundedTimer: null, autoEnable: false, hidden: false, welcomeSeen: false, diagnosticsEnabled: true };

export class MockBackend implements SparkBackend {
  // A stand-in pool (the 6 DO relays used for multi-server bring-up) so the selection screen is
  // fully usable at `npm run dev`; the TauriBackend reads the real pool over the NE channel.
  private readonly pool: ServerInfo[] = [
    { index: 0, name: "sfo3", country: "United States", countryCode: "US", city: "San Francisco", protocol: "hysteria2", latencyMs: 19, healthy: true, isCurrent: false, isPinned: false },
    { index: 1, name: "nyc3", country: "United States", countryCode: "US", city: "New York", protocol: "samizdat", latencyMs: 71, healthy: true, isCurrent: false, isPinned: false },
    { index: 2, name: "lon1", country: "United Kingdom", countryCode: "GB", city: "London", protocol: "shadowsocks", latencyMs: 138, healthy: true, isCurrent: false, isPinned: false },
    { index: 3, name: "fra1", country: "Germany", countryCode: "DE", city: "Frankfurt", protocol: "hysteria2", latencyMs: 149, healthy: true, isCurrent: false, isPinned: false },
    { index: 4, name: "sgp1", country: "Singapore", countryCode: "SG", city: "Singapore", protocol: "samizdat", latencyMs: 189, healthy: true, isCurrent: false, isPinned: false },
    { index: 5, name: "blr1", country: "India", countryCode: "IN", city: "Bangalore", protocol: "anytls", latencyMs: 212, healthy: true, isCurrent: false, isPinned: false },
  ];
  // Manual pin (null = auto, fastest healthy member) lives in the shared mockState.

  async status(): Promise<SparkStatus> {
    return {
      state: mockState.state,
      protocol: "AnyTLS",
      // No real direct-fallback signal yet, so don't derive it from connection state.
      failOpen: false,
    };
  }

  async connect(): Promise<void> {
    if (mockState.timer) clearTimeout(mockState.timer);
    mockState.state = "connecting";
    mockState.timer = setTimeout(() => {
      mockState.state = "connected";
      mockState.timer = null;
    }, 900);
  }

  async disconnect(): Promise<void> {
    if (mockState.timer) clearTimeout(mockState.timer);
    mockState.timer = null;
    mockState.state = "disconnected";
  }

  async servers(): Promise<ServerInfo[]> {
    // Current = the pin if set, else the fastest healthy member.
    const healthy = this.pool.filter((s) => s.healthy);
    const fastest = healthy.reduce<number>(
      (best, s) =>
        best < 0 || (s.latencyMs ?? Infinity) < (this.pool[best].latencyMs ?? Infinity)
          ? s.index
          : best,
      -1,
    );
    const current = mockState.pinned ?? fastest;
    return this.pool.map((s) => ({
      ...s,
      isCurrent: s.index === current,
      isPinned: s.index === mockState.pinned,
    }));
  }

  async selectServer(index: number | null): Promise<void> {
    mockState.pinned = index;
  }
  async getSelectedServer(): Promise<number | null> { return mockState.pinned; }

  async getSplitTunnel(): Promise<SplitTunnel> { return structuredClone(mockState.split); }
  async setSplitTunnel(st: SplitTunnel): Promise<void> { mockState.split = structuredClone(st); }
  async getRoutingMode(): Promise<"smart" | "full"> { return mockState.routingMode; }
  async setRoutingMode(mode: "smart" | "full"): Promise<void> { mockState.routingMode = mode; }
  async getAdBlockEnabled(): Promise<boolean> { return mockState.adBlockEnabled; }
  async setAdBlockEnabled(enabled: boolean): Promise<void> { mockState.adBlockEnabled = enabled; }

  async listInstalledApps(): Promise<InstalledApp[]> {
    return [
      { id: "com.android.chrome", name: "Chrome", icon: null },
      { id: "org.mozilla.firefox", name: "Firefox", icon: null },
      { id: "com.spotify.music", name: "Spotify", icon: null },
    ];
  }
  async getExcludedApps(): Promise<string[]> { return [...mockState.excludedApps]; }
  async setExcludedApps(ids: string[]): Promise<void> { mockState.excludedApps = [...ids]; }

  // A rotating cast of countries so the globe has something to plot at `npm run dev`; the real
  // TauriBackend gets its peers from the `spark://unbounded` event over the plugin.
  private static readonly geos: UnboundedGeo[] = [
    { countryCode: "IR", lat: 35.7, lon: 51.4 },
    { countryCode: "CN", lat: 39.9, lon: 116.4 },
    { countryCode: "RU", lat: 55.8, lon: 37.6 },
    { countryCode: "TR", lat: 41.0, lon: 28.98 },
    { countryCode: "EG", lat: 30.0, lon: 31.2 },
    { countryCode: "MM", lat: 16.8, lon: 96.2 },
  ];

  /** Our own position in the mock. Deliberately far from every peer above: a long chord is the
   *  harder case for the globe's arc geometry, so dev should show it rather than hide it. */
  private static readonly ownGeo: UnboundedGeo = { countryCode: "US", lat: 39.74, lon: -104.98 };

  async unboundedStart(): Promise<void> {
    mockState.unbounded.enabled = true;
    mockState.unbounded.origin = MockBackend.ownGeo;
    // Only drive the simulated peer stream in a browser context; unit tests run under node
    // (no `window`) and just assert the enabled flag flips synchronously above.
    if (typeof window === "undefined" || mockState.unboundedTimer) return;
    mockState.unboundedTimer = setInterval(() => {
      const u = mockState.unbounded;
      // Occasionally drop a peer, otherwise add one — a gentle churn around a handful of helpers.
      if (u.peers.length > 2 && Math.random() < 0.3) {
        u.peers.shift();
      } else {
        const geo = MockBackend.geos[Math.floor(Math.random() * MockBackend.geos.length)];
        u.peers.push({ sessionId: crypto.randomUUID(), geo });
        u.totalHelped += 1;
      }
      u.helpingNow = u.peers.length;
    }, 2000);
  }

  async unboundedStop(): Promise<void> {
    mockState.unbounded.origin = null;
    if (mockState.unboundedTimer) clearInterval(mockState.unboundedTimer);
    mockState.unboundedTimer = null;
    mockState.unbounded.enabled = false;
    mockState.unbounded.helpingNow = 0;
    mockState.unbounded.peers = [];
    // totalHelped is cumulative — it survives stop.
  }

  async unboundedStatus(): Promise<UnboundedStatus> { return structuredClone(mockState.unbounded); }

  async unboundedGetSettings(): Promise<UnboundedSettings> {
    return { autoEnable: mockState.autoEnable, hidden: mockState.hidden, welcomeSeen: mockState.welcomeSeen };
  }
  async unboundedSetSettings(settings: Partial<UnboundedSettings>): Promise<void> {
    if (settings.autoEnable !== undefined) mockState.autoEnable = settings.autoEnable;
    if (settings.hidden !== undefined) mockState.hidden = settings.hidden;
    if (settings.welcomeSeen !== undefined) mockState.welcomeSeen = settings.welcomeSeen;
  }
  // Dev-visible: the mock always reports Unbounded available so the tab/row shows at `npm run dev`.
  async unboundedAvailable(): Promise<boolean> { return true; }

  // Dev stand-in for the diag spool: just make the forwarded error visible in the console.
  async reportError(message: string, source: string): Promise<void> {
    console.error(`[mock diag] ${source}: ${message}`);
  }
  async diagnosticsEnabled(): Promise<boolean> { return mockState.diagnosticsEnabled; }
  async setDiagnosticsEnabled(enabled: boolean): Promise<void> { mockState.diagnosticsEnabled = enabled; }
}
