// The UI talks only to this abstract backend — the same small shape as
// spark-ffi's `Backend` and the Flutter `SparkBackend` (status / connect /
// disconnect). That seam is the point: the screen never changes as the binding
// underneath it does. U0 ships the mock; U1 adds a TauriBackend over invoke().

export type ConnState = "disconnected" | "connecting" | "connected" | "failed";

export interface SparkStatus {
  state: ConnState;
  /** Active transport, e.g. "AnyTLS". */
  protocol: string;
  /** Routing mode, e.g. "Full tunnel". */
  routing: string;
  /** True while the tunnel fails open (traffic flows unprotected if it drops). */
  failOpen: boolean;
}

// One server in the latency-selected pool, as the server-selection screen renders it. Mirrors the
// Rust `MemberStatus` JSON (see core `snapshot_to_json`): optional location metadata, last-probe
// latency, health, and whether new flows currently dial it.
export interface ServerInfo {
  /** Stable pool index — the handle passed back to selectServer(). */
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
}

export interface SplitTunnel {
  enabled: boolean;
  domains: string[];
  ips: string[];
}

export interface SparkBackend {
  status(): Promise<SparkStatus>;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  /** The current pool's members (empty when no pool is active). */
  servers(): Promise<ServerInfo[]>;
  /** Pin a server by index, or pass null for auto (fastest). */
  selectServer(index: number | null): Promise<void>;
  getSplitTunnel(): Promise<SplitTunnel>;
  setSplitTunnel(st: SplitTunnel): Promise<void>;
  getRoutingMode(): Promise<"smart" | "full">;
  setRoutingMode(mode: "smart" | "full"): Promise<void>;
}

// MockBackend simulates the service for U0: connect → connecting → (≈900ms) →
// connected, disconnect → disconnected. The screen polls status() on an
// interval, exactly as it will against the real service, so swapping in the
// TauriBackend at U1 changes nothing in the UI.
export class MockBackend implements SparkBackend {
  private state: ConnState = "disconnected";
  private timer: ReturnType<typeof setTimeout> | null = null;
  // A stand-in pool (the 6 DO relays used for multi-server bring-up) so the selection screen is
  // fully usable at `npm run dev`; the TauriBackend reads the real pool over the NE channel.
  private readonly pool: ServerInfo[] = [
    { index: 0, name: "sfo3", country: "United States", countryCode: "US", city: "San Francisco", protocol: "hysteria2", latencyMs: 19, healthy: true, isCurrent: false },
    { index: 1, name: "nyc3", country: "United States", countryCode: "US", city: "New York", protocol: "samizdat", latencyMs: 71, healthy: true, isCurrent: false },
    { index: 2, name: "lon1", country: "United Kingdom", countryCode: "GB", city: "London", protocol: "shadowsocks", latencyMs: 138, healthy: true, isCurrent: false },
    { index: 3, name: "fra1", country: "Germany", countryCode: "DE", city: "Frankfurt", protocol: "hysteria2", latencyMs: 149, healthy: true, isCurrent: false },
    { index: 4, name: "sgp1", country: "Singapore", countryCode: "SG", city: "Singapore", protocol: "samizdat", latencyMs: 189, healthy: true, isCurrent: false },
    { index: 5, name: "blr1", country: "India", countryCode: "IN", city: "Bangalore", protocol: "anytls", latencyMs: 212, healthy: true, isCurrent: false },
  ];
  // Manual pin; null = auto (fastest healthy member is current).
  private pinned: number | null = null;

  async status(): Promise<SparkStatus> {
    return {
      state: this.state,
      protocol: "AnyTLS",
      routing: "Full tunnel",
      // No real direct-fallback signal yet, so don't derive it from connection state.
      failOpen: false,
    };
  }

  async connect(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.state = "connecting";
    this.timer = setTimeout(() => {
      this.state = "connected";
      this.timer = null;
    }, 900);
  }

  async disconnect(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.state = "disconnected";
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
    const current = this.pinned ?? fastest;
    return this.pool.map((s) => ({ ...s, isCurrent: s.index === current }));
  }

  async selectServer(index: number | null): Promise<void> {
    this.pinned = index;
  }

  private split: SplitTunnel = { enabled: false, domains: [], ips: [] };
  async getSplitTunnel(): Promise<SplitTunnel> { return structuredClone(this.split); }
  async setSplitTunnel(st: SplitTunnel): Promise<void> { this.split = structuredClone(st); }
  private routingMode: "smart" | "full" = "smart";
  async getRoutingMode(): Promise<"smart" | "full"> { return this.routingMode; }
  async setRoutingMode(mode: "smart" | "full"): Promise<void> { this.routingMode = mode; }
}
