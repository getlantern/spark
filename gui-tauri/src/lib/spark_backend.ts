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

export interface SparkBackend {
  status(): Promise<SparkStatus>;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
}

// MockBackend simulates the service for U0: connect → connecting → (≈900ms) →
// connected, disconnect → disconnected. The screen polls status() on an
// interval, exactly as it will against the real service, so swapping in the
// TauriBackend at U1 changes nothing in the UI.
export class MockBackend implements SparkBackend {
  private state: ConnState = "disconnected";
  private timer: ReturnType<typeof setTimeout> | null = null;

  async status(): Promise<SparkStatus> {
    return {
      state: this.state,
      protocol: "AnyTLS",
      routing: "Full tunnel",
      failOpen: this.state !== "connected",
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
}
