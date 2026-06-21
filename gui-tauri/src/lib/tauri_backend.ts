// The real backend: drives the Rust command surface (spark_status /
// spark_connect / spark_disconnect) over Tauri's invoke(). status() reflects the
// live NE connection state; connect()/disconnect() drive the real NE write path
// (NETunnelProviderManager save/load/start/stop). Same SparkBackend shape as
// MockBackend, so the UI is unchanged.

import { invoke } from "@tauri-apps/api/core";

import type { SparkBackend, SparkStatus } from "./spark_backend";

export class TauriBackend implements SparkBackend {
  async status(): Promise<SparkStatus> {
    return await invoke<SparkStatus>("spark_status");
  }
  async connect(): Promise<void> {
    await invoke("spark_connect");
  }
  async disconnect(): Promise<void> {
    await invoke("spark_disconnect");
  }
}

/// True when running inside the Tauri webview (vs a plain browser at `npm run dev`).
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
