// The real backend: drives the Rust command surface (spark_status /
// spark_connect / spark_disconnect) over Tauri's invoke(). status() reflects the
// live NE connection state; connect()/disconnect() drive the real NE write path
// (NETunnelProviderManager save/load/start/stop). Same SparkBackend shape as
// MockBackend, so the UI is unchanged.

import { invoke } from "@tauri-apps/api/core";

import type { ServerInfo, SparkBackend, SparkStatus, SplitTunnel } from "./spark_backend";

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
  async servers(): Promise<ServerInfo[]> {
    return await invoke<ServerInfo[]>("spark_servers");
  }
  async selectServer(index: number | null): Promise<void> {
    // The Rust command takes a plain i32; -1 means auto (the pool has no negative indices).
    await invoke("spark_select_server", { index: index ?? -1 });
  }
  async getSplitTunnel(): Promise<SplitTunnel> {
    return JSON.parse(await invoke<string>("spark_get_split_tunnel"));
  }
  async setSplitTunnel(st: SplitTunnel): Promise<void> {
    await invoke("spark_set_split_tunnel", { json: JSON.stringify(st) });
  }
  async getRoutingMode(): Promise<"smart" | "full"> {
    return (await invoke<string>("spark_get_routing_mode")) as "smart" | "full";
  }
  async setRoutingMode(mode: "smart" | "full"): Promise<void> {
    await invoke("spark_set_routing_mode", { mode });
  }
}

// True when running inside the Tauri webview (vs a plain browser at `npm run dev`).
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
