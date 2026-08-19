// Small presentation helpers shared by the home tile and the server-selection screen.
import type { ServerInfo } from "./spark_backend";

/// A flag emoji from an ISO 3166-1 alpha-2 code (e.g. "US" → 🇺🇸), via Unicode regional indicators.
/// Falls back to a neutral white flag for missing/odd codes — the same approach as Lantern's `Flag`.
export function flagEmoji(countryCode?: string | null): string {
  if (!countryCode || countryCode.length !== 2) return "🏳️";
  const A = 0x1f1e6; // regional indicator 'A'
  const cc = countryCode.toUpperCase();
  const a = cc.charCodeAt(0) - 65;
  const b = cc.charCodeAt(1) - 65;
  if (a < 0 || a > 25 || b < 0 || b > 25) return "🏳️";
  return String.fromCodePoint(A + a, A + b);
}

/// "Country – City", or whichever is present, falling back to the server name then "Server".
export function serverLabel(s: ServerInfo): string {
  const parts = [s.country, s.city].filter((p): p is string => !!p && p.length > 0);
  if (parts.length) return parts.join(" – ");
  return s.name || "Server";
}

/// Canonical display name for a transport protocol kind (e.g. "hysteria2" → "Hysteria2",
/// "anytls" → "AnyTLS"). Unknown kinds pass through unchanged; null/empty → "".
export function protocolLabel(protocol?: string | null): string {
  if (!protocol) return "";
  const known: Record<string, string> = {
    anytls: "AnyTLS",
    samizdat: "Samizdat",
    shadowsocks: "Shadowsocks",
    hysteria2: "Hysteria2",
    // A delivered module reports the engine it was signed as, so this maps the engines rather than
    // the mechanism. "WASM" stays only as the fallback for a locally provisioned artifact, which
    // has a file rather than an engine to name.
    bip324: "BIP324",
    wasm: "WASM",
    tunnel: "Tunnel",
  };
  return known[protocol.toLowerCase()] ?? protocol;
}

/// Latency band for the pill color. `null`/unhealthy → "slow" (worst, so it never looks fast).
export function latencyClass(latencyMs?: number | null): "good" | "amber" | "slow" {
  if (latencyMs == null) return "slow";
  if (latencyMs < 80) return "good";
  if (latencyMs < 160) return "amber";
  return "slow";
}
