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

/// The transport's name, exactly as the config delivered it.
///
/// Deliberately not a lookup table. Transports are introduced by the *server* — a signed module
/// arrives over the config channel and a client that has never heard of it can run it — so a
/// client-side map of display names would mean every new transport needed a client release just to
/// be named, which is the property the delivery channel exists to remove. A map would also fail
/// unevenly: known transports would look finished and each new one would look unfinished, for no
/// reason a user could perceive.
///
/// So the name the config gives is the name shown. Whoever names a transport server-side chooses
/// how it reads, and can change it without shipping anything.
///
/// Trimmed only — whitespace is not a name — and empty/null yields "" so callers can test it.
export function protocolLabel(protocol?: string | null): string {
  return protocol?.trim() ?? "";
}

/// Latency band for the pill color. `null`/unhealthy → "slow" (worst, so it never looks fast).
export function latencyClass(latencyMs?: number | null): "good" | "amber" | "slow" {
  if (latencyMs == null) return "slow";
  if (latencyMs < 80) return "good";
  if (latencyMs < 160) return "amber";
  return "slow";
}
