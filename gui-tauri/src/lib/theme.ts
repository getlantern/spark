// Appearance state: System (follow OS) / Light / Dark. Pure front-end state persisted in
// localStorage — the tunnel core never needs it (unlike routing/ad-block). Mirrors the i18n
// locale store. The layout maps `theme` -> a `data-theme` attribute on <html>; the dark palette
// keys off `:root[data-theme="dark"]`. Default 'system' preserves the OS-following behavior.
import { writable } from "svelte/store";

export type Theme = "system" | "light" | "dark";

const STORAGE_KEY = "spark.theme";
const THEMES: Theme[] = ["system", "light", "dark"];

/** Coerce a raw stored value to a valid Theme, defaulting to 'system' for a missing/unknown value.
 * Pure (no localStorage) so the init/default/fallback behavior is unit-testable. */
export function coerceTheme(v: string | null | undefined): Theme {
  return v && (THEMES as string[]).includes(v) ? (v as Theme) : "system";
}

function initialTheme(): Theme {
  try {
    return coerceTheme(localStorage.getItem(STORAGE_KEY));
  } catch {
    /* localStorage unavailable (SSR / node) */
    return "system";
  }
}

export const theme = writable<Theme>(initialTheme());

export function setTheme(t: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, t);
  } catch {
    /* ignore */
  }
  theme.set(t);
}

/** Resolve the effective palette. 'system' follows the OS; explicit modes pass through. */
export function resolveTheme(t: Theme, prefersDark: boolean): "light" | "dark" {
  if (t === "dark") return "dark";
  if (t === "light") return "light";
  return prefersDark ? "dark" : "light";
}
