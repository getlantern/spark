// Appearance state: System (follow OS) / Light / Dark. Pure front-end state persisted in
// localStorage — the tunnel core never needs it (unlike routing/ad-block). Mirrors the i18n
// locale store. The layout maps `theme` -> a `data-theme` attribute on <html>; the dark palette
// keys off `:root[data-theme="dark"]`. Default 'system' preserves the OS-following behavior.
import { writable } from "svelte/store";

export type Theme = "system" | "light" | "dark";

const STORAGE_KEY = "spark.theme";
const THEMES: Theme[] = ["system", "light", "dark"];

function initialTheme(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v && (THEMES as string[]).includes(v)) return v as Theme;
  } catch {
    /* localStorage unavailable (SSR / node) */
  }
  return "system";
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
