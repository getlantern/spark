import { register, init, locale, _, isLoading, waitLocale } from "svelte-i18n";
import { derived } from "svelte/store";
import { SUPPORTED, RTL_LOCALES, matchLocale } from "./locales";

const STORAGE_KEY = "spark.locale";
const FALLBACK = "en";

// Register every supported locale with a lazy loader for its generated dictionary.
const dicts = import.meta.glob("./generated/*.json");
for (const { code } of SUPPORTED) {
  const loader = dicts[`./generated/${code}.json`];
  if (loader) register(code, () => loader() as Promise<Record<string, string>>);
}

export async function resolveInitialLocale(): Promise<string> {
  try {
    const saved = matchLocale(localStorage.getItem(STORAGE_KEY));
    if (saved) return saved;
  } catch { /* localStorage unavailable */ }
  let osLocale: string | null = null;
  try {
    const os = await import("@tauri-apps/plugin-os");
    osLocale = await os.locale();
  } catch {
    osLocale = typeof navigator !== "undefined" ? navigator.language : null;
  }
  return (
    matchLocale(osLocale) ??
    matchLocale(typeof navigator !== "undefined" ? navigator.language : null) ??
    FALLBACK
  );
}

export async function setupI18n(): Promise<void> {
  const initialLocale = await resolveInitialLocale();
  init({ fallbackLocale: FALLBACK, initialLocale });
  await waitLocale();
}

export function setLocale(code: string): void {
  try { localStorage.setItem(STORAGE_KEY, code); } catch { /* ignore */ }
  locale.set(code);
}

export const isRtl = derived(locale, ($locale) => !!$locale && RTL_LOCALES.has($locale));

export { _, locale, isLoading };
