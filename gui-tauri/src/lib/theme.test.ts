import { describe, it, expect, beforeEach } from "vitest";
import { get } from "svelte/store";
import { coerceTheme, resolveTheme, setTheme, theme } from "./theme";

describe("coerceTheme", () => {
  it("passes valid themes through", () => {
    expect(coerceTheme("system")).toBe("system");
    expect(coerceTheme("light")).toBe("light");
    expect(coerceTheme("dark")).toBe("dark");
  });
  it("defaults to 'system' for a missing or unknown value", () => {
    expect(coerceTheme(null)).toBe("system");
    expect(coerceTheme(undefined)).toBe("system");
    expect(coerceTheme("")).toBe("system");
    expect(coerceTheme("solarized")).toBe("system");
  });
});

describe("resolveTheme", () => {
  it("passes explicit modes through", () => {
    expect(resolveTheme("dark", false)).toBe("dark");
    expect(resolveTheme("light", true)).toBe("light");
  });
  it("resolves 'system' against the OS preference", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });
});

describe("setTheme", () => {
  beforeEach(() => {
    const store: Record<string, string> = {};
    (globalThis as unknown as { localStorage: Storage }).localStorage = {
      getItem: (k: string) => (k in store ? store[k] : null),
      setItem: (k: string, v: string) => { store[k] = v; },
      removeItem: (k: string) => { delete store[k]; },
      clear: () => { for (const k of Object.keys(store)) delete store[k]; },
      key: () => null,
      length: 0,
    } as Storage;
  });
  it("updates the store and persists the choice", () => {
    setTheme("dark");
    expect(get(theme)).toBe("dark");
    expect(localStorage.getItem("spark.theme")).toBe("dark");
  });
});
