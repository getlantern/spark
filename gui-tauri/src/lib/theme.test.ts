import { describe, it, expect, beforeEach } from "vitest";
import { get } from "svelte/store";
import { resolveTheme, setTheme, theme } from "./theme";

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
