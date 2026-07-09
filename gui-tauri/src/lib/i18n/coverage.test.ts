import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import en from "./generated/en.json";

function svelteFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...svelteFiles(p));
    else if (e.name.endsWith(".svelte")) out.push(p);
  }
  return out;
}

function usedKeys(src: string): string[] {
  const keys: string[] = [];
  const re = /\$(?:_|format)\(\s*["']([^"']+)["']/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) keys.push(m[1]);
  return keys;
}

describe("i18n key coverage", () => {
  it("every $_() key used in .svelte exists in English", () => {
    const dict = en as Record<string, string>;
    const missing = new Set<string>();
    for (const file of svelteFiles(join(__dirname, "..", "..", "routes"))) {
      for (const key of usedKeys(readFileSync(file, "utf-8"))) {
        if (!(key in dict)) missing.add(key);
      }
    }
    expect([...missing].sort()).toEqual([]);
  });
});
