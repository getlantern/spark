#!/usr/bin/env node
// Convert vendored Lantern .po (+ a Spark overlay) to per-locale JSON for svelte-i18n.
// Output src/lib/i18n/generated/{locale}.json = { key: string }. Header + empty msgstr dropped
// so missing strings fall back to English (svelte-i18n fallbackLocale).
import gettextParser from "gettext-parser";
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, basename } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const PO_DIR = join(HERE, "..", "src", "lib", "i18n", "po");
const SPARK_DIR = join(HERE, "..", "src", "lib", "i18n", "spark");
const OUT_DIR = join(HERE, "..", "src", "lib", "i18n", "generated");

export function poToMap(poText) {
  const parsed = gettextParser.po.parse(poText, "utf-8");
  const ctx = parsed.translations[""] || {};
  const out = {};
  for (const [msgid, entry] of Object.entries(ctx)) {
    if (msgid === "") continue;                 // header
    const value = entry.msgstr && entry.msgstr[0];
    if (!value) continue;                        // empty -> English fallback
    out[msgid] = value;
  }
  return out;
}

export function build() {
  mkdirSync(OUT_DIR, { recursive: true });
  const poFiles = readdirSync(PO_DIR).filter((f) => f.endsWith(".po"));
  if (poFiles.length === 0) throw new Error(`no .po files in ${PO_DIR}`);
  for (const file of poFiles) {
    const locale = basename(file, ".po");
    const base = poToMap(readFileSync(join(PO_DIR, file), "utf-8"));
    const overlayPath = join(SPARK_DIR, `${locale}.json`);
    const overlay = existsSync(overlayPath) ? JSON.parse(readFileSync(overlayPath, "utf-8")) : {};
    writeFileSync(join(OUT_DIR, `${locale}.json`), JSON.stringify({ ...base, ...overlay }, null, 2) + "\n");
  }
  return poFiles.map((f) => basename(f, ".po"));
}

if (process.argv[1] && process.argv[1].endsWith("po-to-json.mjs")) {
  const locales = build();
  console.log(`i18n: generated ${locales.length} locales -> src/lib/i18n/generated/`);
}
