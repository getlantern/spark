import { describe, it, expect } from "vitest";
import { matchLocale, SUPPORTED, RTL_LOCALES } from "./locales";

describe("matchLocale", () => {
  it("matches exact codes", () => {
    expect(matchLocale("fa")).toBe("fa");
    expect(matchLocale("zh-Hans")).toBe("zh-Hans");
  });
  it("matches by base language", () => {
    expect(matchLocale("fa-IR")).toBe("fa");
    expect(matchLocale("fr-FR")).toBe("fr");
  });
  it("maps zh variants", () => {
    expect(matchLocale("zh")).toBe("zh-Hans");
    expect(matchLocale("zh-CN")).toBe("zh-Hans");
    expect(matchLocale("zh-TW")).toBe("zh-Hant");
  });
  it("returns null for unsupported/empty", () => {
    expect(matchLocale("xx")).toBeNull();
    expect(matchLocale("")).toBeNull();
    expect(matchLocale(undefined)).toBeNull();
  });
  it("declares the RTL set", () => {
    expect(RTL_LOCALES.has("fa")).toBe(true);
    expect(RTL_LOCALES.has("en")).toBe(false);
    expect(SUPPORTED.some((l) => l.code === "en")).toBe(true);
  });
});
