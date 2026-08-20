import { describe, it, expect } from "vitest";
import { protocolLabel } from "./format";

// `protocolLabel` is deliberately NOT a lookup table (see its doc comment): a transport can be
// introduced by the server and run by a client that has never heard of it, so naming has to work
// without a client release. These cases pin the consequence of that choice — a generic transform,
// applied to names this build does not know.
describe("protocolLabel", () => {
  it("capitalizes a lowercase wire name", () => {
    expect(protocolLabel("unbounded")).toBe("Unbounded");
    expect(protocolLabel("samizdat")).toBe("Samizdat");
  });

  it("leaves the rest of the name exactly as the config delivered it", () => {
    // Not "Hysteria 2" and not "Anytls" — only the first letter is ours to change. Anything more
    // would be a lookup table wearing a disguise, and would mangle a name we have never seen.
    expect(protocolLabel("hysteria2")).toBe("Hysteria2");
    expect(protocolLabel("dns-tunnel")).toBe("Dns-tunnel");
  });

  it("is a no-op on a name the server already capitalized", () => {
    // Upper-casing an upper-case letter changes nothing, so a server that ships a display-ready
    // name keeps it verbatim — including interior capitals a naive title-case would flatten.
    expect(protocolLabel("AnyTLS")).toBe("AnyTLS");
    expect(protocolLabel("BIP324")).toBe("BIP324");
  });

  it("trims, because whitespace is not a name", () => {
    expect(protocolLabel("  meek  ")).toBe("Meek");
  });

  it("yields empty string for absent or whitespace-only names so callers can test it", () => {
    // The home tile and the server rows gate their subtitle on the LABEL rather than the raw field,
    // so a whitespace-only protocol must collapse to falsy instead of rendering a blank line.
    expect(protocolLabel(undefined)).toBe("");
    expect(protocolLabel(null)).toBe("");
    expect(protocolLabel("")).toBe("");
    expect(protocolLabel("   ")).toBe("");
  });

  it("upper-cases a cased astral first character rather than splitting it", () => {
    // Deseret, which HAS an uppercase mapping — so this proves the transform applies to an astral
    // char, not merely that we avoid cutting one in half. Indexing by UTF-16 unit would emit a lone
    // surrogate here: mojibake, not just something ugly.
    expect(protocolLabel("𐐨bfs")).toBe("𐐀bfs");
    // And one with NO uppercase mapping passes through unchanged, rather than being mangled.
    expect(protocolLabel("𝟶bfs")).toBe("𝟶bfs");
  });
});
