import { describe, it, expect } from "vitest";
import { unboundedVisible } from "./unbounded";

describe("unboundedVisible", () => {
  it("shows only when server-enabled and not hidden", () => {
    expect(unboundedVisible(true, false)).toBe(true);
    expect(unboundedVisible(true, true)).toBe(false);
    expect(unboundedVisible(false, false)).toBe(false);
    expect(unboundedVisible(false, true)).toBe(false);
  });
});
