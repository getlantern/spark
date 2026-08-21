import { describe, it, expect } from "vitest";
import { arrivals, newArrivalTracker, unboundedVisible } from "./unbounded";

const p = (id: string) => ({ sessionId: id });

describe("unboundedVisible", () => {
  it("shows only when server-enabled and not hidden", () => {
    expect(unboundedVisible(true, false)).toBe(true);
    expect(unboundedVisible(true, true)).toBe(false);
    expect(unboundedVisible(false, false)).toBe(false);
    expect(unboundedVisible(false, true)).toBe(false);
  });
});

describe("arrivals", () => {
  it("celebrates nobody before a real snapshot has landed", () => {
    const t = newArrivalTracker();
    // The page paints from a placeholder status before its first fetch returns.
    expect(arrivals(t, [], false)).toEqual([]);
    expect(t.baselined).toBe(false);
  });

  it("absorbs the first real snapshot silently, however many peers are in it", () => {
    const t = newArrivalTracker();
    // Opening the screen while three people are already connected is not three arrivals.
    expect(arrivals(t, [p("a"), p("b"), p("c")], true)).toEqual([]);
    expect(t.baselined).toBe(true);
  });

  it("does not defer the false burst by one tick when the placeholder comes first", () => {
    const t = newArrivalTracker();
    // The regression the `loaded` flag exists for: baselining on the first CALL would take the
    // placeholder's empty list as the baseline, then celebrate everyone on the snapshot after it.
    arrivals(t, [], false);
    expect(arrivals(t, [p("a"), p("b")], true)).toEqual([]);
  });

  it("celebrates a peer that arrives after the baseline, once", () => {
    const t = newArrivalTracker();
    arrivals(t, [p("a")], true);
    expect(arrivals(t, [p("a"), p("b")], true)).toEqual([p("b")]);
    // Same snapshot again: already celebrated.
    expect(arrivals(t, [p("a"), p("b")], true)).toEqual([]);
  });

  it("celebrates a reconnect after a peer has departed", () => {
    const t = newArrivalTracker();
    arrivals(t, [p("a")], true);
    expect(arrivals(t, [], true)).toEqual([]); // a departs
    expect(arrivals(t, [p("a")], true)).toEqual([p("a")]); // and comes back
  });

  it("prunes a departure that shares a tick with an arrival", () => {
    const t = newArrivalTracker();
    arrivals(t, [p("a")], true);
    // `a` leaves in the very tick `b` joins. Pruning only on quiet ticks left `a` in the set, so
    // its reconnect below went uncelebrated.
    expect(arrivals(t, [p("b")], true)).toEqual([p("b")]);
    expect(arrivals(t, [p("a"), p("b")], true)).toEqual([p("a")]);
  });
});
