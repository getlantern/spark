import { describe, it, expect, beforeEach } from "vitest";
import { get } from "svelte/store";
import { selectedIndex, selectServer, syncFromSnapshot, reapplyIfDropped } from "./selection";
import { MockBackend, type ServerInfo } from "./spark_backend";

// A pool member, keyed the way the tunnel's snapshot reports it. `isPinned` is the user's pick tracked
// by identity; `isCurrent` marks both the member flows dial and (by its presence anywhere in the list)
// that this came from a live tunnel rather than the pre-connect config cache. `id` is the location the
// UI shows — pass it explicitly to model the same server appearing at a different index in another list.
function member(index: number, isCurrent = false, isPinned = false, id = index): ServerInfo {
  return {
    index,
    name: `s${id}`,
    country: "United States",
    countryCode: "US",
    city: `city${id}`,
    protocol: "hysteria2",
    latencyMs: 20 + index,
    healthy: true,
    isCurrent,
    isPinned,
  };
}

// A pre-connect list: no live snapshot, so nothing is current and nothing carries a pin.
const preConnect = [member(0), member(1), member(2)];

describe("selectedIndex ↔ snapshot reconciliation", () => {
  beforeEach(async () => {
    await selectServer(null); // reset both the store and the mock backend's pin
  });

  it("follows the pin to its new index after a refresh reorders the pool", async () => {
    await selectServer(1);
    // The refresh moved the pinned server to slot 2. Keeping the old index would name member 1 —
    // a different server — which is the bug this exists to prevent.
    syncFromSnapshot([member(0), member(1), member(2, true, true)]);
    expect(get(selectedIndex)).toBe(2);
  });

  it("leaves the pin alone when the snapshot carries none", async () => {
    await selectServer(1);
    syncFromSnapshot([member(0, true), member(1), member(2)]); // live, tunnel on auto
    expect(get(selectedIndex)).toBe(1);
    syncFromSnapshot(preConnect); // and a pre-connect list must not clear it either
    expect(get(selectedIndex)).toBe(1);
  });

  it("re-pushes a pin the tunnel hasn't taken up, once a pool exists", async () => {
    await selectServer(2, member(2));
    // Simulate the tunnel having started fresh on auto (a restart resets the pin): the store holds the
    // intent, the live snapshot reports none.
    const mock = new MockBackend();
    await mock.selectServer(null);
    await reapplyIfDropped([member(0, true), member(1), member(2)]);
    expect((await mock.servers()).find((s) => s.isPinned)?.index).toBe(2);
    expect(get(selectedIndex)).toBe(2);
  });

  it("re-pushes by location, not by the index the pick was made against", async () => {
    // The pick came from the pre-connect list, whose order is the app's own config fetch — independent
    // of the tunnel's, so slot 2 there is a different server here. Pushing the bare index would pin
    // whatever now sits in it: the very bug this module exists to prevent, on the write path.
    await selectServer(2, member(2, false, false, 7)); // "city7" happened to be at index 2 there
    const mock = new MockBackend();
    await mock.selectServer(null);
    const live = [member(0, true, false, 7), member(1, false, false, 3), member(2, false, false, 9)];
    await reapplyIfDropped(live);
    expect((await mock.servers()).find((s) => s.isPinned)?.index).toBe(0); // city7, not slot 2
    expect(get(selectedIndex)).toBe(0);
  });

  it("does not try to apply a pin before there is a pool", async () => {
    await selectServer(2, member(2));
    const mock = new MockBackend();
    await mock.selectServer(null);
    await reapplyIfDropped(preConnect); // no live snapshot — the apply would just fail
    expect((await mock.servers()).some((s) => s.isPinned)).toBe(false);
    expect(get(selectedIndex)).toBe(2); // intent survives for the next live poll
  });

  it("drops to auto when the picked location is not in the pool", async () => {
    await selectServer(5, member(5));
    // Terminates the retry: a pin the pool can't satisfy would otherwise be re-pushed every poll.
    await reapplyIfDropped([member(0, true), member(1)]);
    expect(get(selectedIndex)).toBe(null);
  });

  it("drops to auto rather than guessing when the pick was never identified", async () => {
    // e.g. a pin adopted from the plugin cache on mount, with no snapshot to identify it against. An
    // index alone is not enough to re-apply — pushing it would be a guess at which server it names.
    await selectServer(1);
    const mock = new MockBackend();
    await mock.selectServer(null);
    await reapplyIfDropped([member(0, true), member(1), member(2)]);
    expect((await mock.servers()).some((s) => s.isPinned)).toBe(false);
    expect(get(selectedIndex)).toBe(null);
  });
});
