import { describe, it, expect, beforeEach } from "vitest";
import { get } from "svelte/store";
import { selectedIndex, selectServer, syncFromSnapshot, reapplyIfDropped } from "./selection";
import { MockBackend, type ServerInfo } from "./spark_backend";

// A pool member, keyed the way the tunnel's snapshot reports it. `isPinned` is the user's pick tracked
// by identity; `isCurrent` marks both the member flows dial and (by its presence anywhere in the list)
// that this came from a live tunnel rather than the pre-connect config cache.
function member(index: number, isCurrent = false, isPinned = false): ServerInfo {
  return {
    index,
    name: `s${index}`,
    country: "United States",
    countryCode: "US",
    city: `city${index}`,
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
    await selectServer(2);
    // Simulate the tunnel having started fresh on auto (a restart resets the pin): the store holds the
    // intent, the live snapshot reports none.
    const mock = new MockBackend();
    await mock.selectServer(null);
    await reapplyIfDropped([member(0, true), member(1), member(2)]);
    expect((await mock.servers()).find((s) => s.isPinned)?.index).toBe(2);
    expect(get(selectedIndex)).toBe(2);
  });

  it("does not try to apply a pin before there is a pool", async () => {
    await selectServer(2);
    const mock = new MockBackend();
    await mock.selectServer(null);
    await reapplyIfDropped(preConnect); // no live snapshot — the apply would just fail
    expect((await mock.servers()).some((s) => s.isPinned)).toBe(false);
    expect(get(selectedIndex)).toBe(2); // intent survives for the next live poll
  });

  it("drops to auto when the pool no longer has the pinned member", async () => {
    await selectServer(5);
    // Terminates the retry: a pin the pool can't satisfy would otherwise be re-pushed every poll.
    await reapplyIfDropped([member(0, true), member(1)]);
    expect(get(selectedIndex)).toBe(null);
  });
});
