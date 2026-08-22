import { describe, it, expect, beforeEach } from "vitest";
import { MockBackend } from "./spark_backend";

describe("MockBackend unbounded", () => {
  let mock: MockBackend;
  beforeEach(() => {
    mock = new MockBackend();
  });

  it("starts disabled with an empty view", async () => {
    expect(await mock.unboundedStatus()).toEqual({
      enabled: false,
      helpingNow: 0,
      totalHelped: 0,
      peers: [],
      // No self lookup while sharing is off — we only ask the geo service where we are because the
      // user turned the feature on.
      origin: null,
    });
  });

  it("reflects enabled:true after unboundedStart()", async () => {
    await mock.unboundedStart();
    expect((await mock.unboundedStatus()).enabled).toBe(true);
    await mock.unboundedStop();
  });

  it("reflects enabled:false after unboundedStop()", async () => {
    await mock.unboundedStart();
    await mock.unboundedStop();
    expect((await mock.unboundedStatus()).enabled).toBe(false);
  });

  it("defaults settings to all false, with no manual port override", async () => {
    expect(await mock.unboundedGetSettings()).toEqual({
      autoEnable: false,
      hidden: false,
      welcomeSeen: false,
      // null, not 0: zero is a real value in the port-mapping protocols (a wildcard forwarding every
      // port), so "unset" must not be spelled the same way.
      manualPort: null,
    });
  });

  it("clears the manual port when sent zero", async () => {
    await mock.unboundedSetSettings({ manualPort: 51820 });
    expect((await mock.unboundedGetSettings()).manualPort).toBe(51820);
    await mock.unboundedSetSettings({ manualPort: 0 });
    expect((await mock.unboundedGetSettings()).manualPort).toBeNull();
  });

  it("persists a partial settings update", async () => {
    await mock.unboundedSetSettings({ welcomeSeen: true });
    expect((await mock.unboundedGetSettings()).welcomeSeen).toBe(true);
  });

  it("reports the feature as available (dev-visible)", async () => {
    expect(await mock.unboundedAvailable()).toBe(true);
  });
});
