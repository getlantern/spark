<script lang="ts">
  // Bottom navigation between the two primary views — VPN and Unbounded — per the design.
  // Each segment stacks an icon over its label (VPN = key, Unbounded = handshake), with a status
  // indicator beside the label (grey dot for VPN, green broadcast for Unbounded). The active
  // segment is raised on a light pill. Shown only when Unbounded is available.
  import { goto } from "$app/navigation";
  import { _ } from "$lib/i18n";

  let {
    current,
    vpnOn = false,
    unboundedOn = false,
  }: { current: "vpn" | "unbounded"; vpnOn?: boolean; unboundedOn?: boolean } = $props();
</script>

<nav class="tabs" aria-label="Primary">
  <button
    class="seg"
    class:active={current === "vpn"}
    aria-current={current === "vpn" ? "page" : undefined}
    onclick={() => current !== "vpn" && goto("/")}
  >
    <span class="ic">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7" cy="12" r="3.2"/><path d="M10.2 12H21"/><path d="M17.5 12v3"/><path d="M20.5 12v2.4"/></svg>
    </span>
    <span class="foot">
      <span class="label">{$_("tab_vpn")}</span>
      <span class="dot" class:on={vpnOn}></span>
    </span>
  </button>

  <button
    class="seg"
    class:active={current === "unbounded"}
    aria-current={current === "unbounded" ? "page" : undefined}
    onclick={() => current !== "unbounded" && goto("/unbounded")}
  >
    <span class="ic">
      <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m11 17 2 2a1 1 0 1 0 3-3"/><path d="m14 14 2.5 2.5a1 1 0 1 0 3-3l-3.88-3.88a3 3 0 0 0-4.24 0l-.88.88a1 1 0 1 1-3-3l2.81-2.81a5.79 5.79 0 0 1 7.06-.87l.47.28a2 2 0 0 0 1.42.25L21 4"/><path d="m21 3 1 11h-2"/><path d="M3 3 2 14l6.5 6.5a1 1 0 1 0 3-3"/><path d="M3 4h8"/></svg>
    </span>
    <span class="foot">
      <span class="label">{$_("tab_unbounded")}</span>
      <span class="cast" class:on={unboundedOn} aria-hidden="true">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none"/><path d="M8.5 8.5a5 5 0 0 0 0 7"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/></svg>
      </span>
    </span>
  </button>
</nav>

<style>
  .tabs {
    flex-shrink: 0;
    display: flex;
    gap: 10px;
    padding: 8px 16px calc(8px + env(safe-area-inset-bottom, 0px));
    background: var(--bg);
    border-top: 1px solid var(--border);
  }
  .seg {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 8px 10px;
    border: none;
    border-radius: 16px;
    background: transparent;
    color: var(--text-tertiary);
    font-family: var(--font);
    cursor: pointer;
    transition:
      background 0.15s ease,
      color 0.15s ease;
  }
  .seg:hover {
    background: var(--hover);
  }
  .seg.active {
    background: rgba(0, 189, 214, 0.12);
    color: var(--text-primary);
    cursor: default;
  }
  .ic {
    display: inline-flex;
  }
  .foot {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .label {
    font-size: 13px;
    font-weight: 600;
    letter-spacing: -0.1px;
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--indicator-off, #c2ccd2);
    flex-shrink: 0;
  }
  .dot.on {
    background: var(--success, #34b759);
  }
  /* Broadcast glyph: muted when idle, green when Unbounded is on. */
  .cast {
    display: inline-flex;
    color: var(--indicator-off, #c2ccd2);
  }
  .cast.on {
    color: var(--success, #34b759);
  }
</style>
