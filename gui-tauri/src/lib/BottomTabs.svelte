<script lang="ts">
  // Bottom navigation between the two primary views — VPN and Unbounded — per the design.
  // Rendered only when Unbounded is available (otherwise there's nothing to switch to). The
  // active segment is raised on a light pill; each carries a small status dot (green = on).
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
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 19 4"/><path d="M16 7l3 3"/><path d="M14 9l3 3"/></svg>
    </span>
    <span class="label">{$_("tab_vpn")}</span>
    <span class="dot" class:on={vpnOn}></span>
  </button>

  <button
    class="seg"
    class:active={current === "unbounded"}
    aria-current={current === "unbounded" ? "page" : undefined}
    onclick={() => current !== "unbounded" && goto("/unbounded")}
  >
    <span class="ic">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 12l2.5 2.5a2 2 0 0 0 2.8 0L18 10"/><path d="M6 10l3-3a2 2 0 0 1 2.8 0l1.2 1.2"/><path d="M2 12l4-4"/><path d="M22 12l-4-4"/></svg>
    </span>
    <span class="label">{$_("tab_unbounded")}</span>
    <span class="dot" class:on={unboundedOn}></span>
  </button>
</nav>

<style>
  .tabs {
    flex-shrink: 0;
    display: flex;
    gap: 8px;
    padding: 10px 16px calc(10px + env(safe-area-inset-bottom, 0px));
    background: var(--bg);
    border-top: 1px solid var(--border);
  }
  .seg {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 10px;
    border: none;
    border-radius: 14px;
    background: transparent;
    color: var(--text-tertiary);
    font-family: var(--font);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition:
      background 0.15s ease,
      color 0.15s ease;
  }
  .seg:hover {
    background: var(--hover);
  }
  .seg.active {
    background: var(--pill-bg);
    color: var(--text-primary);
    cursor: default;
  }
  .ic {
    display: inline-flex;
  }
  .label {
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
</style>
