<script lang="ts">
  // An informational note: a Material `info` icon beside a line or two of text, on an elevated card.
  //
  // A component rather than per-page markup because the Unbounded screen's note drew three separate
  // complaints in the Lantern implementation (getlantern/engineering#3844) — wrong component, wrong
  // font, and a misaligned icon — all of which are what inlined one-off markup produces. Anything
  // else in the app needing a note should use this and inherit the fixes.
  //
  // Details worth not re-deriving:
  //   - the icon is a real Material Symbol, not the `ⓘ` text character the previous markup used. A
  //     glyph from the body font has its own baseline and optical size, which is what "the icon is
  //     misaligned top and bottom" describes.
  //   - `align-items: center` on the row, so a one-line note centres its icon rather than pinning it
  //     to the first line's ascender.
  //   - Body/Large (Urbanist Regular 16/26) per Figma, and padding kept tight — round 2 asked for
  //     "less padding above and below the text".
  import Icon from "$lib/Icon.svelte";

  let { text }: { text: string } = $props();
</script>

<div class="note">
  <span class="ic"><Icon name="info" size={20} /></span>
  <p>{text}</p>
</div>

<style>
  .note {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    background: var(--surface);
    border-radius: 16px;
    box-shadow: 0 4px 32px var(--shadow);
  }
  .ic {
    display: inline-flex;
    color: var(--text-tertiary);
  }
  p {
    margin: 0;
    /* Body/Large, trimmed to 1.35 so a two-line note stays compact in the fixed-height window. */
    font-size: 16px;
    font-weight: 400;
    line-height: 1.35;
    color: var(--text-secondary);
  }
</style>
