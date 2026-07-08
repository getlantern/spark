<script lang="ts">
  // Content-loading spinner, matching Lantern's `Spinner` widget (a CircularProgressIndicator with
  // strokeWidth 8, neutral color — lantern/lib/core/widgets/spinner.dart) and the app's existing
  // connect-toggle spinner. A neutral ring on a faint track; stroke scales with size (~1/6, like
  // Lantern's 8px on a ~48px indicator). Use anywhere a fetch/enumeration can take a beat.
  let { size = 40 }: { size?: number } = $props();
  const stroke = $derived(Math.max(2, Math.round(size / 6)));
</script>

<span
  class="spinner"
  style="width:{size}px;height:{size}px;border-width:{stroke}px"
  role="status"
  aria-label="Loading"
></span>

<style>
  .spinner {
    display: inline-block;
    box-sizing: border-box;
    border-radius: 50%;
    border-style: solid;
    border-color: var(--indicator-off); /* faint track */
    border-top-color: var(--text-secondary); /* the moving arc (neutral, like Lantern's logTextColor) */
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
