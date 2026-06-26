<script lang="ts">
  // Urbanist — the actual Lantern app font (getlantern/lantern app_text_styles.dart), bundled
  // locally (CSP-safe, no CDN). Loaded in the layout so the tokens + font persist across routes
  // (home ↔ server selection); a component-scoped :global() block would be torn down on navigation.
  import "@fontsource/urbanist/latin-400.css";
  import "@fontsource/urbanist/latin-500.css";
  import "@fontsource/urbanist/latin-600.css";
  import "@fontsource/urbanist/latin-700.css";

  let { children } = $props();
</script>

{@render children()}

<style>
  /* Lantern palette (app_colors.dart) + semantic mappings (app_semantic_colors.dart), shared by
     every route. */
  :global(:root) {
    --bg: #f8fafb;          /* gray1  bg.surface */
    --surface: #ffffff;     /* gray0  card */
    --brand: #00bdd6;       /* blue4  toggle-brand-active */
    --off: #616569;         /* gray7  toggle-disabled */
    --knob: #ffffff;        /* gray0  toggle-knob */
    --text-primary: #1b1c1d;   /* gray9 */
    --text-secondary: #3e464e; /* gray8 */
    --text-tertiary: #616569;  /* gray7 */
    --border: #edefef;      /* gray2 */
    --success: #00531f;     /* green8  status-success-text */
    --indicator-off: #dedfdf; /* gray3 */
    --shadow: rgba(0, 97, 98, 0.098); /* shadowColor 0x19006162 (teal-tinted) */
    --bolt: #f5b800;        /* statusWarningBgDot — the smart/auto bolt */
    /* Latency-pill thresholds: good < 80ms, amber < 160ms, else slow. Ramp connotes speed, not
       danger: green -> yellow-green -> gold. No red (a slow server is "slower", not an error). */
    --lat-good: #1f9d55;
    --lat-amber: #7ca006;
    --lat-slow: #c98a00;
    --font: "Urbanist", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  :global(html),
  :global(body) {
    margin: 0;
    height: 100%;
    background: var(--bg);
    font-family: var(--font);
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
    user-select: none;
  }
</style>
