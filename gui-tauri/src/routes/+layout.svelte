<script lang="ts">
  // Urbanist — the actual Lantern app font (getlantern/lantern app_text_styles.dart), bundled
  // locally (CSP-safe, no CDN). Loaded in the layout so the tokens + font persist across routes
  // (home ↔ server selection); a component-scoped :global() block would be torn down on navigation.
  import "@fontsource/urbanist/latin-400.css";
  import "@fontsource/urbanist/latin-500.css";
  import "@fontsource/urbanist/latin-600.css";
  import "@fontsource/urbanist/latin-700.css";

  import { setupI18n, isRtl, locale, isLoading } from "$lib/i18n";
  import { theme, resolveTheme } from "$lib/theme";
  import { listen } from "@tauri-apps/api/event";
  import { goto } from "$app/navigation";
  import { initSelectedIndex } from "$lib/selection";
  import { MockBackend, type SparkBackend } from "$lib/spark_backend";
  import { TauriBackend, isTauri } from "$lib/tauri_backend";

  let { children } = $props();

  const backend: SparkBackend = isTauri() ? new TauriBackend() : new MockBackend();

  let ready = $state(false);
  setupI18n().then(() => (ready = true));

  $effect(() => {
    const code = $locale ?? "en";
    document.documentElement.lang = code;
    document.documentElement.dir = $isRtl ? "rtl" : "ltr";
  });

  // Track the OS dark-mode preference reactively so `theme === "system"` follows it live.
  let prefersDark = $state(false);
  $effect(() => {
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    prefersDark = mql.matches;
    const onChange = (e: MediaQueryListEvent) => (prefersDark = e.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  });
  $effect(() => {
    document.documentElement.dataset.theme = resolveTheme($theme, prefersDark);
  });

  // Webview error bridge: uncaught JS exceptions and unhandled rejections are otherwise
  // invisible to diagnostics (spec §C2a), so forward them fire-and-forget to the plugin's
  // diag spool. Everything is wrapped so the handlers themselves can NEVER throw — an
  // error inside the error hook would just re-enter it. Default handling is not suppressed
  // (onerror returns false / no preventDefault), so errors still hit the devtools console.
  $effect(() => {
    const prevOnError = window.onerror;
    window.onerror = (message, source, lineno, colno, error) => {
      try {
        void backend.reportError(String(message ?? "unknown"), source ?? "window").catch(() => {});
      } catch {
        /* swallow — never throw from the error hook */
      }
      // Chain to any previously-installed handler so its reporting keeps working,
      // and propagate its verdict on suppressing default handling. Without one,
      // return false so errors still hit the devtools console.
      try {
        return prevOnError ? prevOnError.call(window, message, source, lineno, colno, error) === true : false;
      } catch {
        return false;
      }
    };
    const onRejection = (e: PromiseRejectionEvent) => {
      try {
        let reason: string;
        try {
          reason = String(e.reason);
        } catch {
          reason = "unstringifiable rejection reason";
        }
        void backend.reportError(reason, "unhandledrejection").catch(() => {});
      } catch {
        /* swallow — never throw from the error hook */
      }
    };
    window.addEventListener("unhandledrejection", onRejection);
    return () => {
      window.onerror = prevOnError ?? null;
      window.removeEventListener("unhandledrejection", onRejection);
    };
  });

  // Tray ↔ window sync: pull the pin on load + whenever the tray changes state; handle tray-driven
  // navigation. Tauri-only — in a plain browser there's no tray and `listen` would reject on mount,
  // producing a noisy unhandled rejection, so skip it entirely off-Tauri.
  $effect(() => {
    if (!isTauri()) return;
    void initSelectedIndex();
    const state = listen("spark://state", () => void initSelectedIndex());
    const nav = listen<string>("spark://navigate", (e) => goto(e.payload));
    return () => {
      state.then((f) => f()).catch((e) => console.error("[layout] unlisten spark://state:", e));
      nav.then((f) => f()).catch((e) => console.error("[layout] unlisten spark://navigate:", e));
    };
  });
</script>

{#if ready && !$isLoading}
  {@render children()}
{/if}

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
    --snack-bg: #23282b;      /* toast background (dark on light) */
    --switch-off: #c8ccce;    /* small toggle track, off (split-tunnel screen) */
    --hover: rgba(0, 0, 0, 0.02);   /* row/tile hover tint */
    --pill-bg: rgba(0, 0, 0, 0.06); /* count-pill background */
    /* Unbounded / tab bar semantics, taken from Figma variables rather than eyeballed. The values
       below were read out of the design file (`Lantern-VPN` node 4734:5498), because the equivalent
       code in Lantern had picked the *adjacent* palette entries — blue2/blue3 instead of blue1/blue2
       — and the mistake is invisible without the source numbers (getlantern/engineering#3844). */
    --tabbar-bg: #f0fdff;            /* action/tabbar/tabbar-bg — selected pill */
    --tabbar-border: #d6f6fa;        /* action/tabbar/tabbar-border */
    --tabbar-selected-text: #012d2d; /* action/tabbar/tabbar-selected-text */
    --tabbar-text: #848484;          /* action/tabbar/tabbar-disabled-text — unselected */
    --link: #004d57;                 /* text/link — stat values, checked checkbox */
    --toggle-on: #3da360;            /* action/toggle/toggle-active-bg — GREEN, not the cyan brand */
    /* Indicator lights are two-tone: a filled dot inside a lighter ring (see Indicator.svelte). */
    --dot-neutral-bg: #a2a2a2;       /* status/neutral-bg-dot */
    --dot-neutral-border: #dedfdf;   /* status/neutral-border-dot */
    --dot-success-bg: #0a8638;       /* status/success-bg-dot */
    --dot-success-border: #a2ddaf;   /* status/success-border-dot */
    --font: "Urbanist", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  /* Dark palette applies when the resolved theme is dark (data-theme is set by +layout.svelte and
     the app.html pre-paint script). 'system' resolves against the OS; explicit Light/Dark force it.
     Declarations are unchanged from the former prefers-color-scheme block. */
  :global(:root[data-theme="dark"]) {
    --bg: #16181b;
    --surface: #1e2124;
    --brand: #00bdd6;
    --off: #4b5056;
    --knob: #ffffff;
    --text-primary: #f4f6f7;
    --text-secondary: #c2c7cc;
    --text-tertiary: #9aa0a6;
    --border: #2a2e33;
    --success: #34c759;
    --indicator-off: #3a3f45;
    --shadow: rgba(0, 0, 0, 0.45);
    --bolt: #ffc105;
    --lat-good: #34c759;
    --lat-amber: #b7c94a;
    --lat-slow: #e0a52a;
    --snack-bg: #2e3439;
    --switch-off: #4b5056;
    /* Light-on-dark tints — a black overlay is invisible on the dark surface. */
    --hover: rgba(255, 255, 255, 0.04);
    --pill-bg: rgba(255, 255, 255, 0.08);
    /* Dark counterparts. The design file is light-only, so these are derived rather than read: the
       tab-bar pill becomes a low-alpha wash of the same cyan family (a literal #f0fdff pill would
       glare on a dark surface), and the selected text flips to the light foreground. Deriving is
       stated here so nobody later "corrects" them back to the light hexes — which is how the tab bar
       ended up the wrong colour in dark mode in the Lantern implementation. */
    --tabbar-bg: rgba(0, 189, 214, 0.14);
    --tabbar-border: rgba(0, 189, 214, 0.24);
    --tabbar-selected-text: #eaf7f9;
    --tabbar-text: #9aa0a6;
    --link: #4fd3e6;                 /* #004d57 is unreadable on dark; same hue, lifted */
    --toggle-on: #34c759;
    --dot-neutral-bg: #6b7075;
    --dot-neutral-border: #3a3f45;
    --dot-success-bg: #34c759;
    --dot-success-border: rgba(52, 199, 89, 0.32);
  }
  /* border-box everywhere: rows use `width: 100%` + padding, and under the default content-box
     that overflows the card by the padding (32px), whose `overflow: hidden` then clips the
     right-edge control (the split-tunnel toggle, routing radios, etc.). */
  :global(*),
  :global(*::before),
  :global(*::after) {
    box-sizing: border-box;
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
    /* Android WebView paints a translucent highlight over the BORDER BOX of whatever was tapped,
       and does not follow border-radius — so tapping the 140x70 rounded VPN switch flashed a
       rectangle around it on every connect and disconnect. Global rather than per-element: every
       tappable thing in the app has the same problem, the switch was just the one big enough to
       be obvious. Desktop is unaffected (no tap highlight there). */
    -webkit-tap-highlight-color: transparent;
  }
  /* Removing the tap highlight must not remove the KEYBOARD focus indicator, so the ring is
     re-established on :focus-visible only — shown for keyboard navigation, not for pointer or
     touch input, which is what produced the flash. */
  :global(:focus-visible) {
    outline: 2px solid var(--brand);
    outline-offset: 2px;
  }
  /* Edge-to-edge safe areas. On Android 15 (and iOS notch devices) the WebView draws behind
     the status bar + camera cutout + nav bar, so the app-bar collided with the system clock and
     notch. Every route's root is `.app` (height:100vh, full-bleed); inset it by the safe area so
     the chrome clears the system UI. `:global(*)` already sets box-sizing:border-box, so this
     padding subtracts from the 100vh rather than overflowing. env() needs viewport-fit=cover
     (app.html); on desktop/non-notched screens every inset resolves to 0 → no visual change. */
  :global(.app) {
    padding-top: env(safe-area-inset-top);
    padding-bottom: env(safe-area-inset-bottom);
    padding-left: env(safe-area-inset-left);
    padding-right: env(safe-area-inset-right);
  }
</style>
