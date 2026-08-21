<script lang="ts">
  // A Material Symbol, rendered from the path data in `icons.ts`.
  //
  // Owns the `0 -960 960 960` viewBox so no caller has to remember it, and renders the glyph as a
  // FILL (`fill="currentColor"`, no stroke). Both details matter: Material Symbols paths are
  // outline-shaped fills, so adding a stroke thickens every edge — which is precisely the "icons
  // appear to have an extra stroke" complaint from getlantern/engineering#3844.
  import { icons, MATERIAL_VIEWBOX, type IconName } from "$lib/icons";

  let {
    name,
    size = 20,
    label,
  }: {
    name: IconName;
    size?: number;
    /** Accessible name. Omit for decoration, which is the common case beside a text label. */
    label?: string;
  } = $props();
</script>

<svg
  viewBox={MATERIAL_VIEWBOX}
  width={size}
  height={size}
  fill="currentColor"
  role={label ? "img" : "presentation"}
  aria-label={label}
  aria-hidden={label ? undefined : "true"}
>
  <path d={icons[name]} />
</svg>

<style>
  svg {
    display: block;
    flex-shrink: 0;
  }
</style>
