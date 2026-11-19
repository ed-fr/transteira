<script lang="ts">
  // Decorative colour swatch of a tenant (CLAUDE.md section 13.2: entity rows of the home and of the
  // lists; plan of step 3c, deviation 11): a rounded square in the primary colour of the tenant,
  // next to its name. aria-hidden: the name carries the information. The colour
  // (Tenant.primaryColor) is validated again by swatchColor (exactly #RRGGBB, threat model T-417)
  // and only ever rendered as the fill attribute of an SVG rect, never in a style attribute
  // (strict CSP). Without a valid colour, the swatch is neutral (--tt-chip-bg). The tenant colour
  // is never used for anything else in the administration.
  //
  //   <TenantSwatch color={tenant.primaryColor} />
  //
  // Props:
  //   color  primary colour of the tenant (any value: validated here)
  //   size   md (36 px, default) | sm (24 px)
  import { swatchColor } from './swatch';

  interface Props {
    /** Primary colour of the tenant; anything but #RRGGBB gives the neutral swatch. */
    color?: unknown;
    /** 36 px (md, default) or 24 px (sm). */
    size?: 'sm' | 'md';
    class?: string;
  }

  let { color, size = 'md', class: className = '' }: Props = $props();

  const fill = $derived(swatchColor(color));
  const px = $derived(size === 'sm' ? 24 : 36);
</script>

<svg
  class="tt-swatch {className}"
  aria-hidden="true"
  focusable="false"
  width={px}
  height={px}
  viewBox="0 0 36 36"
>
  {#if fill !== null}
    <rect x="0.5" y="0.5" width="35" height="35" rx="10" {fill} class="tt-swatch__edge" />
  {:else}
    <rect x="0.5" y="0.5" width="35" height="35" rx="10" class="tt-swatch__neutral" />
  {/if}
</svg>

<style>
  .tt-swatch {
    display: block;
    flex: none;
  }

  /* A decorative edge, so that a colour close to the surface still shows its shape. */
  .tt-swatch__edge {
    stroke: var(--tt-separator);
    stroke-width: 1;
  }

  .tt-swatch__neutral {
    fill: var(--tt-chip-bg);
    stroke: var(--tt-separator);
    stroke-width: 1;
  }
</style>
