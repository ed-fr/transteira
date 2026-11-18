<script lang="ts">
  // Information pill (CLAUDE.md section 13.2, download page: expiry, confidentiality level,
  // downloads left, total size): neutral text on the muted surface with a decorative border and an
  // optional decorative icon. Never a status colour: use Badge for statuses.
  //
  // Props:
  //   icon      optional decorative icon of the set (Icon.svelte), e.g. 'clock', 'shield'
  //   tag       element: 'span' (default) or 'li' (pills in a <ul>, e.g. aria-label "About this transfer")
  //   children  the text of the pill (may hold a <time> element)
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  interface Props {
    /** Decorative icon before the text. */
    icon?: IconName | undefined;
    /** Element of the pill. */
    tag?: 'span' | 'li';
    /** Text of the pill. */
    children: Snippet;
    class?: string;
  }

  let { icon, tag = 'span', children, class: className = '' }: Props = $props();
</script>

<svelte:element this={tag} class="tt-pill {className}">
  {#if icon}<Icon name={icon} size="sm" />{/if}
  <span class="tt-pill__text">{@render children()}</span>
</svelte:element>

<style>
  .tt-pill {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-2);
    min-height: 2rem;
    padding: var(--tt-space-1) var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-separator);
    border-radius: var(--tt-radius-full);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
    font-size: var(--tt-font-size-sm);
    line-height: var(--tt-line-height-tight);
  }

  .tt-pill__text {
    overflow-wrap: anywhere;
  }

  @media (forced-colors: active) {
    .tt-pill {
      border-color: CanvasText;
    }
  }
</style>
