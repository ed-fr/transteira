<script lang="ts">
  // Status badge (CLAUDE.md section 13.2): a short text in a rounded tint, optionally after an icon.
  // The text always carries the meaning ("Scanned", "Not scanned: too large"): the colour only
  // repeats it, so the badge never conveys a status by colour alone. Status variants use the status
  // tokens (never a tenant colour); "neutral" uses the chip tokens. Text AA on its tint in both
  // themes (tokens.test.ts). Forced colours: the tint is dropped and a border keeps the shape.
  //
  // Props:
  //   variant   'success' | 'warning' | 'danger' | 'info' | 'neutral' (default 'neutral')
  //   icon      optional decorative icon of the set (Icon.svelte), e.g. 'check', 'alert'
  //   children  the text of the badge (required)
  import type { Snippet } from 'svelte';
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  interface Props {
    /** Colour family of the badge. */
    variant?: 'success' | 'warning' | 'danger' | 'info' | 'neutral';
    /** Decorative icon before the text. */
    icon?: IconName | undefined;
    /** Text of the badge. */
    children: Snippet;
    class?: string;
  }

  let { variant = 'neutral', icon, children, class: className = '' }: Props = $props();
</script>

<span class="tt-badge tt-badge--{variant} {className}">
  {#if icon}<Icon name={icon} size="xs" />{/if}
  <span>{@render children()}</span>
</span>

<style>
  .tt-badge {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-1);
    padding: 0.125rem var(--tt-space-2);
    border: var(--tt-border-width) solid transparent;
    border-radius: var(--tt-radius-full);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-bold);
    line-height: var(--tt-line-height-tight);
    white-space: nowrap;
  }

  .tt-badge--success {
    background: var(--tt-success-bg);
    color: var(--tt-success);
  }

  .tt-badge--warning {
    background: var(--tt-warning-bg);
    color: var(--tt-warning);
  }

  .tt-badge--danger {
    background: var(--tt-danger-bg);
    color: var(--tt-danger);
  }

  .tt-badge--info {
    background: var(--tt-info-bg);
    color: var(--tt-info);
  }

  .tt-badge--neutral {
    background: var(--tt-chip-bg);
    color: var(--tt-chip-text);
  }

  @media (forced-colors: active) {
    .tt-badge {
      border-color: CanvasText;
    }
  }
</style>
