<script lang="ts">
  // Message box by severity. Errors and warnings are role="alert" (assertive), information and
  // success role="status" (polite); live={false} gives a static notice. The severity is also
  // spelled out for screen readers, never conveyed by colour alone (RGAA 3.1).
  import type { Snippet } from 'svelte';
  import { t } from '../i18n/i18n.svelte';

  interface Props {
    /** Severity. */
    severity?: 'info' | 'success' | 'warning' | 'error';
    /** Optional title, in bold. */
    title?: string;
    /** Announce on insertion (role alert/status); false for a static notice. */
    live?: boolean;
    /** Shows a dismiss button calling ondismiss. */
    ondismiss?: () => void;
    /** The alert element; focusable by script (tabindex -1), e.g. for a form error summary. */
    element?: HTMLDivElement | undefined;
    children: Snippet;
    class?: string;
  }

  let {
    severity = 'info',
    title,
    live = true,
    ondismiss,
    element = $bindable(),
    children,
    class: className = '',
  }: Props = $props();

  const role = $derived(
    live ? (severity === 'error' || severity === 'warning' ? 'alert' : 'status') : undefined,
  );
</script>

<div bind:this={element} class="tt-alert tt-alert--{severity} {className}" {role} tabindex="-1">
  <div class="tt-alert__body">
    {#if title}
      <p class="tt-alert__title">
        <span class="visually-hidden">{t(`components.alert.${severity}`)}</span>
        {title}
      </p>
      {@render children()}
    {:else}
      <span class="visually-hidden">{t(`components.alert.${severity}`)}</span>
      {@render children()}
    {/if}
  </div>
  {#if ondismiss}
    <button
      type="button"
      class="tt-alert__dismiss"
      aria-label={t('components.alert.dismiss')}
      onclick={ondismiss}
    >
      <span aria-hidden="true">×</span>
    </button>
  {/if}
</div>

<style>
  .tt-alert {
    display: flex;
    align-items: flex-start;
    gap: var(--tt-space-3);
    margin-bottom: var(--tt-space-4);
    padding: var(--tt-space-3) var(--tt-space-4);
    border: var(--tt-border-width) solid currentColor;
    border-left-width: 0.375rem;
    border-radius: var(--tt-radius);
  }

  .tt-alert--info {
    color: var(--tt-info);
    background: var(--tt-info-bg);
  }

  .tt-alert--success {
    color: var(--tt-success);
    background: var(--tt-success-bg);
  }

  .tt-alert--warning {
    color: var(--tt-warning);
    background: var(--tt-warning-bg);
  }

  .tt-alert--error {
    color: var(--tt-danger);
    background: var(--tt-danger-bg);
  }

  .tt-alert__body {
    flex: 1;
    min-width: 0;
    color: var(--tt-text);
  }

  .tt-alert__body :global(> :last-child) {
    margin-bottom: 0;
  }

  .tt-alert__title {
    margin: 0 0 var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-alert__dismiss {
    flex: none;
    width: 2rem;
    height: 2rem;
    padding: 0;
    border: 0;
    border-radius: var(--tt-radius-sm);
    background: none;
    color: var(--tt-text);
    font-size: var(--tt-font-size-lg);
    line-height: 1;
    cursor: pointer;
  }
</style>
