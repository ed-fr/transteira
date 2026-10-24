<script lang="ts">
  // Status badge (RGAA 3.1): the status is always written out and doubled by an icon drawn by a
  // CSS class (hidden from assistive technologies), never conveyed by colour alone.
  //   <StatusBadge variant="ok" />                 → "OK" with a check mark
  //   <StatusBadge variant="AA" label="AA 5.2:1" /> → contrast level of a colour
  import { t } from '../../shared/i18n/i18n.svelte';
  import { statusIcon, statusKey, type StatusVariant } from './fields';

  interface Props {
    /** Status shown. */
    variant: StatusVariant;
    /** Visible text; defaults to the name of the status (adminComponents.status.*). */
    label?: string;
    /** Extra text read by screen readers only, after the label (e.g. "contrast ratio 5.2:1"). */
    srText?: string;
    class?: string;
  }

  let { variant, label, srText, class: className = '' }: Props = $props();

  const text = $derived(label ?? t(`adminComponents.status.${statusKey(variant)}`));
  const icon = $derived(statusIcon(variant));
</script>

<span class="tt-badge tt-badge--{statusKey(variant)} {className}">
  <span class="tt-badge__icon tt-badge__icon--{icon}" aria-hidden="true"></span>
  <span class="tt-badge__text">{text}</span>
  {#if srText}<span class="visually-hidden">{srText}</span>{/if}
</span>

<style>
  .tt-badge {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-1);
    padding: 0 var(--tt-space-2);
    border: var(--tt-border-width) solid currentColor;
    border-radius: var(--tt-radius-sm);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-bold);
    line-height: 1.6;
    white-space: nowrap;
  }

  .tt-badge__text {
    color: var(--tt-text);
  }

  .tt-badge--ok,
  .tt-badge--aa,
  .tt-badge--aaa {
    color: var(--tt-success);
    background: var(--tt-success-bg);
  }

  .tt-badge--warning {
    color: var(--tt-warning);
    background: var(--tt-warning-bg);
  }

  .tt-badge--missing,
  .tt-badge--error,
  .tt-badge--fail {
    color: var(--tt-danger);
    background: var(--tt-danger-bg);
  }

  .tt-badge--info {
    color: var(--tt-info);
    background: var(--tt-info-bg);
  }

  .tt-badge__icon {
    flex: none;
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-badge__icon--check::before {
    content: '\2713';
  }

  .tt-badge__icon--alert::before {
    content: '!';
  }

  .tt-badge__icon--cross::before {
    content: '\2715';
  }

  .tt-badge__icon--info::before {
    content: 'i';
  }
</style>
