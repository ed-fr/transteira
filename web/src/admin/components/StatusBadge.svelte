<script lang="ts">
  // Status pill (CLAUDE.md section 13.2, RGAA 3.1): the status is always written out and doubled
  // by a decorative icon, never conveyed by colour alone. A rounded tint of the status colour
  // (success for ok, AA and AAA; warning; danger for missing, error and fail; info) with the text in
  // the status colour (AA on its tint in both themes, tokens.test.ts), or the neutral chip colours
  // for "neutral" (e.g. maintenance "Inactive"). Status colours are never tenant colours.
  // Forced colours: the tint is dropped and a border keeps the shape.
  //   <StatusBadge variant="ok" />                       → "OK" with a check mark
  //   <StatusBadge variant="AA" label="AA 5.2:1" />       → contrast level of a colour
  //   <StatusBadge variant="neutral" label={inactive} />  → a state without status colour
  //
  // Props:
  //   variant  ok | warning | missing | error | AA | AAA | fail | info | neutral
  //   label    visible text; defaults to the name of the status (adminComponents.status.*)
  //   srText   extra text read by screen readers only, after the label
  import Icon from '../../shared/components/Icon.svelte';
  import type { IconName } from '../../shared/components/icons';
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

  const ICONS: Record<'check' | 'alert' | 'cross' | 'info', IconName> = {
    check: 'check',
    alert: 'alert',
    cross: 'x',
    info: 'info',
  };

  const text = $derived(label ?? t(`adminComponents.status.${statusKey(variant)}`));
  const icon = $derived(statusIcon(variant));
</script>

<span class="tt-badge tt-badge--{statusKey(variant)} {className}">
  {#if icon === 'dot'}
    <span class="tt-badge__dot" aria-hidden="true"></span>
  {:else}
    <Icon name={ICONS[icon]} size="xs" />
  {/if}
  <span class="tt-badge__text">{text}</span>
  {#if srText}<span class="visually-hidden">{srText}</span>{/if}
</span>

<style>
  .tt-badge {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-1);
    padding: 0.1875rem 0.625rem;
    border: var(--tt-border-width) solid transparent;
    border-radius: var(--tt-radius-full);
    font-size: 0.8125rem;
    font-weight: var(--tt-font-weight-bold);
    line-height: var(--tt-line-height-tight);
    white-space: nowrap;
    vertical-align: middle;
  }

  .tt-badge--ok,
  .tt-badge--aa,
  .tt-badge--aaa {
    background: var(--tt-success-bg);
    color: var(--tt-success);
  }

  .tt-badge--warning {
    background: var(--tt-warning-bg);
    color: var(--tt-warning);
  }

  .tt-badge--missing,
  .tt-badge--error,
  .tt-badge--fail {
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

  .tt-badge__dot {
    flex: none;
    width: 0.375rem;
    height: 0.375rem;
    border-radius: 50%;
    background: currentColor;
  }

  @media (forced-colors: active) {
    .tt-badge {
      border-color: CanvasText;
    }

    .tt-badge__dot {
      background: CanvasText;
    }
  }
</style>
