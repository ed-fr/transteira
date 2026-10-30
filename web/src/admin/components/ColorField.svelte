<script lang="ts">
  // Colour field of the branding form (RGAA 3.2, 11.1): a fieldset grouping two labelled inputs
  // kept in sync, a native colour picker and a #RRGGBB text field, then the live contrast of the
  // colour (contrastView rows chosen by the parent), each written out with its ratio and a
  // StatusBadge, never conveyed by colour alone. The picker cannot show an invalid value: while
  // the text is not a colour, it keeps the last valid one.
  //
  //   <ColorField id="primary" label={text} hint={text} bind:value={primary}
  //               rows={rowsForPairs(rows, ['primary-on-light', 'primary-on-dark', 'text-on-primary'])} />
  import TextField from '../../shared/components/TextField.svelte';
  import { formatNumber, t } from '../../shared/i18n/i18n.svelte';
  import type { ContrastRow } from '../forms/contrastView';
  import { colorError, hexFromPicker, isHexColor, pickerValue } from './branding';
  import StatusBadge from './StatusBadge.svelte';

  interface Props {
    /** Base id: the text field is <id>-hex (the id to focus from an error summary), the picker <id>-picker. */
    id: string;
    /** Name of the colour (legend). */
    label: string;
    /** Help text under the legend. */
    hint?: string;
    /** Bound colour text (#RRGGBB once valid). */
    value?: string;
    /** Contrast rows to show for this colour. */
    rows?: readonly ContrastRow[];
    /** Error from the form (summary); otherwise an invalid text is reported once the field is left. */
    error?: string | undefined;
  }

  let { id, label, hint, value = $bindable(''), rows = [], error }: Props = $props();

  const pickerId = $derived(`${id}-picker`);
  const hexId = $derived(`${id}-hex`);
  const hintId = $derived(`${id}-hint`);
  let lastValid = $state('');
  let touched = $state(false);

  $effect.pre(() => {
    if (isHexColor(value.trim())) {
      lastValid = value.trim();
    }
  });

  const shownError = $derived(
    error ??
      (touched && colorError(value) !== undefined ? t('adminTenants.branding.colors.invalid') : undefined),
  );

  function fromPicker(event: Event & { currentTarget: HTMLInputElement }): void {
    const hex = hexFromPicker(event.currentTarget.value);
    if (hex !== null) {
      value = hex;
    }
  }

  function levelText(row: ContrastRow): string {
    return t(`adminTenants.branding.contrast.level.${row.level}`);
  }

  function ratioText(row: ContrastRow): string {
    return t('adminTenants.branding.contrast.ratio', {
      ratio: formatNumber(row.ratio, { minimumFractionDigits: 1, maximumFractionDigits: 2 }),
    });
  }
</script>

<fieldset class="tt-color" aria-describedby={hint ? hintId : undefined}>
  <legend class="tt-color__legend">{label}</legend>
  {#if hint}<p class="tt-color__hint" id={hintId}>{hint}</p>{/if}
  <div class="tt-color__row">
    <div class="tt-color__picker">
      <label class="tt-color__label" for={pickerId}>
        {t('adminTenants.branding.colors.picker', { label })}
      </label>
      <input
        type="color"
        id={pickerId}
        class="tt-color__swatch"
        value={pickerValue(value, lastValid)}
        oninput={fromPicker}
        onchange={fromPicker}
      />
    </div>
    <TextField
      id={hexId}
      class="tt-color__hex"
      label={t('adminTenants.branding.colors.hex', { label })}
      hint={t('adminTenants.branding.colors.hexHint')}
      bind:value
      error={shownError}
      autocomplete="off"
      spellcheck={false}
      maxlength={7}
      onblur={() => {
        touched = true;
      }}
    />
  </div>
  {#if rows.length > 0}
    <ul class="tt-color__contrast">
      {#each rows as row (row.pair)}
        <li class="tt-color__result">
          <span>{t(`adminTenants.branding.contrast.pair.${row.pair}`)}</span>
          <span class="tt-color__ratio">{ratioText(row)}</span>
          <StatusBadge variant={row.level} label={levelText(row)} />
        </li>
      {/each}
    </ul>
  {/if}
</fieldset>

<style>
  .tt-color {
    margin: 0 0 var(--tt-space-6);
    padding: 0;
    border: 0;
    min-width: 0;
  }

  .tt-color__legend {
    padding: 0;
    margin-bottom: var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-color__hint {
    margin: 0 0 var(--tt-space-2);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-color__row {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-4);
    align-items: flex-start;
  }

  .tt-color__picker {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-1);
    max-width: 12rem;
  }

  .tt-color__label {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-color__swatch {
    width: 4rem;
    min-height: var(--tt-control-height);
    padding: var(--tt-space-1);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
    cursor: pointer;
  }

  .tt-color__row :global(.tt-color__hex) {
    flex: 1 1 14rem;
  }

  .tt-color__contrast {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .tt-color__result {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2);
    align-items: center;
    margin-bottom: var(--tt-space-1);
  }

  .tt-color__ratio {
    font-weight: var(--tt-font-weight-bold);
  }
</style>
