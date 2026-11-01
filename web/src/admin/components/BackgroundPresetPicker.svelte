<script lang="ts">
  // Radio group of the background library (CLAUDE.md section 13), shared by the branding screen
  // and the entity creation form: native radios (keyboard navigation, RGAA 11.1, 11.5, 12.8), the
  // thumbnail is the preview endpoint loaded lazily, its alternative text is the label.
  import { locale } from '../../shared/i18n/i18n.svelte';
  import { presetLabel, previewUrl, type PresetItem } from './backgroundPresets';

  interface Props {
    /** Backgrounds of the library. */
    items: readonly PresetItem[];
    /** Legend of the group. */
    legend: string;
    /** Optional help text shown under the legend and linked to the group. */
    hint?: string | undefined;
    /** Identifier of the chosen preset. */
    choice: string;
  }

  let { items, legend, hint = undefined, choice = $bindable() }: Props = $props();

  const uid = $props.id();
  const groupName = `${uid}-preset`;
  const hintId = `${uid}-hint`;
</script>

<fieldset class="tt-preset-picker" aria-describedby={hint === undefined ? undefined : hintId}>
  <legend class="tt-preset-picker__legend">{legend}</legend>
  {#if hint !== undefined}
    <p id={hintId} class="tt-preset-picker__hint">{hint}</p>
  {/if}
  <div class="tt-preset-picker__list">
    {#each items as item (item.id)}
      {@const label = presetLabel(item, locale.current)}
      <label class="tt-preset-picker__item" class:tt-preset-picker__item--checked={choice === item.id}>
        <input type="radio" name={groupName} value={item.id} bind:group={choice} />
        <img class="tt-preset-picker__thumb" src={previewUrl(item.id)} alt={label} loading="lazy" />
        <span class="tt-preset-picker__label">{label}</span>
      </label>
    {/each}
  </div>
</fieldset>

<style>
  .tt-preset-picker {
    margin: 0 0 var(--tt-space-4);
    padding: 0;
    border: 0;
    min-width: 0;
  }

  .tt-preset-picker__legend {
    padding: 0;
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-preset-picker__hint {
    margin: 0 0 var(--tt-space-2);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-preset-picker__list {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
  }

  .tt-preset-picker__item {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-1);
    width: 9rem;
    padding: var(--tt-space-2);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    cursor: pointer;
  }

  .tt-preset-picker__item--checked {
    border-color: var(--tt-primary);
    box-shadow: 0 0 0 2px var(--tt-primary);
  }

  /* The native radio stays in the page; the whole card shows the keyboard focus. */
  .tt-preset-picker__item:focus-within {
    outline: 2px solid var(--tt-focus);
    outline-offset: 2px;
  }

  .tt-preset-picker__thumb {
    display: block;
    width: 100%;
    height: 5rem;
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
    object-fit: cover;
  }

  .tt-preset-picker__label {
    overflow-wrap: anywhere;
  }
</style>
