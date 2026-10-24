<script lang="ts">
  // Filter form of a list (RGAA 11.10): a <form role="search"> holding the filter fields, with
  // "Apply" (submit, Enter in a field) and "Reset" buttons. The result text (e.g. "12 transfers
  // loaded.") is shown, and announced politely as the outcome of an apply or a reset, even when
  // it did not change; other changes of the text (initial load, "Load more", whose added rows the
  // DataTable announces) are not announced (filterBar.ts). onapply may return false when it
  // applied nothing (e.g. refused by validation, whose errors are shown instead).
  //
  //   <FilterBar label={filtersLabel} onapply={load} onreset={clear} busy={loading}
  //              resultText={loadedText}>
  //     <SelectField label={...} bind:value={status} options={...} />
  //   </FilterBar>
  import { tick, type Snippet } from 'svelte';
  import Button from '../../shared/components/Button.svelte';
  import { announce } from '../../shared/components/announce.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { createFilterAnnouncer } from './filterBar';

  interface Props {
    /** Accessible name of the search region (default "Filters"). */
    label?: string;
    /** Applies the filters (submit of the form); false when nothing was applied. */
    onapply: () => Promise<boolean | void> | boolean | void;
    /** Resets the filters to their defaults; false when nothing was reset. */
    onreset: () => Promise<boolean | void> | boolean | void;
    /** While true, the apply button shows its loading state and further submits are ignored. */
    busy?: boolean;
    /** Result text shown under the filters, announced politely after an apply or a reset. */
    resultText?: string | undefined;
    /** Filter fields. */
    children: Snippet;
    class?: string;
  }

  let {
    label,
    onapply,
    onreset,
    busy = false,
    resultText,
    children,
    class: className = '',
  }: Props = $props();

  const announcer = createFilterAnnouncer();

  $effect(() => {
    const message = announcer.result(resultText);
    if (message !== undefined) {
      announce(message);
    }
  });

  async function run(action: () => Promise<boolean | void> | boolean | void): Promise<void> {
    announcer.trigger();
    let applied = false;
    try {
      applied = (await action()) !== false;
    } finally {
      await tick();
      const message = announcer.settle(resultText, applied);
      if (message !== undefined) {
        announce(message);
      }
    }
  }

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    if (!busy) {
      void run(onapply);
    }
  }

  function reset(event: Event): void {
    event.preventDefault();
    if (!busy) {
      void run(onreset);
    }
  }
</script>

<form
  class="tt-filter {className}"
  role="search"
  aria-label={label ?? t('adminComponents.filter.label')}
  novalidate
  onsubmit={submit}
  onreset={reset}
>
  <div class="tt-filter__fields">
    {@render children()}
  </div>
  <div class="tt-filter__actions">
    <Button type="submit" loading={busy}>{t('adminComponents.filter.apply')}</Button>
    <Button type="reset" variant="secondary" disabled={busy}>{t('adminComponents.filter.reset')}</Button>
  </div>
  {#if resultText}
    <p class="tt-filter__result">{resultText}</p>
  {/if}
</form>

<style>
  .tt-filter {
    margin-bottom: var(--tt-space-4);
    padding: var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
  }

  .tt-filter__fields {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(14rem, 100%), 1fr));
    gap: 0 var(--tt-space-4);
    align-items: end;
  }

  .tt-filter__actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
  }

  .tt-filter__result {
    margin: var(--tt-space-3) 0 0;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
