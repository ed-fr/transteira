<script lang="ts">
  // Error summary of an authentication form (RGAA 11.10): an alert listing the fields in error,
  // each entry a button that moves the focus to its field. Rendered only when there are errors.
  import { Alert } from '../../../shared/components';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import type { SummaryEntry } from '../../auth/views';

  interface Props {
    /** Fields in error, in the order of the form. */
    entries: readonly SummaryEntry[];
    /** The summary element (focusable by script). */
    element?: HTMLDivElement | undefined;
  }

  let { entries, element = $bindable() }: Props = $props();

  function focusField(id: string): void {
    document.getElementById(id)?.focus();
  }
</script>

{#if entries.length > 0}
  <Alert severity="error" title={t('admin.common.errorSummary.title')} bind:element>
    <p>{t('admin.common.errorSummary.count', { count: entries.length })}</p>
    <ul>
      {#each entries as entry (entry.id)}
        <li>
          <button type="button" class="tt-summary__link" onclick={() => focusField(entry.id)}>
            {t('adminComponents.form.errorLink', { label: entry.label, message: entry.message })}
          </button>
        </li>
      {/each}
    </ul>
  </Alert>
{/if}

<style>
  .tt-summary__link {
    padding: 0;
    border: 0;
    background: none;
    color: var(--tt-link);
    text-align: left;
    text-decoration: underline;
    cursor: pointer;
  }
</style>
