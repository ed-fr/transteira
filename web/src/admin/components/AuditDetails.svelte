<script lang="ts">
  // Free details of an audit event, in a collapsible block of key/value pairs (detailEntries).
  // Values are always rendered as text, never as HTML.
  import { t } from '../../shared/i18n/i18n.svelte';
  import { detailEntries } from '../screens/ops/auditLabels';

  interface Props {
    /** Details of the event (absent or empty: "no details" text). */
    details: Record<string, unknown> | null | undefined;
  }

  const { details }: Props = $props();

  const lines = $derived(detailEntries(details));
</script>

{#if lines.length > 0}
  <details class="tt-audit__details">
    <summary>{t('opsAudit.list.showDetails')}</summary>
    <dl>
      {#each lines as line (line.key)}
        <dt>{line.key}</dt>
        <dd class="tt-break">{line.value}</dd>
      {/each}
    </dl>
  </details>
{:else}
  {t('opsAudit.list.noDetails')}
{/if}

<style>
  .tt-audit__details summary {
    cursor: pointer;
  }

  .tt-audit__details dl {
    margin: var(--tt-space-2) 0 0;
  }

  .tt-audit__details dt {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-audit__details dd {
    margin: 0 0 var(--tt-space-1);
  }
</style>
