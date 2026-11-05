<script lang="ts">
  // Table of security events with the standard columns (date and time, type, reason, IP address,
  // occurrences) and an optional leading column (e.g. the tenant in the instance security log).
  // The type is shown translated, with its raw token under it when known (an unknown type is
  // already shown as its token). Paging is handed to DataTable ("Load more" with the next cursor).
  import type { Snippet } from 'svelte';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import {
    ipText,
    isKnownType,
    lastSeen,
    occurrenceCount,
    reasonText,
    typeLabel,
    type SecurityEvent,
  } from '../screens/ops/securityLog';
  import DataTable from './DataTable.svelte';

  /** Extra column shown before the standard ones. */
  interface LeadingColumn {
    /** Stable id of the column (other than date, type, reason, ip and occurrences). */
    id: string;
    /** Header text. */
    header: string;
    /** Content of a cell. */
    cell: Snippet<[SecurityEvent]>;
  }

  interface Props {
    /** Caption of the table (its accessible name). */
    caption: string;
    /** Events, most recent first. */
    rows: readonly SecurityEvent[];
    /** Optional column shown before the date. */
    leadingColumn?: LeadingColumn;
    /** Text shown instead of the table when there are no events. */
    emptyText?: string;
    /** First page loading. */
    loading?: boolean;
    /** Cursor of the next page. */
    nextCursor?: string | null | undefined;
    /** Loads the next page (see DataTable). */
    onloadmore?: () => Promise<void>;
  }

  const {
    caption,
    rows,
    leadingColumn,
    emptyText,
    loading = false,
    nextCursor,
    onloadmore,
  }: Props = $props();

  const stamp = { dateStyle: 'short', timeStyle: 'medium' } as const;

  const columns = $derived([
    ...(leadingColumn ? [leadingColumn] : []),
    { id: 'date', header: t('opsSecurity.list.columns.date'), cell: dateCell, rowHeader: true },
    { id: 'type', header: t('opsSecurity.list.columns.type'), cell: typeCell },
    { id: 'reason', header: t('opsSecurity.list.columns.reason'), cell: reasonCell },
    { id: 'ip', header: t('opsSecurity.list.columns.ip'), cell: ipCell },
    { id: 'occurrences', header: t('opsSecurity.list.columns.occurrences'), cell: occurrencesCell },
  ]);
</script>

{#snippet dateCell(row: SecurityEvent)}
  <time datetime={row.occurredAt}>{formatDate(row.occurredAt, stamp)}</time>
{/snippet}

{#snippet typeCell(row: SecurityEvent)}
  {typeLabel(row.type, t)}
  {#if isKnownType(row.type)}<code class="tt-security__code">{row.type}</code>{/if}
{/snippet}

{#snippet reasonCell(row: SecurityEvent)}
  {#if row.reason}<code class="tt-security__reason">{row.reason}</code>{:else}{reasonText(row, t)}{/if}
{/snippet}

{#snippet ipCell(row: SecurityEvent)}
  <span class="tt-break">{ipText(row, t)}</span>
{/snippet}

{#snippet occurrencesCell(row: SecurityEvent)}
  {@const last = lastSeen(row)}
  {occurrenceCount(row)}
  {#if last !== undefined}
    <span class="tt-security__last">
      {t('opsSecurity.list.lastSeen')}
      <time datetime={last}>{formatDate(last, stamp)}</time>
    </span>
  {/if}
{/snippet}

<DataTable
  {caption}
  captionHidden
  {rows}
  key={(row) => row.id}
  {loading}
  {emptyText}
  {nextCursor}
  {onloadmore}
  {columns}
/>

<style>
  .tt-security__code {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    font-family: var(--tt-font-mono);
    overflow-wrap: anywhere;
  }

  .tt-security__reason {
    font-family: var(--tt-font-mono);
    overflow-wrap: anywhere;
  }

  .tt-security__last {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
