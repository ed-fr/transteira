<script lang="ts">
  // Table of audit events with the standard columns (date and time, actor, action, object, IP,
  // details) and an optional leading column (e.g. the tenant in the global audit log). Paging is
  // handed to DataTable ("Load more" with the next cursor).
  //
  //   {#snippet tenantCell(row: AuditEvent)}{nameOf(row.tenantId)}{/snippet}
  //   <AuditEventsTable caption={text} rows={events} {nav} nextCursor={cursor} onloadmore={more}
  //                     leadingColumn={{ id: 'tenant', header: text, cell: tenantCell }} />
  import type { Snippet } from 'svelte';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import type { AuditEvent } from '../screens/ops/auditLabels';
  import type { Navigation } from '../screens/types';
  import AuditActionCell from './AuditActionCell.svelte';
  import AuditActorCell from './AuditActorCell.svelte';
  import AuditDetails from './AuditDetails.svelte';
  import AuditObjectCell from './AuditObjectCell.svelte';
  import DataTable from './DataTable.svelte';

  /** Extra column shown before the standard ones. */
  interface LeadingColumn {
    /** Stable id of the column (other than date, actor, action, object, ip and details). */
    id: string;
    /** Header text. */
    header: string;
    /** Content of a cell. */
    cell: Snippet<[AuditEvent]>;
  }

  interface Props {
    /** Caption of the table (its accessible name). */
    caption: string;
    /** Hides the caption visually (default true: the screen title already names the list). */
    captionHidden?: boolean;
    /** Events, most recent first. */
    rows: readonly AuditEvent[];
    /** Router helpers of the screen (links of transfer objects). */
    nav: Navigation;
    /**
     * Tenant whose pages the object links of an event point to (default: the event's own
     * tenantId). No link when it is absent.
     */
    linkTenant?: (event: AuditEvent) => string | null | undefined;
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
    captionHidden = true,
    rows,
    nav,
    linkTenant = (event: AuditEvent) => event.tenantId,
    leadingColumn,
    emptyText,
    loading = false,
    nextCursor,
    onloadmore,
  }: Props = $props();

  const columns = $derived([
    ...(leadingColumn ? [leadingColumn] : []),
    { id: 'date', header: t('opsAudit.list.columns.date'), cell: dateCell, rowHeader: true },
    { id: 'actor', header: t('opsAudit.list.columns.actor'), cell: actorCell },
    { id: 'action', header: t('opsAudit.list.columns.action'), cell: actionCell },
    { id: 'object', header: t('opsAudit.list.columns.object'), cell: objectCell },
    { id: 'ip', header: t('opsAudit.list.columns.ip'), cell: ipCell },
    { id: 'details', header: t('opsAudit.list.columns.details'), cell: detailsCell },
  ]);
</script>

{#snippet dateCell(row: AuditEvent)}
  <time datetime={row.occurredAt}
    >{formatDate(row.occurredAt, { dateStyle: 'short', timeStyle: 'medium' })}</time
  >
{/snippet}

{#snippet actorCell(row: AuditEvent)}
  <AuditActorCell actor={row.actor} />
{/snippet}

{#snippet actionCell(row: AuditEvent)}
  <AuditActionCell action={row.action} />
{/snippet}

{#snippet objectCell(row: AuditEvent)}
  <AuditObjectCell object={row.object} tenantId={linkTenant(row)} {nav} />
{/snippet}

{#snippet ipCell(row: AuditEvent)}
  {#if row.ip}<span class="tt-break">{row.ip}</span>{:else}{t('opsAudit.list.noIp')}{/if}
{/snippet}

{#snippet detailsCell(row: AuditEvent)}
  <AuditDetails details={row.details} />
{/snippet}

<DataTable
  {caption}
  {captionHidden}
  {rows}
  key={(row) => row.id}
  {loading}
  {emptyText}
  {nextCursor}
  {onloadmore}
  {columns}
/>
