<script lang="ts" generics="T">
  // Semantic data table (RGAA 5.4, 5.6, 5.7): <caption>, column headers with scope="col",
  // optional row headers (scope="row"). The rows are shown in the order of the API (no client
  // sorting). With a cursor, a "Load more" button fetches the next page; the number of rows
  // added is announced, and the focus stays on the button (or moves to the table when every
  // row is shown, since the button disappears).
  //
  //   {#snippet nameCell(row: Tenant)}<a href={...}>{row.name}</a>{/snippet}
  //   <DataTable caption={text} rows={tenants} key={(r) => r.id}
  //              columns={[{ id: 'name', header: text, cell: nameCell, rowHeader: true }]}
  //              nextCursor={cursor} onloadmore={loadMore} />
  import type { Snippet } from 'svelte';
  import Button from '../../shared/components/Button.svelte';
  import LiveRegion from '../../shared/components/LiveRegion.svelte';
  import Spinner from '../../shared/components/Spinner.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';

  /** One column of the table. */
  interface Column {
    /** Stable id of the column. */
    id: string;
    /** Header text. */
    header: string;
    /** Content of a cell. */
    cell: Snippet<[T]>;
    /** The header is read by screen readers but not shown (e.g. an actions column). */
    headerHidden?: boolean;
    /** Cells of this column are row headers (th scope="row"), e.g. the name column. */
    rowHeader?: boolean;
    /** Alignment of the column (numbers: end). */
    align?: 'start' | 'end';
  }

  interface Props {
    /** Caption of the table (its accessible name). */
    caption: string;
    /** Hides the caption visually (it stays read by screen readers). */
    captionHidden?: boolean;
    /** Columns. */
    columns: readonly Column[];
    /** Rows, in display order. */
    rows: readonly T[];
    /** Unique key of a row. */
    key: (row: T) => string;
    /** Text shown instead of the table when there are no rows (default "Nothing to show."). */
    emptyText?: string;
    /** First page loading: a spinner replaces the table. */
    loading?: boolean;
    /** Cursor of the next page; the "Load more" button is shown when it is set. */
    nextCursor?: string | null | undefined;
    /**
     * Loads the next page (appends to rows); the button shows its loading state meanwhile. It
     * shows its own errors: a rejection is ignored here.
     */
    onloadmore?: () => Promise<void>;
    class?: string;
  }

  let {
    caption,
    captionHidden = false,
    columns,
    rows,
    key,
    emptyText,
    loading = false,
    nextCursor,
    onloadmore,
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  let loadingMore = $state(false);
  let message = $state('');
  let table: HTMLTableElement | undefined = $state();

  const hasMore = $derived(
    nextCursor !== undefined && nextCursor !== null && nextCursor !== '' && !!onloadmore,
  );

  async function loadMore(): Promise<void> {
    if (onloadmore === undefined || loadingMore) {
      return;
    }
    const before = rows.length;
    loadingMore = true;
    message = '';
    try {
      await onloadmore();
    } catch {
      // The screen shows its own error (onloadmore should not throw); nothing was added.
      return;
    } finally {
      loadingMore = false;
    }
    const added = Math.max(0, rows.length - before);
    message = t('adminComponents.dataTable.loaded', { count: added });
    if (!hasMore) {
      message = `${message} ${t('adminComponents.dataTable.noMore')}`;
      table?.focus();
    }
  }
</script>

<div class="tt-table {className}">
  {#if loading}
    <p><Spinner showLabel /></p>
  {:else if rows.length === 0}
    <p class="tt-table__empty" id="{uid}-empty">{emptyText ?? t('admin.common.noResults')}</p>
  {:else}
    <div class="tt-table__scroll">
      <table bind:this={table} tabindex="-1">
        <caption class:visually-hidden={captionHidden}>{caption}</caption>
        <thead>
          <tr>
            {#each columns as column (column.id)}
              <th scope="col" class:tt-table__end={column.align === 'end'}>
                <span class:visually-hidden={column.headerHidden}>{column.header}</span>
              </th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each rows as row (key(row))}
            <tr>
              {#each columns as column (column.id)}
                {#if column.rowHeader}
                  <th scope="row" class:tt-table__end={column.align === 'end'}>{@render column.cell(row)}</th>
                {:else}
                  <td class:tt-table__end={column.align === 'end'}>{@render column.cell(row)}</td>
                {/if}
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
  {#if hasMore && !loading}
    <div class="tt-table__more">
      <Button
        variant="secondary"
        loading={loadingMore}
        loadingLabel={t('admin.common.loadingMore')}
        onclick={loadMore}
      >
        {t('admin.common.loadMore')}
      </Button>
    </div>
  {/if}
  <LiveRegion {message} />
</div>

<style>
  .tt-table {
    margin-bottom: var(--tt-space-6);
  }

  .tt-table__scroll {
    max-width: 100%;
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  table:focus-visible {
    outline: var(--tt-focus-width) solid var(--tt-focus);
  }

  caption {
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
    text-align: left;
  }

  th,
  td {
    padding: var(--tt-space-2) var(--tt-space-3);
    border-bottom: var(--tt-border-width) solid var(--tt-border);
    text-align: left;
    vertical-align: top;
  }

  thead th {
    border-bottom-width: 2px;
    background: var(--tt-surface-muted);
  }

  tbody th {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-table__end {
    text-align: right;
  }

  .tt-table__empty {
    color: var(--tt-muted);
  }

  .tt-table__more {
    margin-top: var(--tt-space-3);
  }
</style>
