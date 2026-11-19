<script lang="ts" generics="T">
  // Semantic data table (RGAA 5.4, 5.6, 5.7): <caption>, column headers with scope="col",
  // optional row headers (scope="row"). The rows are shown in the order of the API (no client
  // sorting). With a cursor, a "Load more" button fetches the next page; the number of rows
  // added is announced, and the focus stays on the button (or moves to the table when every
  // row is shown, since the button disappears).
  //
  // Look (CLAUDE.md section 13.2): a card (radius 16 px, decorative --tt-separator border) whose
  // caption is the card heading, small uppercase muted column headers (12 px), cell text in the
  // small font size (14 px, so that wide tables fit their card better), rows of at least 44 px
  // separated by --tt-separator lines, links of the cells 44 px high. Words are never broken
  // inside the cells (.tt-break included), at every width: a table wider than its card (a phone,
  // or many columns on a desktop) keeps its real columns and readable words and scrolls
  // horizontally inside the card (plan deviation 7), instead of squeezing its columns letter by
  // letter; the scroll area becomes a named focusable region only while it overflows
  // (scrollRegion.ts). The cells are padded by 12 px, 20 px at the edges of the card.
  // variant="plain" drops the card frame, for a table inside a Card (flush) or a dialog.
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
  import { scrollRegion } from './scrollRegion';

  /** One column of the table. */
  interface Column {
    /** Stable id of the column. */
    id: string;
    /** Header text. */
    header: string;
    /** Content of a cell; receives the row and, for a snippet shared by several columns, the column id. */
    cell: Snippet<[T, string]>;
    /** Language (BCP 47) of the header, when it is a language name shown in another language. */
    lang?: string;
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
    /** card (default): the table in its own card; plain: no frame (inside a Card or a dialog). */
    variant?: 'card' | 'plain';
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
    variant = 'card',
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  const captionId = `${uid}-caption`;
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

<div class="tt-table tt-table--{variant} {className}">
  {#if loading}
    <p class="tt-table__status"><Spinner showLabel /></p>
  {:else if rows.length === 0}
    <p class="tt-table__empty" id="{uid}-empty">{emptyText ?? t('admin.common.noResults')}</p>
  {:else}
    <div class="tt-table__scroll" use:scrollRegion={captionId}>
      <table bind:this={table} tabindex="-1">
        <caption id={captionId} class:visually-hidden={captionHidden}>{caption}</caption>
        <thead>
          <tr>
            {#each columns as column (column.id)}
              <th scope="col" lang={column.lang} class:tt-table__end={column.align === 'end'}>
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
                  <th scope="row" class:tt-table__end={column.align === 'end'}
                    >{@render column.cell(row, column.id)}</th
                  >
                {:else}
                  <td class:tt-table__end={column.align === 'end'}>{@render column.cell(row, column.id)}</td>
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
    min-width: 0;
    margin-bottom: var(--tt-space-4);
  }

  .tt-table--card {
    border: var(--tt-border-width) solid var(--tt-separator);
    border-radius: var(--tt-radius-lg);
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-table--plain {
    margin-bottom: 0;
  }

  /*
   * position: relative makes the scroll area the containing block of the visually hidden texts of
   * the cells (position: absolute): otherwise they escape it and widen the page on a phone.
   */
  .tt-table__scroll {
    position: relative;
    max-width: 100%;
    overflow-x: auto;
  }

  /* Focus of the scroll region (when it overflows), kept inside the card. */
  .tt-table__scroll:focus-visible {
    outline-offset: -3px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  table:focus-visible {
    outline: var(--tt-focus-width) solid var(--tt-focus);
    outline-offset: -3px;
  }

  caption {
    padding: 1.125rem var(--tt-space-5) var(--tt-space-3);
    font-size: var(--tt-font-size-lg);
    font-weight: var(--tt-font-weight-heading);
    text-align: left;
  }

  .tt-table--plain caption {
    padding: 0 var(--tt-space-5) var(--tt-space-3);
  }

  /*
   * Whole words in the cells at every width (.tt-break breaks anywhere elsewhere in the admin): the
   * columns keep readable words and a wide table scrolls inside its card (plan deviation 7).
   */
  th,
  td,
  tbody :global(.tt-break) {
    overflow-wrap: normal;
    word-break: normal;
  }

  /* A value without words (a SHA-256 digest) still breaks anywhere: tt-table__break-anywhere. */
  tbody :global(.tt-table__break-anywhere) {
    overflow-wrap: anywhere;
    word-break: break-all;
  }

  /* Cell text in the small size (14 px; the headers are smaller still, below). */
  th,
  td {
    padding: 0.875rem var(--tt-space-3);
    border-bottom: var(--tt-border-width) solid var(--tt-separator);
    font-size: var(--tt-font-size-sm);
    text-align: left;
    vertical-align: middle;
  }

  /* The first and last cells keep the inset of the card. */
  th:first-child,
  td:first-child {
    padding-left: var(--tt-space-5);
  }

  th:last-child,
  td:last-child {
    padding-right: var(--tt-space-5);
  }

  thead th {
    padding-top: var(--tt-space-3);
    padding-bottom: var(--tt-space-3);
    color: var(--tt-muted);
    font-size: 0.75rem;
    font-weight: var(--tt-font-weight-bold);
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  tbody tr:last-child > * {
    border-bottom: 0;
  }

  tbody th {
    font-weight: var(--tt-font-weight-bold);
  }

  /* Links of the cells: targets of at least 44 px (plan deviation 6). */
  tbody :global(a) {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
  }

  .tt-table__end {
    text-align: right;
  }

  .tt-table__empty,
  .tt-table__status {
    margin: 0;
    padding: var(--tt-space-5);
  }

  .tt-table__empty {
    color: var(--tt-muted);
  }

  .tt-table--plain .tt-table__empty,
  .tt-table--plain .tt-table__status {
    padding: 0 var(--tt-space-5) var(--tt-space-5);
  }

  .tt-table__more {
    padding: var(--tt-space-3) var(--tt-space-5) var(--tt-space-5);
    border-top: var(--tt-border-width) solid var(--tt-separator);
  }

  /* Phones: a narrower inset of the card. */
  @media (max-width: 40rem) {
    caption {
      padding-left: var(--tt-space-4);
      padding-right: var(--tt-space-4);
    }

    th:first-child,
    td:first-child {
      padding-left: var(--tt-space-4);
    }

    th:last-child,
    td:last-child {
      padding-right: var(--tt-space-4);
    }
  }

  @media (forced-colors: active) {
    .tt-table--card {
      border-color: CanvasText;
    }
  }
</style>
