<script lang="ts">
  // Abuse reports of a tenant (CLAUDE.md section 10, version 1.1; /admin/tenants/{id}/abuse-reports,
  // the page the alert mails link to):
  // - filter by status (open, closed, all), reflected in the URL query string, cursor paging;
  // - columns: date, category, reporter, status; a button opens the detail (a dialog);
  // - detail: category, reporter (verified address, or the number of the recipient link used,
  //   unverified, or a shared link), sender, the message as TEXT (never HTML), the transfer (a
  //   link to its detail while it exists), and close (with an optional note) or reopen.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick, untrack } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Dialog, HelpIcon, TextArea, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import FilterBar from '../../components/FilterBar.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    NOTE_MAX_LENGTH,
    addressText,
    afterUpdate,
    categoryLabel,
    loadedText,
    noteTooLong,
    reportStatusView,
    reporterText,
    statusFilterOptions,
    updateBody,
    type AbuseReport,
  } from './abuseReports';
  import {
    ABUSE_REPORT_FILTERS,
    filtersToApiParams,
    filtersToForm,
    formToFilters,
    isEmpty,
    parseFilters,
    pathWithFilters,
  } from './filters';
  import { emptyList, receiveError, receivePage, startMore, startReset, type PagedList } from './paging';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const tenantId = $derived(params['id'] ?? '');
  const filters = $derived(parseFilters(ABUSE_REPORT_FILTERS, nav.current.search));

  let list = $state.raw<PagedList<AbuseReport>>(emptyList());
  let status = $state('');
  let heading: HTMLHeadingElement | undefined = $state();

  // Detail dialog.
  let detailOpen = $state(false);
  let report = $state.raw<AbuseReport | undefined>(undefined);
  let transferExists = $state<boolean | undefined>(undefined);
  let note = $state('');
  let busy = $state(false);
  let detailError = $state('');
  let noteError = $state('');

  const loadError = $derived(!list.loaded && typeof list.error === 'string' ? list.error : '');
  const moreError = $derived(list.loaded && typeof list.error === 'string' ? list.error : '');
  const resultText = $derived(
    list.loaded ? loadedText(list.items.length, list.nextCursor !== null, t) : undefined,
  );

  const when = (iso: string): string => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' });

  async function fetchPage(cursor?: string): Promise<{ items: AbuseReport[]; nextCursor?: string }> {
    const res = await adminApi.get('/admin/tenants/{tenantId}/abuse-reports', {
      path: { tenantId },
      params: filtersToApiParams(ABUSE_REPORT_FILTERS, filters, { cursor }),
    });
    return res.data;
  }

  async function reload(): Promise<void> {
    list = startReset(list);
    const generation = list.generation;
    try {
      list = receivePage(list, generation, await fetchPage());
    } catch (err) {
      list = receiveError(list, generation, describeError(i18n, err).message);
    }
  }

  async function loadMore(): Promise<void> {
    const next = startMore(list);
    if (next === list || list.nextCursor === null) {
      return;
    }
    const cursor = list.nextCursor;
    list = next;
    const generation = list.generation;
    try {
      list = receivePage(list, generation, await fetchPage(cursor));
    } catch (err) {
      list = receiveError(list, generation, describeError(i18n, err).message);
    }
  }

  $effect(() => {
    void tenantId;
    const form = filtersToForm(ABUSE_REPORT_FILTERS, filters);
    untrack(() => {
      status = form.status;
      void reload();
    });
  });

  async function apply(): Promise<boolean> {
    const next = formToFilters(ABUSE_REPORT_FILTERS, { status });
    if (next === undefined) {
      return false;
    }
    await nav.navigate(pathWithFilters(nav.current.path, ABUSE_REPORT_FILTERS, next));
    return true;
  }

  async function clear(): Promise<void> {
    status = '';
    await nav.navigate(pathWithFilters(nav.current.path, ABUSE_REPORT_FILTERS, {}));
  }

  async function checkTransfer(row: AbuseReport): Promise<void> {
    transferExists = undefined;
    try {
      await adminApi.get('/admin/tenants/{tenantId}/transfers/{transferId}', {
        path: { tenantId, transferId: row.transferId },
      });
      transferExists = true;
    } catch (err) {
      transferExists = err instanceof ApiProblem && err.status === 404 ? false : undefined;
    }
  }

  async function open(row: AbuseReport): Promise<void> {
    report = row;
    note = '';
    detailError = '';
    noteError = '';
    detailOpen = true;
    void checkTransfer(row);
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/abuse-reports/{reportId}', {
        path: { tenantId, reportId: row.id },
      });
      if (report?.id === row.id) {
        report = res.data;
      }
    } catch {
      // The row of the list is still shown.
    }
  }

  async function update(next: 'open' | 'closed'): Promise<void> {
    const current = report;
    if (current === undefined || busy) {
      return;
    }
    noteError = '';
    detailError = '';
    if (next === 'closed' && noteTooLong(note)) {
      noteError = t('fieldErrors.too-long', { max: NOTE_MAX_LENGTH });
      return;
    }
    busy = true;
    try {
      const res = await adminApi.patch('/admin/tenants/{tenantId}/abuse-reports/{reportId}', {
        path: { tenantId, reportId: current.id },
        body: updateBody(next, note),
      });
      report = res.data;
      list = afterUpdate(list, res.data, filters.status);
      announce(t(next === 'closed' ? 'opsAbuse.detail.closedDone' : 'opsAbuse.detail.reopenedDone'));
      detailOpen = false;
    } catch (err) {
      detailError = describeError(i18n, err).message;
    } finally {
      busy = false;
    }
  }

  async function closed(): Promise<void> {
    await tick();
    heading?.focus();
  }
</script>

{#snippet dateCell(row: AbuseReport)}
  {when(row.reportedAt)}
{/snippet}

{#snippet categoryCell(row: AbuseReport)}
  {categoryLabel(row.category, t)}
{/snippet}

{#snippet reporterCell(row: AbuseReport)}
  <span class="tt-break">{reporterText(row, t)}</span>
{/snippet}

{#snippet statusCell(row: AbuseReport)}
  {@const view = reportStatusView(row.status, t)}
  <StatusBadge variant={view.variant} label={view.label} />
{/snippet}

{#snippet actionsCell(row: AbuseReport)}
  <Button
    variant="secondary"
    aria-label={t('opsAbuse.open.buttonFor', {
      category: categoryLabel(row.category, t),
      date: when(row.reportedAt),
    })}
    onclick={() => void open(row)}
  >
    {t('opsAbuse.open.button')}
  </Button>
{/snippet}

<div class="tt-title-row">
  <h1 tabindex="-1" bind:this={heading}>{t('adminOps.abuseReports.title')}</h1>
  <HelpIcon topic="tenant-abuse-reports" title={t('adminOps.abuseReports.title')} {nav} />
</div>
<p>{t('adminOps.abuseReports.intro')}</p>

<FilterBar
  label={t('opsAbuse.filters.label')}
  onapply={apply}
  onreset={clear}
  busy={list.loading && !list.loaded}
  {resultText}
>
  <SelectField label={t('opsAbuse.filters.status')} options={statusFilterOptions(t)} bind:value={status} />
</FilterBar>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void reload()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsAbuse.caption')}
    captionHidden
    rows={list.items}
    key={(row) => row.id}
    loading={list.loading && !list.loaded}
    emptyText={isEmpty(filters) ? t('opsAbuse.empty') : t('opsAbuse.emptyFiltered')}
    nextCursor={list.nextCursor}
    onloadmore={loadMore}
    columns={[
      { id: 'reportedAt', header: t('opsAbuse.columns.reportedAt'), cell: dateCell, rowHeader: true },
      { id: 'category', header: t('opsAbuse.columns.category'), cell: categoryCell },
      { id: 'reporter', header: t('opsAbuse.columns.reporter'), cell: reporterCell },
      { id: 'status', header: t('opsAbuse.columns.status'), cell: statusCell },
      { id: 'actions', header: t('opsAbuse.columns.actions'), cell: actionsCell, headerHidden: true },
    ]}
  />
  {#if moreError !== ''}
    <Alert severity="error">{moreError}</Alert>
  {/if}
{/if}

<Dialog
  bind:open={detailOpen}
  title={t('opsAbuse.detail.title')}
  hideCloseButton={busy}
  onclose={() => void closed()}
>
  {#if report !== undefined}
    {@const view = reportStatusView(report.status, t)}
    <dl class="tt-dl">
      <dt>{t('opsAbuse.detail.status')}</dt>
      <dd><StatusBadge variant={view.variant} label={view.label} /></dd>
      <dt>{t('opsAbuse.detail.category')}</dt>
      <dd>{categoryLabel(report.category, t)}</dd>
      <dt>{t('opsAbuse.detail.reportedAt')}</dt>
      <dd>{when(report.reportedAt)}</dd>
      <dt>{t('opsAbuse.detail.reporter')}</dt>
      <dd class="tt-break">{reporterText(report, t)}</dd>
      <dt>{t('opsAbuse.detail.sender')}</dt>
      <dd class="tt-break">{addressText(report.senderEmail, t)}</dd>
      <dt>{t('opsAbuse.detail.transfer')}</dt>
      <dd class="tt-break">
        {#if transferExists === true}
          <a
            href={nav.href(`${tenantPath(tenantId, 'transfers')}/${encodeURIComponent(report.transferId)}`)}
            use:nav.link
          >
            {report.transferId}
          </a>
        {:else}
          {report.transferId}
          {#if transferExists === false}
            <span class="tt-text-muted">({t('opsAbuse.detail.transferGone')})</span>
          {/if}
        {/if}
      </dd>
    </dl>
    <h3 class="tt-text-lg">{t('opsAbuse.detail.message')}</h3>
    {#if report.message !== undefined && report.message !== ''}
      <p class="tt-break tt-abuse-message">{report.message}</p>
    {:else}
      <p class="tt-text-muted">{t('opsAbuse.detail.noMessage')}</p>
    {/if}
    {#if report.status === 'closed'}
      <dl class="tt-dl">
        {#if report.closedAt !== undefined}
          <dt>{t('opsAbuse.detail.closedAt')}</dt>
          <dd>{when(report.closedAt)}</dd>
        {/if}
        {#if report.closedBy !== undefined}
          <dt>{t('opsAbuse.detail.closedBy')}</dt>
          <dd class="tt-break">{report.closedBy}</dd>
        {/if}
        {#if report.note !== undefined && report.note !== ''}
          <dt>{t('opsAbuse.detail.note')}</dt>
          <dd class="tt-break tt-abuse-message">{report.note}</dd>
        {/if}
      </dl>
    {:else}
      <TextArea
        id="{uid}-note"
        label={t('opsAbuse.detail.noteLabel')}
        hint={t('opsAbuse.detail.noteHint')}
        bind:value={note}
        counterMax={NOTE_MAX_LENGTH}
        rows={3}
        error={noteError === '' ? undefined : noteError}
      />
    {/if}
    {#if detailError !== ''}
      <Alert severity="error">{detailError}</Alert>
    {/if}
  {/if}
  {#snippet actions()}
    <Button
      variant="secondary"
      disabled={busy}
      onclick={() => {
        detailOpen = false;
      }}
    >
      {t('opsAbuse.detail.cancel')}
    </Button>
    {#if report?.status === 'closed'}
      <Button loading={busy} loadingLabel={t('admin.common.saving')} onclick={() => void update('open')}>
        {t('opsAbuse.detail.reopen')}
      </Button>
    {:else if report !== undefined}
      <Button loading={busy} loadingLabel={t('admin.common.saving')} onclick={() => void update('closed')}>
        {t('opsAbuse.detail.close')}
      </Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .tt-abuse-message {
    white-space: pre-wrap;
  }
</style>
