<script lang="ts">
  // Legal texts of a tenant (CLAUDE.md section 13): one row per document, one column per
  // language, each cell saying whether the text is written (badge, with its date) and linking
  // to the editor. There is no list operation: every document is read in every language
  // (GET .../legal/{document}/{lang}, an empty text meaning not written). The tenant
  // navigation is in the sidebar (SidebarTenantBlock of AdminShell).
  import type { components } from '../../../shared/api/schema';
  import { HelpIcon, Spinner, languageName } from '../../../shared/components';
  import { formatDate, locale, supportedLanguages, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import PageHeader from '../../components/PageHeader.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { loadLegalRows, type LegalDocumentName, type LegalRow } from '../../components/legal';
  import type { AdminScreenProps } from '../types';

  type Language = components['schemas']['Language'];

  let { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  // The interface language first, then the other supported ones.
  const languages = $derived(
    [...new Set([locale.current, ...supportedLanguages])].filter((l) => supportedLanguages.includes(l)),
  );
  let rows = $state<LegalRow[] | undefined>();
  let ticket = 0;

  async function load(id: string, langs: readonly string[]): Promise<void> {
    const mine = ++ticket;
    rows = undefined;
    const loaded = await loadLegalRows(async (document, language) => {
      const { data } = await adminApi.get('/admin/tenants/{tenantId}/legal/{document}/{language}', {
        path: { tenantId: id, document, language: language as Language },
      });
      return data;
    }, langs);
    if (mine === ticket) {
      rows = loaded;
    }
  }

  $effect(() => {
    void load(tenantId, languages);
  });

  function editHref(document: LegalDocumentName, lang: string): string {
    return nav.href(
      `/tenants/${encodeURIComponent(tenantId)}/legal/${encodeURIComponent(document)}/${encodeURIComponent(lang)}`,
    );
  }
</script>

<PageHeader title={t('adminTenants.legal.title')} description={t('adminTenants.legal.intro')}>
  {#snippet help()}
    <HelpIcon topic="tenant-legal" title={t('adminTenants.legal.title')} {nav} />
  {/snippet}
</PageHeader>

{#snippet docCell(row: LegalRow)}
  {t(`adminTenants.legal.document.${row.document}`)}
{/snippet}

{#snippet langCell(row: LegalRow, lang: string)}
  {@const cell = row.cells[lang]}
  {@const name = t(`adminTenants.legal.document.${row.document}`)}
  <div class="tt-legal-cell">
    {#if cell?.state === 'present'}
      <StatusBadge variant="ok" label={t('adminTenants.legal.present')} />
      {#if cell.updatedAt}
        <span class="tt-legal-cell__date">
          {t('admin.common.lastUpdated', { date: formatDate(cell.updatedAt) })}
        </span>
      {/if}
    {:else if cell?.state === 'absent'}
      <StatusBadge variant="missing" label={t('adminTenants.legal.absent')} />
    {:else}
      <StatusBadge variant="error" />
    {/if}
    <a
      href={editHref(row.document, lang)}
      use:nav.link
      aria-label={t('adminTenants.legal.edit', {
        document: name,
        language: languageName(lang),
      })}>{t('admin.common.edit')}</a
    >
  </div>
{/snippet}

{#if rows === undefined}
  <Spinner label={t('admin.common.loading')} />
{:else}
  <DataTable
    caption={t('adminTenants.legal.caption')}
    captionHidden
    {rows}
    key={(row) => row.document}
    columns={[
      { id: 'document', header: t('adminTenants.legal.columns.document'), cell: docCell, rowHeader: true },
      ...languages.map((lang) => ({ id: lang, header: languageName(lang), lang, cell: langCell })),
    ]}
  />
{/if}

<style>
  .tt-legal-cell {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--tt-space-1);
  }

  .tt-legal-cell__date {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
