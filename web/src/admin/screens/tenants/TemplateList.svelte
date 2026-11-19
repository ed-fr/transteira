<script lang="ts">
  // Mail templates of a tenant (CLAUDE.md section 12.3): GET .../email-templates, shown as a
  // table with one row per template and one column per language (RGAA 5.4 to 5.7: caption,
  // column and row headers); each cell says whether the template is customized (badge, with
  // its date) and links to the editor. The tenant navigation is in the sidebar
  // (SidebarTenantBlock of AdminShell).
  import { describeError } from '../../../shared/api/problem';
  import { Alert, HelpIcon, Spinner, languageName } from '../../../shared/components';
  import { formatDate, i18n, locale, supportedLanguages, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import DataTable from '../../components/DataTable.svelte';
  import PageHeader from '../../components/PageHeader.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { groupTemplates, type TemplateGrid } from '../../components/templates';
  import type { AdminScreenProps } from '../types';

  type View =
    { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; grid: TemplateGrid };

  let { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  let view = $state<View>({ kind: 'loading' });
  let ticket = 0;

  async function load(id: string): Promise<void> {
    const mine = ++ticket;
    view = { kind: 'loading' };
    try {
      const { data } = await adminApi.get('/admin/tenants/{tenantId}/email-templates', {
        path: { tenantId: id },
      });
      if (mine === ticket) {
        // The interface language first, then the other supported ones.
        const preferred = [locale.current, ...supportedLanguages];
        view = { kind: 'ready', grid: groupTemplates(data, preferred) };
      }
    } catch (err) {
      if (mine === ticket) {
        view = { kind: 'error', message: describeError(i18n, err).message };
      }
    }
  }

  $effect(() => {
    void load(tenantId);
  });

  function keyLabel(key: string): string {
    const k = `adminTenants.templates.key.${key}`;
    return i18n.has(k) ? t(k) : key;
  }

  function editHref(key: string, lang: string): string {
    return nav.href(
      `/tenants/${encodeURIComponent(tenantId)}/templates/${encodeURIComponent(key)}/${encodeURIComponent(lang)}`,
    );
  }

  type TemplateRow = TemplateGrid['rows'][number];
</script>

<PageHeader title={t('adminTenants.templates.title')} description={t('adminTenants.templates.intro')}>
  {#snippet help()}
    <HelpIcon topic="tenant-templates" title={t('adminTenants.templates.title')} {nav} />
  {/snippet}
</PageHeader>

{#snippet keyCell(row: TemplateRow)}
  {keyLabel(row.key)}
{/snippet}

{#snippet langCell(row: TemplateRow, lang: string)}
  {@const cell = row.cells[lang]}
  {#if cell !== undefined}
    <div class="tt-template-cell">
      {#if cell.customised}
        <StatusBadge variant="info" label={t('adminTenants.templates.customized')} />
        {#if cell.updatedAt}
          <span class="tt-template-cell__date">
            {t('admin.common.lastUpdated', { date: formatDate(cell.updatedAt) })}
          </span>
        {/if}
      {:else}
        <span>{t('adminTenants.templates.default')}</span>
      {/if}
      <a
        href={editHref(row.key, lang)}
        use:nav.link
        aria-label={t('adminTenants.templates.edit', {
          template: keyLabel(row.key),
          language: languageName(lang),
        })}>{t('admin.common.edit')}</a
      >
    </div>
  {:else}
    <span>{t('admin.common.none')}</span>
  {/if}
{/snippet}

{#if view.kind === 'loading'}
  <Spinner label={t('admin.common.loading')} />
{:else if view.kind === 'error'}
  <Alert severity="error">{view.message}</Alert>
{:else if view.grid.rows.length === 0}
  <p>{t('admin.common.noResults')}</p>
{:else}
  <DataTable
    caption={t('adminTenants.templates.caption')}
    captionHidden
    rows={view.grid.rows}
    key={(row) => row.key}
    columns={[
      {
        id: 'template',
        header: t('adminTenants.templates.columns.template'),
        cell: keyCell,
        rowHeader: true,
      },
      ...view.grid.languages.map((lang) => ({
        id: lang,
        header: languageName(lang),
        lang,
        cell: langCell,
      })),
    ]}
  />
{/if}

<style>
  .tt-template-cell {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--tt-space-1);
  }

  .tt-template-cell__date {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
