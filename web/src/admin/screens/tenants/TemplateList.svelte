<script lang="ts">
  // Mail templates of a tenant (CLAUDE.md section 12.3): GET .../email-templates, shown as a
  // table with one row per template and one column per language (RGAA 5.4 to 5.7: caption,
  // column and row headers); each cell says whether the template is customized (badge, with
  // its date) and links to the editor. The tenant sub-navigation is rendered by App.svelte.
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Spinner, languageName } from '../../../shared/components';
  import { formatDate, i18n, locale, supportedLanguages, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
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
</script>

<h1 tabindex="-1">{t('adminTenants.templates.title')}</h1>
<p>{t('adminTenants.templates.intro')}</p>

{#if view.kind === 'loading'}
  <Spinner label={t('admin.common.loading')} />
{:else if view.kind === 'error'}
  <Alert severity="error">{view.message}</Alert>
{:else if view.grid.rows.length === 0}
  <p>{t('admin.common.noResults')}</p>
{:else}
  <div class="tt-table-wrap">
    <table class="tt-table">
      <caption>{t('adminTenants.templates.caption')}</caption>
      <thead>
        <tr>
          <th scope="col">{t('adminTenants.templates.columns.template')}</th>
          {#each view.grid.languages as lang (lang)}
            <th scope="col" {lang}>{languageName(lang)}</th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each view.grid.rows as row (row.key)}
          <tr>
            <th scope="row">{keyLabel(row.key)}</th>
            {#each view.grid.languages as lang (lang)}
              {@const cell = row.cells[lang]}
              <td>
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
              </td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .tt-table-wrap {
    overflow-x: auto;
  }

  .tt-table {
    width: 100%;
    border-collapse: collapse;
  }

  .tt-table caption {
    text-align: start;
    font-weight: var(--tt-font-weight-bold);
    margin-bottom: var(--tt-space-2);
  }

  .tt-table th,
  .tt-table td {
    padding: var(--tt-space-2) var(--tt-space-3);
    border-bottom: var(--tt-border-width) solid var(--tt-border);
    text-align: start;
    vertical-align: top;
  }

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

  .tt-template-cell a {
    color: var(--tt-link);
  }
</style>
