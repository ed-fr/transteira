<script lang="ts">
  // Legal texts of a tenant (CLAUDE.md section 13): one row per document, one column per
  // language, each cell saying whether the text is written (badge, with its date) and linking
  // to the editor. There is no list operation: every document is read in every language
  // (GET .../legal/{document}/{lang}, an empty text meaning not written). The tenant
  // sub-navigation is rendered by App.svelte.
  import type { components } from '../../../shared/api/schema';
  import { Spinner, languageName } from '../../../shared/components';
  import { formatDate, locale, supportedLanguages, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
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

<h1 tabindex="-1">{t('adminTenants.legal.title')}</h1>
<p>{t('adminTenants.legal.intro')}</p>

{#if rows === undefined}
  <Spinner label={t('admin.common.loading')} />
{:else}
  <div class="tt-table-wrap">
    <table class="tt-table">
      <caption>{t('adminTenants.legal.caption')}</caption>
      <thead>
        <tr>
          <th scope="col">{t('adminTenants.legal.columns.document')}</th>
          {#each languages as lang (lang)}
            <th scope="col" {lang}>{languageName(lang)}</th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each rows as row (row.document)}
          {@const name = t(`adminTenants.legal.document.${row.document}`)}
          <tr>
            <th scope="row">{name}</th>
            {#each languages as lang (lang)}
              {@const cell = row.cells[lang]}
              <td>
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

  .tt-legal-cell a {
    color: var(--tt-link);
  }
</style>
