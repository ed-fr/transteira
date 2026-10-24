<script lang="ts">
  // Legal notice and privacy policy of the tenant (CLAUDE.md section 13): GET
  // /tenant/legal/{document} in the interface language, reloaded when the language changes.
  import { api } from '../../shared/api/api';
  import type { components } from '../../shared/api/schema';
  import { LegalContent, Spinner } from '../../shared/components';
  import { formatDate, locale, t } from '../../shared/i18n/i18n.svelte';
  import { isPublishedLegalDocument } from '../bootstrap';
  import ErrorPage from './ErrorPage.svelte';
  import NotFound from './NotFound.svelte';
  import { loadFailure } from './outcomes';
  import type { ScreenProps } from './types';

  type LegalDocument = components['schemas']['LegalDocument'];
  type State =
    { kind: 'loading' } | { kind: 'ready'; doc: LegalDocument } | { kind: 'not-found' } | { kind: 'error' };

  let { tenant, params, nav }: ScreenProps = $props();
  const name = $derived(params['document'] ?? '');
  let view = $state<State>({ kind: 'loading' });
  let ticket = 0;

  async function load(document: string): Promise<void> {
    const mine = ++ticket;
    if (!isPublishedLegalDocument(tenant, document)) {
      view = { kind: 'not-found' };
      return;
    }
    view = { kind: 'loading' };
    try {
      const { data } = await api.get('/tenant/legal/{document}', { path: { document } });
      if (mine === ticket) {
        view = { kind: 'ready', doc: data };
      }
    } catch (err) {
      if (mine === ticket) {
        view = loadFailure(err) === 'error' ? { kind: 'error' } : { kind: 'not-found' };
      }
    }
  }

  $effect(() => {
    // Reload on a document or language change.
    void locale.current;
    void load(name);
  });

  const heading = $derived(name === 'privacy-policy' ? t('legal.privacyPolicy') : t('legal.legalNotice'));
</script>

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{heading}</h1>
  <Spinner showLabel />
{:else if view.kind === 'ready'}
  <h1 tabindex="-1">{heading}</h1>
  {#if view.doc.html}
    <LegalContent html={view.doc.html} />
  {:else}
    <p class="tt-break legal-plain">{view.doc.markdown}</p>
  {/if}
  {#if view.doc.updatedAt}
    <p class="tt-text-muted tt-text-sm">
      {t('legal.updatedAt', { date: formatDate(view.doc.updatedAt, { dateStyle: 'long' }) })}
    </p>
  {/if}
{:else if view.kind === 'not-found'}
  <NotFound {nav} title={t('legal.notFound.title')} text={t('legal.notFound.text')} />
{:else}
  <ErrorPage onretry={() => void load(name)} />
{/if}

<style>
  .legal-plain {
    white-space: pre-line;
  }
</style>
