<script lang="ts">
  // Public application (tenant hosts): start-up (tenant configuration, theme, language), page
  // frame (logo, background, footer with legal links, help and language switch, maintenance
  // banner) and the screen of the current route.
  import { onMount } from 'svelte';
  import { api } from '../shared/api/api';
  import { problemMessage } from '../shared/api/problem';
  import { Alert, Footer, PageLayout, Spinner, announce } from '../shared/components';
  import {
    FALLBACK_LANGUAGE,
    i18n,
    locale,
    setLocale,
    supportedLanguages,
    t,
  } from '../shared/i18n/i18n.svelte';
  import { browserStorage, changeLanguage } from '../shared/i18n/language';
  import { createRouter } from '../shared/router/router.svelte';
  import { applyTenantTheme } from '../shared/theme/theme';
  import {
    bootstrapTenant,
    documentTitle,
    legalPath,
    maintenanceNotice,
    type BootstrapDeps,
    type PublicTenant,
  } from './bootstrap';
  import { isHelpRoute, notFoundRoute, routes } from './routes';
  import ErrorPage from './screens/ErrorPage.svelte';

  type Status = 'loading' | 'ready' | 'error';

  let tenant = $state<PublicTenant | undefined>();
  let status = $state<Status>('loading');
  let errorMessage = $state<string | undefined>();
  let retrying = $state(false);

  const storage = browserStorage();
  const router = createRouter({
    routes,
    notFound: notFoundRoute,
    title: (match) => documentTitle(t(match.route.titleKey), tenant?.name),
    announce: (message) => announce(message),
  });

  async function fetchTenant(): Promise<PublicTenant> {
    return (await api.get('/tenant')).data;
  }

  const deps: BootstrapDeps = {
    fetchTenant,
    setLocale,
    supported: supportedLanguages,
    fallback: FALLBACK_LANGUAGE,
    browserLanguages: typeof navigator === 'undefined' ? [] : navigator.languages,
    storage,
  };

  function useTenant(next: PublicTenant): void {
    tenant = next;
    applyTenantTheme(next.branding);
  }

  async function start(): Promise<void> {
    try {
      useTenant(await bootstrapTenant(deps));
      status = 'ready';
    } catch (err) {
      if (locale.current === '') {
        await setLocale(FALLBACK_LANGUAGE);
      }
      errorMessage = problemMessage(i18n, err);
      status = 'error';
    }
  }

  async function retry(): Promise<void> {
    retrying = true;
    await start();
    retrying = false;
  }

  async function onLanguage(lang: string): Promise<void> {
    await changeLanguage(i18n, lang, storage);
    try {
      // Localised tenant texts (maintenance message).
      useTenant(await fetchTenant());
    } catch {
      // Keep the texts already loaded: the language switch itself succeeded.
    }
  }

  onMount(() => {
    router.start();
    void start();
    return () => router.stop();
  });

  // Keeps the document title in sync with the language and the tenant name.
  $effect(() => {
    if (locale.current !== '') {
      document.title = documentTitle(t(router.current.route.titleKey), tenant?.name);
    }
  });

  const match = $derived(router.current);
  const notice = $derived(tenant === undefined ? undefined : maintenanceNotice(tenant));
  // The deposit and invite screens show their own full maintenance page.
  const fullMaintenancePage = new Set(['/', '/invite']);
  const showBanner = $derived(notice !== undefined && !fullMaintenancePage.has(match.route.pattern));
</script>

{#if locale.current === ''}
  <!-- Waiting for the first translation bundle. -->
{:else if status === 'ready' && tenant !== undefined}
  {@const current = tenant}
  {@const Screen = match.route.component}
  <PageLayout
    tenantName={current.name}
    logoUrl={current.branding.logoUrl}
    backgroundUrl={current.branding.backgroundUrl}
    wide={match.route.pattern === '/d/:token'}
  >
    {#snippet banner()}
      {#if showBanner}
        <Alert severity="warning" live={false} title={t('common.maintenance.banner')}>
          {#if notice?.message !== undefined}
            <span class="tt-break banner-text" lang={notice.language}>{notice.message}</span>
          {:else}
            <span class="tt-break banner-text">{t('common.maintenance.bannerText')}</span>
          {/if}
        </Alert>
      {/if}
    {/snippet}
    {#key match.path}
      <Screen tenant={current} params={match.params} nav={router} />
    {/key}
    {#snippet footer()}
      <Footer
        languages={current.availableLanguages}
        currentLanguage={locale.current}
        onlanguagechange={(lang) => void onLanguage(lang)}
        helpTopic={isHelpRoute(match.route) ? null : match.route.helpTopic}
      >
        {#snippet legal()}
          {#each current.legalDocuments as document (document)}
            <li>
              <a href={router.href(legalPath(document))} use:router.link>
                {document === 'privacy-policy' ? t('legal.privacyPolicy') : t('legal.legalNotice')}
              </a>
            </li>
          {/each}
        {/snippet}
      </Footer>
    {/snippet}
  </PageLayout>
{:else if status === 'error'}
  <PageLayout tenantName={t('common.appName')}>
    <ErrorPage message={errorMessage} onretry={() => void retry()} {retrying} />
  </PageLayout>
{:else}
  <PageLayout tenantName={t('common.appName')}>
    <h1 tabindex="-1" class="visually-hidden">{t('common.appName')}</h1>
    <Spinner showLabel />
  </PageLayout>
{/if}

<style>
  .banner-text {
    white-space: pre-line;
  }
</style>
