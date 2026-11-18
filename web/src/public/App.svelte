<script lang="ts">
  // Public application (tenant hosts): start-up (tenant configuration, theme, language), page
  // frame of CLAUDE.md section 13.2 (logo, background, glass header actions: "My transfers", the
  // express secret when the tenant offers it, language, theme and help; footer with the legal
  // links, help and "Powered by TransTeira"; maintenance banner; public card sized by the
  // CardFrame of frame/card.svelte.ts) and the screen of the current route.
  import { onMount } from 'svelte';
  import { pageTitleOf } from '../help/title.svelte';
  import { api } from '../shared/api/api';
  import { tenantSetup } from '../shared/api/setupSignal.svelte';
  import { problemMessage } from '../shared/api/problem';
  import { Alert, PageLayout, Spinner, announce } from '../shared/components';
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
    showSetupPage,
    type BootstrapDeps,
    type PublicTenant,
  } from './bootstrap';
  import { CardFrame, provideCardFrame, routeCardSize } from './frame/card.svelte';
  import HeaderActions from './frame/HeaderActions.svelte';
  import PublicFooter from './frame/PublicFooter.svelte';
  import { isHelpRoute, notFoundRoute, routes } from './routes';
  import { EXPRESS_PATH } from './secret/express';
  import ErrorPage from './screens/ErrorPage.svelte';
  import SetupPage from './screens/SetupPage.svelte';

  type Status = 'loading' | 'ready' | 'error';

  let tenant = $state<PublicTenant | undefined>();
  let status = $state<Status>('loading');
  let errorMessage = $state<string | undefined>();
  let retrying = $state(false);

  const storage = browserStorage();
  const router = createRouter({
    routes,
    notFound: notFoundRoute,
    title: (match) =>
      documentTitle(pageTitleOf(isHelpRoute(match.route), t(match.route.titleKey)), tenant?.name),
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
    if (next.setupState !== 'setup') {
      // A fresh configuration saying the tenant is open clears a sticky tenant-in-setup signal.
      tenantSetup.reset();
    }
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

  // Keeps the document title in sync with the language, the tenant name and the help page.
  $effect(() => {
    if (locale.current !== '') {
      const route = router.current.route;
      document.title = documentTitle(pageTitleOf(isHelpRoute(route), t(route.titleKey)), tenant?.name);
    }
  });

  const match = $derived(router.current);
  // Width of the public card: the size of the route, unless the screen requests another one.
  const frame = provideCardFrame(new CardFrame(() => routeCardSize(match.route.pattern)));
  const notice = $derived(tenant === undefined ? undefined : maintenanceNotice(tenant));
  // The deposit, invite and express secret screens show their own full maintenance page.
  const fullMaintenancePage = new Set(['/', '/invite', EXPRESS_PATH]);
  const inSetup = $derived(
    // Maintenance wins over setup, as on the server.
    tenant === undefined || notice !== undefined
      ? false
      : showSetupPage(tenant, match.route.pattern, tenantSetup.inSetup),
  );
  const showBanner = $derived(notice !== undefined && !fullMaintenancePage.has(match.route.pattern));
  // The help pages have no help link of their own.
  const helpTopic = $derived(isHelpRoute(match.route) ? null : match.route.helpTopic);
</script>

{#if locale.current === ''}
  <!-- Waiting for the first translation bundle. -->
{:else if status === 'ready' && tenant !== undefined}
  {@const current = tenant}
  {@const Screen = match.route.component}
  <PageLayout
    variant="public"
    cardSize={frame.size}
    tenantName={current.name}
    logoUrl={current.branding.logoUrl}
    backgroundUrl={current.branding.backgroundUrl}
  >
    {#snippet header()}
      <HeaderActions
        tenant={current}
        nav={router}
        pattern={match.route.pattern}
        languages={current.availableLanguages}
        currentLanguage={locale.current}
        onlanguagechange={(lang) => void onLanguage(lang)}
        {helpTopic}
      />
    {/snippet}
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
      {#if inSetup}
        <SetupPage />
      {:else}
        <Screen tenant={current} params={match.params} nav={router} />
      {/if}
    {/key}
    {#snippet footer()}
      {#snippet legal()}
        {#each current.legalDocuments as document (document)}
          <li>
            <a href={router.href(legalPath(document))} use:router.link>
              {document === 'privacy-policy' ? t('legal.privacyPolicy') : t('legal.legalNotice')}
            </a>
          </li>
        {/each}
      {/snippet}
      <!-- No empty "Legal information" navigation when the tenant published no legal text. -->
      <PublicFooter {helpTopic} nav={router} legal={current.legalDocuments.length > 0 ? legal : undefined} />
    {/snippet}
  </PageLayout>
{:else if status === 'error'}
  <PageLayout variant="public" tenantName={t('common.appName')}>
    <ErrorPage message={errorMessage} onretry={() => void retry()} {retrying} />
  </PageLayout>
{:else}
  <PageLayout variant="public" tenantName={t('common.appName')}>
    <h1 tabindex="-1" class="visually-hidden">{t('common.appName')}</h1>
    <Spinner showLabel />
  </PageLayout>
{/if}

<style>
  .banner-text {
    white-space: pre-line;
  }
</style>
