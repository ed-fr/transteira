<script lang="ts">
  // Admin application shell (admin host, under /admin/): language (stored choice, browser
  // languages, English), default theme (no tenant colours), page frame and the screen of the
  // current route. The admin screens arrive in step 16.
  import { onMount } from 'svelte';
  import { Footer, PageLayout, announce } from '../shared/components';
  import { FALLBACK_LANGUAGE, i18n, locale, supportedLanguages, t } from '../shared/i18n/i18n.svelte';
  import { browserStorage, changeLanguage, initLanguage } from '../shared/i18n/language';
  import { createRouter } from '../shared/router/router.svelte';
  import { ADMIN_BASE, notFoundRoute, routes } from './routes';

  const storage = browserStorage();

  function documentTitle(page: string, site: string): string {
    return page === site ? page : `${page} – ${site}`;
  }
  const router = createRouter({
    routes,
    notFound: notFoundRoute,
    base: ADMIN_BASE,
    title: (match) => documentTitle(t(match.route.titleKey), t('admin.appName')),
    announce: (message) => announce(message),
  });

  onMount(() => {
    router.start();
    void initLanguage(i18n, {
      available: supportedLanguages,
      tenantLanguage: FALLBACK_LANGUAGE,
      browserLanguages: typeof navigator === 'undefined' ? [] : navigator.languages,
      storage,
    });
    return () => router.stop();
  });

  $effect(() => {
    if (locale.current !== '') {
      document.title = documentTitle(t(router.current.route.titleKey), t('admin.appName'));
    }
  });

  const match = $derived(router.current);
  const helpTopic = $derived(match.route.pattern.startsWith('/help') ? null : match.route.helpTopic);
</script>

{#if locale.current !== ''}
  {@const Screen = match.route.component}
  <PageLayout tenantName={t('admin.appName')}>
    {#key match.path}
      <Screen params={match.params} nav={router} />
    {/key}
    {#snippet footer()}
      <Footer
        languages={supportedLanguages}
        currentLanguage={locale.current}
        onlanguagechange={(lang) => void changeLanguage(i18n, lang, storage)}
        {helpTopic}
        helpBase={ADMIN_BASE}
      />
    {/snippet}
  </PageLayout>
{/if}
