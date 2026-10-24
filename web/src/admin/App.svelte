<script lang="ts">
  // Admin application shell (admin host, under /admin/).
  //
  // - Language (plan D5): the stored choice, then the language of the admin profile once known,
  //   then the browser languages, then English. The footer switch stores the choice.
  // - Session: adminSession.bootstrap() (setup status, then profile); a failed bootstrap, or a
  //   failed profile fetch after a sign-in, shows an error page whose button calls
  //   adminSession.retry().
  // - Access: resolveAccess (auth/guard.ts) runs on every navigation and every change of the
  //   authentication state; a redirect replaces the history entry and bypasses the leave
  //   guards (an unsaved-changes guard cannot keep a lost access), a refused route shows the
  //   "not found" page (like the 404 of the server), a pending state a loading indicator.
  // - Frame: AdminLayout (default theme, no tenant colours), TenantNav above the screens of a
  //   tenant, the screen of the current route, the footer (help link, language switch).
  // The flash message of the anonymous state (session expired, signed out) is read from the
  // session by the sign-in screen.
  import { onMount, untrack } from 'svelte';
  import { problemMessage } from '../shared/api/problem';
  import { Button, Footer, Spinner, announce } from '../shared/components';
  import { i18n, locale, supportedLanguages, t } from '../shared/i18n/i18n.svelte';
  import { browserStorage, changeLanguage, readStoredLanguage } from '../shared/i18n/language';
  import { createRouter, type RouteMatch } from '../shared/router/router.svelte';
  import { adminSession } from './api';
  import { resolveAccess, type AccessDecision } from './auth/guard';
  import AdminLayout from './components/AdminLayout.svelte';
  import TenantNav from './components/TenantNav.svelte';
  import { ADMIN_BASE, adminRoute, isHelpRoute, notFoundRoute, routes } from './routes';
  import NotFound from './screens/NotFound.svelte';
  import type { AdminScreenComponent } from './screens/types';
  import { pickAdminLanguage, redirectTarget, tenantNameOf } from './shell';

  const storage = browserStorage();
  const browserLanguages: readonly string[] = typeof navigator === 'undefined' ? [] : navigator.languages;

  function decide(m: RouteMatch<AdminScreenComponent>): AccessDecision {
    return resolveAccess(adminSession.state, {
      access: adminRoute(m.route).access,
      path: m.path,
      params: m.params,
      search: m.search,
    });
  }

  function documentTitle(m: RouteMatch<AdminScreenComponent>): string {
    const key = decide(m).kind === 'notFound' ? notFoundRoute.titleKey : m.route.titleKey;
    const page = t(key);
    const site = t('admin.appName');
    return page === site ? page : `${page} – ${site}`;
  }

  const router = createRouter({
    routes,
    notFound: notFoundRoute,
    base: ADMIN_BASE,
    title: documentTitle,
    announce: (message) => announce(message),
  });

  // Admin whose profile language was applied (once per sign-in, so that a later profile
  // refresh never undoes a choice made in the footer without storage).
  let profileLanguageOf: string | undefined;

  async function bootstrap(): Promise<void> {
    try {
      await adminSession.bootstrap();
    } catch {
      // adminSession.error holds the error: the error page offers a retry.
    }
  }

  onMount(() => {
    router.start();
    void i18n.setLocale(
      pickAdminLanguage({
        available: supportedLanguages,
        stored: readStoredLanguage(storage),
        browserLanguages,
      }),
    );
    void bootstrap();
    return () => router.stop();
  });

  // Profile language: applies once the profile is known, unless a choice is stored.
  $effect(() => {
    const me = adminSession.me;
    if (me === undefined || me.id === profileLanguageOf) {
      return;
    }
    profileLanguageOf = me.id;
    const lang = pickAdminLanguage({
      available: supportedLanguages,
      stored: readStoredLanguage(storage),
      meLanguage: me.language,
      browserLanguages,
    });
    if (lang !== untrack(() => locale.current)) {
      void i18n.setLocale(lang);
    }
  });

  const match = $derived(router.current);
  const route = $derived(adminRoute(match.route));
  const decision = $derived(decide(match));
  const me = $derived(adminSession.me);
  const bootstrapError = $derived(
    adminSession.state.kind === 'loading' && adminSession.error !== undefined
      ? adminSession.error
      : undefined,
  );
  const showNav = $derived(adminSession.state.kind === 'authenticated' && decision.kind !== 'pending');
  const tenantId = $derived(route.tenantNav === true ? match.params['id'] : undefined);
  const helpTopic = $derived(isHelpRoute(route) ? null : route.helpTopic);

  // Guard: redirects replace the history entry (never towards the page already shown).
  $effect(() => {
    const to = redirectTarget(decision, match.path + match.search);
    if (to !== undefined) {
      void router.navigate(to, { replace: true, force: true });
    }
  });

  // Title: language changes, and the authentication state may turn the page into "not found".
  $effect(() => {
    if (locale.current !== '') {
      document.title = documentTitle(router.current);
    }
  });

  let retrying = $state(false);
  async function retry(): Promise<void> {
    retrying = true;
    try {
      await adminSession.retry();
    } catch {
      // adminSession.error holds the new error: the error page stays.
    }
    retrying = false;
  }
</script>

{#if locale.current !== ''}
  <AdminLayout {me} {showNav} path={match.path} nav={router}>
    {#if bootstrapError !== undefined}
      <h1 tabindex="-1">{t('common.error.title')}</h1>
      <p role="alert">{problemMessage(i18n, bootstrapError)}</p>
      <Button loading={retrying} onclick={() => void retry()}>{t('common.retry')}</Button>
    {:else if decision.kind === 'render'}
      {@const Screen = route.component}
      {#if tenantId !== undefined}
        <TenantNav {tenantId} tenantName={tenantNameOf(me, tenantId)} path={match.path} nav={router} />
      {/if}
      {#key match.path}
        <Screen params={match.params} nav={router} />
      {/key}
    {:else if decision.kind === 'notFound'}
      {#key match.path}
        <NotFound params={match.params} nav={router} />
      {/key}
    {:else}
      <p><Spinner showLabel label={t('admin.loading')} /></p>
    {/if}
    {#snippet footer()}
      <Footer
        languages={supportedLanguages}
        currentLanguage={locale.current}
        onlanguagechange={(lang) => void changeLanguage(i18n, lang, storage)}
        {helpTopic}
        helpBase={ADMIN_BASE}
      />
    {/snippet}
  </AdminLayout>
{/if}
