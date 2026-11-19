<script lang="ts">
  // Frame of the administration (CLAUDE.md section 13.2; plan of step 3c).
  //
  // - Signed-in admin (showNav and a profile): the skip link to the main content, the dark sidebar
  //   (Sidebar.svelte, the banner landmark: logo, main navigation with the tenant and system blocks
  //   nested under their entries, user block with "Sign out"), then the main column on the muted
  //   page background: the main landmark (id "main", target of the skip link) holding the banners
  //   and the screen, and the slim footer (the footer snippet: help link, language, theme,
  //   version) at its bottom (styles/admin.css).
  // - Otherwise (first-run setup, sign-in, activation, intermediate sign-in steps, bootstrap
  //   error): the shared PageLayout frame, unchanged (wide card, TransTeira logo for the theme).
  // The default theme applies everywhere: the administration never uses a tenant colour (only the
  // decorative swatch of TenantSwatch). The shared announcer regions are mounted once here, for
  // both frames, so that they stay in place when the frame changes.
  //
  // Behaviours kept from the former layout:
  // - sign-out (Sidebar button), its error in an Alert of the banners; the search query and the
  //   maintenance state are forgotten with the session;
  // - while an admin is authenticated (never an auditor, whose role cannot read it: 403), the
  //   maintenance state is kept by adminMaintenance (read at sign-in, on each navigation and when
  //   the tab is shown again; never on a timer, which would keep the session alive, T-165), and a
  //   polite banner tells every admin that the maintenance mode is on, with a link to the
  //   maintenance screen for the super admin. The live region (role="status") is always rendered,
  //   empty without a banner, so that its content is announced;
  // - versions read once per sign-in (adminVersion: footer, and for a super admin a discreet notice
  //   when a newer release exists, with a link to the system overview).
  import { untrack, type Snippet } from 'svelte';
  import { problemMessage } from '../../shared/api/problem';
  import { Alert, Announcer, PageLayout } from '../../shared/components';
  import { formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import { adminSession } from '../api';
  import type { AdminMe } from '../auth/machine';
  import logoDark from '../brand/transteira-horizontal-dark.png';
  import logoLight from '../brand/transteira-horizontal.png';
  import { adminMaintenance } from '../maintenance.svelte';
  import { maintenanceBanner, maintenanceBannerText } from '../maintenanceBanner';
  import type { Navigation } from '../screens/types';
  import { searchQuery } from '../search.svelte';
  import { isAuditor, systemPath } from '../shell';
  import { updateNotice } from '../version';
  import { adminVersion } from '../version.svelte';
  import Sidebar from './Sidebar.svelte';

  interface Props {
    /** Profile of the authenticated admin; the sidebar is not shown without it. */
    me: AdminMe | undefined;
    /** Shows the signed-in frame (authenticated state, screen decided). */
    showNav: boolean;
    /** Current application path (aria-current, maintenance reads, menu). */
    path: string;
    /** Tenant of the page shown (the :id of a tenant route), for the tenant block. */
    tenantId?: string | undefined;
    /** The page shown is a system page, for the system block. */
    inSystem?: boolean;
    /** Router helpers. */
    nav: Navigation;
    /** Footer (Footer.svelte). */
    footer?: Snippet;
    /** Page content. */
    children: Snippet;
  }

  let { me, showNav, path, tenantId, inSystem = false, nav, footer, children }: Props = $props();

  let signingOut = $state(false);
  let logoutError = $state<string | undefined>(undefined);
  let main: HTMLElement | undefined = $state();

  const framed = $derived(showNav && me !== undefined);

  // Maintenance state: kept while an admin is authenticated (not during the sign-in steps),
  // forgotten on sign-out and when the shell is destroyed.
  // An auditor cannot read it (read-only role: 403), so it is not asked for it.
  const authenticated = $derived(adminSession.state.kind === 'authenticated');
  const readsMaintenance = $derived(authenticated && !isAuditor(me?.role));
  $effect(() => {
    if (!readsMaintenance) {
      return;
    }
    adminMaintenance.start();
    return () => adminMaintenance.stop();
  });

  // The search query (possibly an address) never outlives the session (T-412).
  $effect(() => {
    if (!authenticated) {
      searchQuery.clear();
    }
  });

  // Versions (footer, update notice of the super admin): read once per sign-in, never on a timer.
  const isSuperAdmin = $derived(me?.role === 'super_admin');
  $effect(() => {
    if (!authenticated || me === undefined) {
      return;
    }
    void adminVersion.start(untrack(() => isSuperAdmin));
    return () => adminVersion.stop();
  });

  // A navigation of the admin is admin activity: the state is read again on a new path.
  $effect(() => {
    if (readsMaintenance) {
      adminMaintenance.routeChanged(path);
    }
  });

  const banner = $derived(maintenanceBanner(adminMaintenance.current, me?.role));
  const showBanner = $derived(framed && banner.visible);
  const bannerText = $derived(
    maintenanceBannerText(banner, t, (iso) => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' })),
  );

  const update = $derived(updateNotice(isSuperAdmin ? adminVersion.system : undefined));

  async function signOut(): Promise<void> {
    signingOut = true;
    logoutError = undefined;
    try {
      await adminSession.logout();
      searchQuery.clear();
      await nav.navigate('/login', { replace: true });
    } catch (err) {
      logoutError = problemMessage(i18n, err);
    } finally {
      signingOut = false;
    }
  }

  // The router uses the History API: move the focus without changing the URL hash.
  function skipToMain(event: MouseEvent): void {
    if (main !== undefined) {
      event.preventDefault();
      main.focus();
      main.scrollIntoView();
    }
  }
</script>

<!-- TransTeira logo of the frame of the signed-out screens: the version for light backgrounds in
     the light theme, the one for dark backgrounds in the dark theme (data-theme on <html>); the
     hidden one is display: none, so only one name is announced. -->
{#snippet adminBrand()}
  <img
    class="tt-admin-logo tt-admin-logo--light"
    src={logoLight}
    alt={t('admin.appName')}
    width="524"
    height="144"
  />
  <img
    class="tt-admin-logo tt-admin-logo--dark"
    src={logoDark}
    alt={t('admin.appName')}
    width="524"
    height="144"
  />
{/snippet}

{#snippet banners()}
  <div role="status" class="tt-admin-maintenance">
    {#if showBanner}
      <Alert severity="warning" live={false}>
        <p>
          {bannerText}
          {#if banner.linkPath !== undefined}
            <a href={nav.href(banner.linkPath)} use:nav.link>{t('adminSystem.banner.manage')}</a>
          {/if}
        </p>
      </Alert>
    {/if}
  </div>
  {#if framed && update.visible}
    <Alert severity="info" live={false}>
      <p>
        {t('sysVersion.notice', { version: update.latest ?? '' })}
        <a href={nav.href(systemPath('overview'))} use:nav.link>{t('sysVersion.noticeDetails')}</a>
      </p>
    </Alert>
  {/if}
  {#if logoutError !== undefined}
    <Alert severity="error" ondismiss={() => (logoutError = undefined)}>
      <p>{logoutError}</p>
    </Alert>
  {/if}
{/snippet}

{#if framed && me !== undefined}
  <a class="skip-link" href="#main" onclick={skipToMain}>{t('components.layout.skipLink')}</a>
  <div class="tt-admin-frame">
    <Sidebar {me} {path} {tenantId} {inSystem} {nav} {signingOut} onsignout={() => void signOut()} />
    <div class="tt-admin-column">
      <main class="tt-admin-main" id="main" tabindex="-1" bind:this={main}>
        <div class="tt-admin-banners">
          {@render banners()}
        </div>
        {@render children()}
      </main>
      {#if footer}{@render footer()}{/if}
    </div>
  </div>
{:else}
  <PageLayout
    tenantName={t('admin.appName')}
    brand={adminBrand}
    wide
    banner={logoutError !== undefined ? banners : undefined}
    {footer}
    announcer={false}
  >
    {@render children()}
  </PageLayout>
{/if}
<Announcer />

<style>
  /* Height bounded, width following the ratio: a narrow header shrinks the logo without
     distorting it (base.css caps every image at max-width: 100%). */
  .tt-admin-logo {
    display: block;
    width: auto;
    height: auto;
    max-height: 3rem;
  }

  .tt-admin-logo--dark {
    display: none;
  }

  @media not print {
    :global([data-theme='dark']) .tt-admin-logo--light {
      display: none;
    }

    :global([data-theme='dark']) .tt-admin-logo--dark {
      display: block;
    }
  }

  /* Empty live region alone in the banner of the signed-out frame: kept in the DOM, out of the
     flow, so that it adds no gap above the card. */
  :global(.tt-page__banner:has(> .tt-admin-maintenance:only-child:empty)) {
    position: absolute;
  }
</style>
