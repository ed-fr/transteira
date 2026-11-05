<script lang="ts">
  // Page frame of the administration: the shared PageLayout (wide card, default theme, no
  // tenant colours) with, once the admin is authenticated, the main navigation (Home, Entities,
  // Administrators and System for a super admin, My account; Home, Entities and My account only
  // for an auditor; aria-current on the current
  // section), the name and role of the admin and the sign-out button. The navigation is hidden
  // on the setup, sign-in and activation screens and during the intermediate sign-in steps.
  // While the admin is authenticated, the maintenance state is kept by adminMaintenance (read at
  // sign-in, on each navigation and when the tab is shown again; never on a timer, which would
  // keep the session alive, T-165) and a polite banner tells every admin that the maintenance
  // mode is on, with a link to the maintenance screen for the super admin. The live region
  // (role="status") is always rendered, empty without a banner, so that its content is announced.
  // Since 1.2, a super admin also sees a discreet notice when a newer release exists (no
  // automatic update: a link to the release page and the screen with the details).
  import { untrack, type Snippet } from 'svelte';
  import { problemMessage } from '../../shared/api/problem';
  import { Alert, Button, PageLayout } from '../../shared/components';
  import { formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import { adminSession } from '../api';
  import type { AdminMe } from '../auth/machine';
  import { adminMaintenance } from '../maintenance.svelte';
  import { maintenanceBanner, maintenanceBannerText } from '../maintenanceBanner';
  import type { Navigation } from '../screens/types';
  import { isAuditor, mainLinks, navCurrent, roleKey, systemPath } from '../shell';
  import { updateNotice } from '../version';
  import { adminVersion } from '../version.svelte';

  interface Props {
    /** Profile of the authenticated admin; the navigation is hidden without it. */
    me: AdminMe | undefined;
    /** Shows the navigation (authenticated state, screen rendered). */
    showNav: boolean;
    /** Current application path (aria-current). */
    path: string;
    /** Router helpers. */
    nav: Navigation;
    /** Footer (Footer.svelte). */
    footer?: Snippet;
    /** Page content. */
    children: Snippet;
  }

  let { me, showNav, path, nav, footer, children }: Props = $props();

  let signingOut = $state(false);
  let logoutError = $state<string | undefined>(undefined);

  const links = $derived(mainLinks(me?.role));

  // Maintenance state: kept while an admin is authenticated (not during the sign-in steps),
  // forgotten on sign-out and when the layout is destroyed.
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
  const showBanner = $derived(showNav && me !== undefined && banner.visible);
  const bannerText = $derived(
    maintenanceBannerText(banner, t, (iso) => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' })),
  );

  const update = $derived(updateNotice(isSuperAdmin ? adminVersion.system : undefined));

  async function signOut(): Promise<void> {
    signingOut = true;
    logoutError = undefined;
    try {
      await adminSession.logout();
      await nav.navigate('/login', { replace: true });
    } catch (err) {
      logoutError = problemMessage(i18n, err);
    } finally {
      signingOut = false;
    }
  }
</script>

{#snippet adminHeader()}
  {#if me}
    <div class="tt-admin-header">
      <nav aria-label={t('admin.nav.label')}>
        <ul class="tt-list-plain tt-admin-nav">
          {#each links as link (link.path)}
            <li>
              <a href={nav.href(link.path)} use:nav.link aria-current={navCurrent(path, link.path)}>
                {t(link.key)}
              </a>
            </li>
          {/each}
        </ul>
      </nav>
      <div class="tt-admin-user">
        <p class="tt-mb-0 tt-text-sm">
          <span class="tt-break">{t('admin.nav.signedInAs', { username: me.username })}</span>
          <span class="tt-admin-user__role tt-text-muted">
            {t('admin.nav.roleOf', { role: t(roleKey(me.role)) })}
          </span>
        </p>
        <Button
          variant="secondary"
          small
          loading={signingOut}
          loadingLabel={t('admin.nav.signingOut')}
          onclick={() => void signOut()}
        >
          {t('admin.nav.signOut')}
        </Button>
      </div>
    </div>
  {/if}
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
  {#if showNav && me !== undefined && update.visible}
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

<PageLayout
  tenantName={t('admin.appName')}
  wide
  header={showNav && me ? adminHeader : undefined}
  banner={(showNav && me) || logoutError !== undefined ? banners : undefined}
  {footer}
>
  {@render children()}
</PageLayout>

<style>
  .tt-admin-header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: var(--tt-space-3) var(--tt-space-6);
  }

  .tt-admin-nav {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2) var(--tt-space-4);
  }

  .tt-admin-nav a {
    display: inline-block;
    padding: var(--tt-space-1) 0;
    color: var(--tt-link);
  }

  .tt-admin-nav a[aria-current] {
    font-weight: var(--tt-font-weight-bold);
    text-decoration-thickness: 0.2em;
  }

  .tt-admin-user {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-3);
  }

  .tt-admin-maintenance:not(:empty):not(:last-child) {
    margin-bottom: var(--tt-space-3);
  }

  /* Empty live region alone: kept in the DOM (so that a banner is announced when it appears)
     but out of the flow, so that it adds no gap above the card. */
  :global(.tt-page__banner:has(> .tt-admin-maintenance:only-child:empty)) {
    position: absolute;
  }

  .tt-admin-user__role {
    display: block;
  }
</style>
