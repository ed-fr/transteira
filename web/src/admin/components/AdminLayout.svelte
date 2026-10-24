<script lang="ts">
  // Page frame of the administration: the shared PageLayout (wide card, default theme, no
  // tenant colours) with, once the admin is authenticated, the main navigation (Home, Entities,
  // Administrators for a super admin, My account; aria-current on the current section), the
  // name and role of the admin and the sign-out button. The navigation is hidden on the setup,
  // sign-in and activation screens and during the intermediate sign-in steps.
  import type { Snippet } from 'svelte';
  import { problemMessage } from '../../shared/api/problem';
  import { Alert, Button, PageLayout } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { adminSession } from '../api';
  import type { AdminMe } from '../auth/machine';
  import type { Navigation } from '../screens/types';
  import { navCurrent, roleKey } from '../shell';

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

  const links = $derived.by(() => {
    const items = [
      { path: '/', key: 'admin.nav.home' },
      { path: '/tenants', key: 'admin.nav.tenants' },
    ];
    if (me?.role === 'super_admin') {
      items.push({ path: '/admins', key: 'admin.nav.admins' });
    }
    items.push({ path: '/account', key: 'admin.nav.account' });
    return items;
  });

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

{#snippet logoutBanner()}
  <Alert severity="error" ondismiss={() => (logoutError = undefined)}>
    <p>{logoutError}</p>
  </Alert>
{/snippet}

<PageLayout
  tenantName={t('admin.appName')}
  wide
  header={showNav && me ? adminHeader : undefined}
  banner={logoutError === undefined ? undefined : logoutBanner}
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

  .tt-admin-user__role {
    display: block;
  }
</style>
