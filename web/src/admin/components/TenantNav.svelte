<script lang="ts">
  // Sub-navigation of the configuration of a tenant: the tenant name, then links to its sections
  // (general, branding, network, SMTP, templates, legal). aria-current="page" marks the section
  // shown, "true" its sub-pages (template or legal editor). Rendered by App.svelte above every
  // /tenants/:id/... screen.
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from '../screens/types';
  import { navCurrent, tenantLinks } from '../shell';

  interface Props {
    /** Tenant id (route parameter). */
    tenantId: string;
    /** Tenant name (from the admin profile); the id is shown when unknown. */
    tenantName?: string | undefined;
    /** Current application path. */
    path: string;
    /** Router helpers. */
    nav: Navigation;
  }

  let { tenantId, tenantName, path, nav }: Props = $props();

  const name = $derived(tenantName ?? tenantId);
  const links = $derived(tenantLinks(tenantId));
</script>

<nav class="tt-tenant-nav" aria-label={t('admin.nav.tenantNav', { name })}>
  <p class="tt-tenant-nav__name tt-text-bold tt-break">{name}</p>
  <ul class="tt-list-plain tt-tenant-nav__links">
    {#each links as link (link.section)}
      <li>
        <a href={nav.href(link.path)} use:nav.link aria-current={navCurrent(path, link.path)}>
          {t(link.labelKey)}
        </a>
      </li>
    {/each}
  </ul>
</nav>

<style>
  .tt-tenant-nav {
    margin-bottom: var(--tt-space-6);
    padding-bottom: var(--tt-space-3);
    border-bottom: var(--tt-border-width) solid var(--tt-border);
  }

  .tt-tenant-nav__name {
    margin: 0 0 var(--tt-space-2);
  }

  .tt-tenant-nav__links {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2) var(--tt-space-4);
  }

  .tt-tenant-nav__links a {
    display: inline-block;
    padding: var(--tt-space-1) 0;
  }

  .tt-tenant-nav__links a[aria-current] {
    font-weight: var(--tt-font-weight-bold);
    text-decoration-thickness: 0.2em;
  }
</style>
