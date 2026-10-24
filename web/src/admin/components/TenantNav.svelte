<script lang="ts">
  // Sub-navigation of a tenant: the tenant name, then two titled groups of links, configuration
  // (general, branding, network, SMTP, templates, legal) and operations (transfers, invitations,
  // blocklist, API tokens, audit, statistics, privacy). Each group is a list labelled by its
  // heading. aria-current="page" marks the section shown, "true" its sub-pages (template or legal
  // editor, transfer detail, token creation). Rendered by App.svelte above every
  // /tenants/:id/... screen.
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from '../screens/types';
  import { navCurrent, tenantLinkGroups } from '../shell';

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
  const groups = $derived(tenantLinkGroups(tenantId));
  // Unique prefix of the group heading ids (several navigations could share a page).
  const uid = $props.id();
</script>

<nav class="tt-tenant-nav" aria-label={t('admin.nav.tenantNav', { name })}>
  <p class="tt-tenant-nav__name tt-text-bold tt-break">{name}</p>
  <div class="tt-tenant-nav__groups">
    {#each groups as group (group.group)}
      {@const headingId = `${uid}-${group.group}`}
      <div class="tt-tenant-nav__group">
        <p id={headingId} class="tt-tenant-nav__group-title">{t(group.labelKey)}</p>
        <ul class="tt-list-plain tt-tenant-nav__links" aria-labelledby={headingId}>
          {#each group.links as link (link.section)}
            <li>
              <a href={nav.href(link.path)} use:nav.link aria-current={navCurrent(path, link.path)}>
                {t(link.labelKey)}
              </a>
            </li>
          {/each}
        </ul>
      </div>
    {/each}
  </div>
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

  .tt-tenant-nav__groups {
    display: grid;
    gap: var(--tt-space-2);
  }

  .tt-tenant-nav__group {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: var(--tt-space-1) var(--tt-space-4);
  }

  .tt-tenant-nav__group-title {
    margin: 0;
    min-width: 8rem;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-bold);
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
