<script lang="ts">
  // Sub-navigation of the system administration (super admin): overview, maintenance, settings,
  // webhooks, global audit log and master key. aria-current="page" marks the section shown,
  // "true" its sub-pages; the overview ("/system", parent of the other paths) is only marked on
  // its exact page. Rendered by App.svelte above every /system screen (routes with systemNav).
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from '../screens/types';
  import { navCurrent, systemLinks } from '../shell';

  interface Props {
    /** Current application path. */
    path: string;
    /** Router helpers. */
    nav: Navigation;
  }

  let { path, nav }: Props = $props();

  const links = systemLinks();
</script>

<nav class="tt-system-nav" aria-label={t('adminSystem.nav.label')}>
  <ul class="tt-list-plain tt-system-nav__links">
    {#each links as link (link.section)}
      <li>
        <a href={nav.href(link.path)} use:nav.link aria-current={navCurrent(path, link.path, link.exact)}>
          {t(link.labelKey)}
        </a>
      </li>
    {/each}
  </ul>
</nav>

<style>
  .tt-system-nav {
    margin-bottom: var(--tt-space-6);
    padding-bottom: var(--tt-space-3);
    border-bottom: var(--tt-border-width) solid var(--tt-border);
  }

  .tt-system-nav__links {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2) var(--tt-space-4);
  }

  .tt-system-nav__links a {
    display: inline-block;
    padding: var(--tt-space-1) 0;
  }

  .tt-system-nav__links a[aria-current] {
    font-weight: var(--tt-font-weight-bold);
    text-decoration-thickness: 0.2em;
  }
</style>
