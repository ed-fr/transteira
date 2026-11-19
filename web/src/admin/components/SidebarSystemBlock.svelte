<script lang="ts">
  // System block of the sidebar (super admin, CLAUDE.md section 13.2), nested under the "System"
  // entry of the main navigation on the system pages: a navigation landmark keeping the name of the
  // system navigation ("System administration", adminSystem.nav.label) with the links of
  // systemLinks (overview, maintenance, settings, webhooks, global audit and security logs, master
  // key, provisioning tokens). aria-current="page" marks the section shown, "true" its sub-pages;
  // the overview ("/system", parent of the other paths) is only marked on its exact page.
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from '../screens/types';
  import type { SidebarSystemBlock } from '../shell';

  interface Props {
    /** The block of the sidebar model. */
    block: SidebarSystemBlock;
    /** Router helpers. */
    nav: Pick<Navigation, 'href' | 'link'>;
  }

  let { block, nav }: Props = $props();
</script>

<nav class="tt-sidebar-system" aria-label={t('adminSystem.nav.label')}>
  <ul class="tt-list-plain tt-sidebar__sublist">
    {#each block.links as link (link.section)}
      <li>
        <a class="tt-sidebar__sublink" href={nav.href(link.path)} use:nav.link aria-current={link.current}>
          {t(link.labelKey)}
        </a>
      </li>
    {/each}
  </ul>
</nav>

<style>
  .tt-sidebar-system {
    margin: var(--tt-space-1) 0 var(--tt-space-2);
    padding-left: var(--tt-space-3);
  }
</style>
