<script lang="ts">
  // Tenant block of the sidebar (CLAUDE.md section 13.2), nested under the "Entities" entry of the
  // main navigation: a navigation landmark named "Configuration of the entity {name}"
  // (admin.nav.tenantNav), the tenant name with the "being set up" badge while its setup is not
  // finished (never for an auditor, who cannot read the setup), then its groups of links
  // (sidebarModel in shell.ts): Configuration and Operations, or the single Consultation group of
  // an auditor. Each group is a disclosure button (aria-expanded, aria-controls) over a list named
  // by the button text. Groups are open by default; a group the admin collapses stays collapsed
  // in memory only (never in a browser storage), and the group of the page shown opens again on
  // each navigation to it (revealCurrentGroups). aria-current: "page" on the section shown,
  // "true" on its sub-pages.
  import { untrack } from 'svelte';
  import Icon from '../../shared/components/Icon.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from '../screens/types';
  import { setupStates } from '../setupStates.svelte';
  import {
    isAuditor,
    isGroupOpen,
    revealCurrentGroups,
    toggleGroup,
    type CollapsedGroups,
    type NavRole,
    type SidebarTenantBlock,
  } from '../shell';
  import StatusBadge from './StatusBadge.svelte';

  interface Props {
    /** The block of the sidebar model. */
    block: SidebarTenantBlock;
    /** Role of the admin (no setup badge for an auditor). */
    role: NavRole;
    /** Router helpers. */
    nav: Pick<Navigation, 'href' | 'link'>;
  }

  let { block, role, nav }: Props = $props();

  // Unique prefix of the ids of the group buttons and lists.
  const uid = $props.id();
  let collapsed = $state.raw<CollapsedGroups>(new Set());

  // On each navigation (new model), the group holding the page shown is opened; a group the
  // admin collapses afterwards stays collapsed until the next navigation (collapsed untracked).
  $effect.pre(() => {
    const groups = block.groups;
    untrack(() => {
      const next = revealCurrentGroups(collapsed, groups);
      if (next !== collapsed) {
        collapsed = next;
      }
    });
  });

  // The "being set up" badge needs the setup state, read once per tenant shown.
  $effect(() => {
    if (!isAuditor(role)) {
      void setupStates.ensure(block.tenantId);
    }
  });
  const inSetup = $derived(!isAuditor(role) && setupStates.stateOf(block.tenantId) === 'setup');
</script>

<nav class="tt-sidebar-tenant" aria-label={t('admin.nav.tenantNav', { name: block.name })}>
  <p class="tt-sidebar-tenant__name">
    <span class="tt-break">{block.name}</span>
    {#if inSetup}
      <StatusBadge variant="warning" label={t('setup.state.setup')} />
    {/if}
  </p>
  {#each block.groups as group (group.group)}
    {@const open = isGroupOpen(collapsed, group.group)}
    {@const buttonId = `${uid}-${group.group}-button`}
    {@const listId = `${uid}-${group.group}-links`}
    <div class="tt-sidebar-group">
      <button
        type="button"
        id={buttonId}
        class="tt-sidebar-group__toggle"
        aria-expanded={open ? 'true' : 'false'}
        aria-controls={listId}
        onclick={() => (collapsed = toggleGroup(collapsed, group.group))}
      >
        <span>{t(group.labelKey)}</span>
        <Icon name="chevron" size="sm" class={open ? 'tt-sidebar-group__chevron--open' : ''} />
      </button>
      <ul id={listId} class="tt-list-plain tt-sidebar__sublist" aria-labelledby={buttonId} hidden={!open}>
        {#each group.links as link (link.section)}
          <li>
            <a
              class="tt-sidebar__sublink"
              href={nav.href(link.path)}
              use:nav.link
              aria-current={link.current}
            >
              {t(link.labelKey)}
            </a>
          </li>
        {/each}
      </ul>
    </div>
  {/each}
</nav>

<style>
  .tt-sidebar-tenant {
    margin: var(--tt-space-1) 0 var(--tt-space-2);
    padding-left: var(--tt-space-3);
  }

  .tt-sidebar-tenant__name {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-1) var(--tt-space-2);
    margin: var(--tt-space-2) 0 var(--tt-space-1);
    padding: 0 var(--tt-space-3);
    color: var(--tt-sidebar-strong);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-sidebar-group__toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--tt-space-2);
    width: 100%;
    min-height: var(--tt-control-height);
    padding: 0 var(--tt-space-3);
    border: 0;
    border-radius: 0.625rem;
    background: transparent;
    color: var(--tt-sidebar-muted);
    font-size: 0.75rem;
    font-weight: var(--tt-font-weight-bold);
    letter-spacing: 0.04em;
    text-align: left;
    text-transform: uppercase;
    cursor: pointer;
  }

  .tt-sidebar-group__toggle:hover {
    background: var(--tt-sidebar-raised-bg);
    color: var(--tt-sidebar-strong);
  }

  /* Closed: the chevron points to the right; open: down. */
  .tt-sidebar-group__toggle :global(.tt-icon) {
    transform: rotate(-90deg);
  }

  .tt-sidebar-group__toggle :global(.tt-sidebar-group__chevron--open) {
    transform: none;
  }

  @media (forced-colors: active) {
    .tt-sidebar-group__toggle {
      color: ButtonText;
    }
  }
</style>
