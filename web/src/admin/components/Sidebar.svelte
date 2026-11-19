<script lang="ts">
  // Sidebar of the administration (CLAUDE.md section 13.2; plan of step 3c), rendered by AdminShell
  // for a signed-in admin as the banner landmark (<header>): a dark green panel (its own palette,
  // the .tt-admin-sidebar block of tokens.css: text and focus #6ee7b7 at AA / 3:1 there).
  //
  // - The TransTeira logo (the PNG for dark backgrounds, alternative text "TransTeira"), a link to
  //   the home page.
  // - Under 60rem, a "Menu" button (aria-expanded, aria-controls) shows or hides the navigation and
  //   the user block, stacked above the content; it closes again after a navigation and on Escape
  //   pressed on the button or in the panel (the focus goes back to the button). From 60rem, the
  //   sidebar is a dark column of 248 px over the whole height of the page whose content box is
  //   sticky (the height of the window): the logo stays at the top and the user block at the
  //   bottom, always visible, and only the navigation between them scrolls when it is longer (the
  //   link of the page shown scrolled into view); the button is hidden.
  // - The main navigation (nav "Main navigation", admin.nav.label): icon and text links of
  //   sidebarModel (shell.ts), aria-current from navCurrent. Under "Entities", the tenant block
  //   (SidebarTenantBlock, nav "Configuration of the entity {name}"); under "System", the system
  //   block (SidebarSystemBlock, nav "System administration").
  // - The user block at the bottom: "Signed in as {username}", the role, and the "Sign out" button
  //   (a link button in #6ee7b7); AdminShell signs out and shows the errors.
  // The current link is marked by a white text on a lighter background, a bold weight and a green
  // bar on its left (a shape, so never colour alone; a system colour border in forced colours).
  // Every link and button is at least 44 px high.
  import { untrack } from 'svelte';
  import Button from '../../shared/components/Button.svelte';
  import Icon from '../../shared/components/Icon.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';
  import logoDark from '../brand/transteira-horizontal-dark.png';
  import type { AdminMe } from '../auth/machine';
  import type { Navigation } from '../screens/types';
  import { closesSidebarMenu, roleKey, sidebarModel } from '../shell';
  import SidebarSystemBlock from './SidebarSystemBlock.svelte';
  import SidebarTenantBlock from './SidebarTenantBlock.svelte';

  interface Props {
    /** Profile of the signed-in admin. */
    me: AdminMe;
    /** Current application path (aria-current, menu closed on change). */
    path: string;
    /** Tenant of the page shown (the :id of a tenant route), if any. */
    tenantId?: string | undefined;
    /** The page shown is a system page (routes with systemNav). */
    inSystem?: boolean;
    /** Router helpers. */
    nav: Pick<Navigation, 'href' | 'link'>;
    /** Sign-out in progress (loading state of the button). */
    signingOut?: boolean;
    /** Signs out (AdminShell). */
    onsignout: () => void;
  }

  let { me, path, tenantId, inSystem = false, nav, signingOut = false, onsignout }: Props = $props();

  /** Width from which the sidebar is a sticky column (the same breakpoint as styles/admin.css). */
  const WIDE_SCREEN = '(min-width: 60rem)';

  const uid = $props.id();
  const panelId = `${uid}-panel`;
  const model = $derived(sidebarModel(me, path, tenantId, inSystem));

  // Menu of narrow screens (in memory only).
  let menuOpen = $state(false);
  let toggleButton: HTMLButtonElement | undefined = $state();
  let inner: HTMLDivElement | undefined = $state();
  let panel: HTMLDivElement | undefined = $state();

  // Closed again after each navigation.
  $effect(() => {
    void path;
    untrack(() => {
      menuOpen = false;
    });
  });

  // From 60rem the navigation of the sticky column scrolls on its own: after each navigation, the
  // link of the page shown is scrolled into its view (under 60rem, the menu closes instead).
  $effect(() => {
    void model;
    if (panel === undefined || !window.matchMedia(WIDE_SCREEN).matches) {
      return;
    }
    panel.querySelector('[aria-current="page"]')?.scrollIntoView({ block: 'nearest' });
  });

  // Escape closes the menu when the focus is on its button (just opened) or in its panel.
  function onKeydown(event: KeyboardEvent): void {
    const focusInSidebar = inner !== undefined && inner.contains(document.activeElement);
    if (!closesSidebarMenu(event.key, menuOpen, focusInSidebar)) {
      return;
    }
    menuOpen = false;
    toggleButton?.focus();
  }
</script>

<svelte:window onkeydown={onKeydown} />

<header class="tt-admin-sidebar">
  <div class="tt-sidebar__inner" bind:this={inner}>
    <div class="tt-sidebar__bar">
      <a class="tt-sidebar__brand" href={nav.href('/')} use:nav.link>
        <img class="tt-sidebar__logo" src={logoDark} alt={t('common.appName')} width="524" height="144" />
      </a>
      <button
        type="button"
        class="tt-sidebar__toggle"
        aria-expanded={menuOpen ? 'true' : 'false'}
        aria-controls={panelId}
        bind:this={toggleButton}
        onclick={() => (menuOpen = !menuOpen)}
      >
        <Icon name={menuOpen ? 'x' : 'menu'} />
        <span>{t('admin.nav.menu')}</span>
      </button>
    </div>
    <div class="tt-sidebar__panel" class:tt-sidebar__panel--open={menuOpen} id={panelId} bind:this={panel}>
      <nav class="tt-sidebar__nav" aria-label={t('admin.nav.label')}>
        <ul class="tt-list-plain tt-sidebar__list">
          {#each model.entries as entry (entry.id)}
            <li>
              <a
                class="tt-sidebar__link"
                href={nav.href(entry.path)}
                use:nav.link
                aria-current={entry.current}
              >
                <Icon name={entry.icon} />
                <span>{t(entry.key)}</span>
              </a>
              {#if entry.tenant}
                <SidebarTenantBlock block={entry.tenant} role={me.role} {nav} />
              {/if}
              {#if entry.system}
                <SidebarSystemBlock block={entry.system} {nav} />
              {/if}
            </li>
          {/each}
        </ul>
      </nav>
      <div class="tt-sidebar__user">
        <p class="tt-sidebar__who tt-break">{t('admin.nav.signedInAs', { username: me.username })}</p>
        <p class="tt-sidebar__role">{t('admin.nav.roleOf', { role: t(roleKey(me.role)) })}</p>
        <Button
          variant="link"
          class="tt-sidebar__signout"
          loading={signingOut}
          loadingLabel={t('admin.nav.signingOut')}
          onclick={onsignout}
        >
          {t('admin.nav.signOut')}
        </Button>
      </div>
    </div>
  </div>
</header>

<style>
  /* The header spans the whole height of the frame (dark column); its inner box is sticky. */
  .tt-admin-sidebar {
    min-width: 0;
    border-right: var(--tt-border-width) solid var(--tt-sidebar-border);
    background: var(--tt-sidebar-bg);
    color: var(--tt-sidebar-text);
  }

  .tt-sidebar__inner {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-6);
    padding: var(--tt-space-5) 0.875rem;
  }

  .tt-sidebar__bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--tt-space-3);
  }

  .tt-sidebar__brand {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
    padding: 0 0.625rem;
    border-radius: 0.625rem;
  }

  .tt-sidebar__logo {
    display: block;
    width: auto;
    height: 2.25rem;
  }

  .tt-sidebar__toggle {
    display: none;
    align-items: center;
    gap: var(--tt-space-2);
    min-height: var(--tt-control-height);
    padding: 0 var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-sidebar-text);
    border-radius: 0.625rem;
    background: transparent;
    color: var(--tt-sidebar-strong);
    font-weight: var(--tt-font-weight-bold);
    cursor: pointer;
  }

  .tt-sidebar__panel {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: var(--tt-space-6);
  }

  .tt-sidebar__list {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }

  /* Links of the main navigation and of the nested blocks (SidebarTenantBlock, SidebarSystemBlock). */
  .tt-sidebar__link,
  .tt-admin-sidebar :global(.tt-sidebar__sublink) {
    display: flex;
    align-items: center;
    gap: var(--tt-space-3);
    min-height: var(--tt-control-height);
    padding: var(--tt-space-1) var(--tt-space-3);
    border-radius: 0.625rem;
    color: var(--tt-sidebar-text);
    font-size: 0.9375rem;
    font-weight: 500;
    line-height: var(--tt-line-height-tight);
    text-decoration: none;
  }

  .tt-admin-sidebar :global(.tt-sidebar__sublink) {
    font-size: var(--tt-font-size-sm);
  }

  .tt-sidebar__link:hover,
  .tt-admin-sidebar :global(.tt-sidebar__sublink:hover) {
    background: var(--tt-sidebar-raised-bg);
    color: var(--tt-sidebar-strong);
    text-decoration: underline;
    text-underline-offset: 0.2em;
  }

  /* Current link: white bold text on a lighter background and a green bar (shape) on its left. */
  .tt-sidebar__link[aria-current],
  .tt-admin-sidebar :global(.tt-sidebar__sublink[aria-current]) {
    padding-left: calc(var(--tt-space-3) - 3px);
    border-left: 3px solid var(--tt-sidebar-active-icon);
    background: var(--tt-sidebar-active-bg);
    color: var(--tt-sidebar-strong);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-sidebar__link[aria-current] :global(.tt-icon) {
    color: var(--tt-sidebar-active-icon);
  }

  .tt-admin-sidebar :global(.tt-sidebar__sublist) {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }

  /* A collapsed group: its list is hidden (the attribute would lose against display: flex). */
  .tt-admin-sidebar :global(.tt-sidebar__sublist[hidden]) {
    display: none;
  }

  .tt-sidebar__user {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--tt-space-1);
    margin-top: auto;
    padding: var(--tt-space-3);
    border-radius: 0.75rem;
    background: var(--tt-sidebar-raised-bg);
    font-size: 0.8125rem;
  }

  .tt-sidebar__user p {
    margin: 0;
  }

  .tt-sidebar__who {
    color: var(--tt-sidebar-strong);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-sidebar__role {
    color: var(--tt-sidebar-text);
  }

  .tt-sidebar__user :global(.tt-sidebar__signout) {
    justify-content: flex-start;
    color: var(--tt-sidebar-link);
    font-size: var(--tt-font-size-sm);
  }

  /*
   * Wide screens: a sticky box of the height of the window. The logo and the user block stay
   * visible; only the navigation between them scrolls when it is longer. Its padding (cancelled by
   * a negative margin) keeps the focus ring of its links (5 px around them) inside the scroll area.
   */
  @media (min-width: 60rem) {
    .tt-sidebar__inner {
      position: sticky;
      top: 0;
      box-sizing: border-box;
      height: 100vh;
      overflow: hidden;
    }

    .tt-sidebar__panel {
      min-height: 0;
    }

    .tt-sidebar__nav {
      flex: 1 1 auto;
      min-height: 0;
      margin: -0.375rem;
      padding: 0.375rem;
      overflow-y: auto;
    }

    .tt-sidebar__user {
      flex: none;
    }
  }

  /* Narrow screens: a bar with the logo and the menu button, the panel stacked above the content. */
  @media (max-width: 59.99rem) {
    .tt-admin-sidebar {
      border-right: 0;
      border-bottom: var(--tt-border-width) solid var(--tt-sidebar-border);
    }

    .tt-sidebar__inner {
      gap: var(--tt-space-3);
      padding: var(--tt-space-2) var(--tt-space-4);
    }

    .tt-sidebar__toggle {
      display: inline-flex;
    }

    .tt-sidebar__panel:not(.tt-sidebar__panel--open) {
      display: none;
    }

    .tt-sidebar__panel {
      padding-bottom: var(--tt-space-3);
    }
  }

  @media (forced-colors: active) {
    .tt-admin-sidebar {
      border-color: CanvasText;
    }

    .tt-sidebar__link[aria-current],
    .tt-admin-sidebar :global(.tt-sidebar__sublink[aria-current]) {
      border-left-color: Highlight;
    }

    .tt-sidebar__toggle {
      border-color: ButtonText;
    }
  }
</style>
