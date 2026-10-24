// Props shared by every screen of the admin application.
import type { Component } from 'svelte';
import type { Router } from '../../shared/router/router.svelte';

/**
 * Navigation helpers handed to the screens (App passes the router itself). addGuard lets a
 * form confirm leaving the page with unsaved changes (FormSection, ActivationLinkPanel).
 */
export type Navigation = Pick<Router, 'href' | 'link' | 'navigate' | 'addGuard'>;

/** Registers a navigation guard and returns its removal (Router.addGuard). */
export type AddGuard = Navigation['addGuard'];

/** Props of an admin screen. */
export interface AdminScreenProps {
  /** Decoded route parameters. */
  params: Record<string, string>;
  /** Router helpers (internal links with use:link, base /admin; navigation guards). */
  nav: Navigation;
}

/** An admin screen component. */
export type AdminScreenComponent = Component<AdminScreenProps>;
