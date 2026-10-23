// Props shared by every screen of the admin application.
import type { Component } from 'svelte';
import type { Router } from '../../shared/router/router.svelte';

/** Navigation helpers handed to the screens. */
export type Navigation = Pick<Router, 'href' | 'link' | 'navigate'>;

/** Props of an admin screen. */
export interface AdminScreenProps {
  /** Decoded route parameters. */
  params: Record<string, string>;
  /** Router helpers (internal links with use:link, base /admin). */
  nav: Navigation;
}

/** An admin screen component. */
export type AdminScreenComponent = Component<AdminScreenProps>;
