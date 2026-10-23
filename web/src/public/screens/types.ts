// Props shared by every screen of the public application (rendered by App.svelte from the
// route table of routes.ts).
import type { Component } from 'svelte';
import type { Router } from '../../shared/router/router.svelte';
import type { PublicTenant } from '../bootstrap';

/** Navigation helpers handed to the screens (addGuard: confirm leaving during an upload). */
export type Navigation = Pick<Router, 'href' | 'link' | 'navigate' | 'addGuard'>;

/** Props of a public screen. */
export interface ScreenProps {
  /** Public configuration of the current tenant. */
  tenant: PublicTenant;
  /** Decoded route parameters (":token", ":document", ":topic"). */
  params: Record<string, string>;
  /** Router helpers (internal links with use:link). */
  nav: Navigation;
}

/** A public screen component. */
export type ScreenComponent = Component<ScreenProps>;
