// Client-side router of the two applications (History API, no hash routing).
//
// - A route table {pattern, component, titleKey, helpTopic}; patterns are literal segments and
//   ":name" parameters ("/d/:token"); an unmatched path gives the notFound route.
// - Optional base path: the admin application lives under "/admin", its routes are written
//   without it ("/tenants/:id") and href() adds it back.
// - Only links marked with the `link` action are intercepted; every other link is a normal
//   browser navigation.
// - After each navigation (not on the first render): document.title, focus on the page
//   heading (h1 with tabindex="-1"), scroll to the top, polite announcement of the new page.
//   The title is also set on the first render.
// - Navigation guards (addGuard) may refuse an in-app navigation (a link, navigate(), back or
//   forward), for example to confirm leaving a page during an upload. A refused back/forward
//   navigation pushes the current URL back, so the address bar keeps matching the page.
//   navigate(path, { force: true }) bypasses the guards: only for redirects the user cannot
//   refuse (session expired, signed out, access lost), never for a user navigation.
// Browser objects are injected (RouterEnv) so that the router is testable in Node.
import { tick } from 'svelte';
import { t as translate } from '../i18n/i18n.svelte';

/**
 * State of the history entries added by the router (pushState). An entry carrying it was created
 * by an in-app navigation, so the previous entry belongs to the same application: the help uses
 * it to offer "back to the previous screen" (isRouterEntry(history.state)).
 */
export const ROUTER_ENTRY: Readonly<{ tt: 'router' }> = Object.freeze({ tt: 'router' });

/** Reports whether a history state (history.state) is one of ROUTER_ENTRY. */
export function isRouterEntry(state: unknown): boolean {
  return typeof state === 'object' && state !== null && (state as { tt?: unknown }).tt === 'router';
}

/** One entry of the route table. */
export interface Route<C = unknown> {
  /** Path pattern, for example "/", "/d/:token", "/legal/:document". */
  pattern: string;
  /** Screen component rendered for this route. */
  component: C;
  /** Translation key of the page title. */
  titleKey: string;
  /** Topic of the integrated help for this screen (step 17). */
  helpTopic?: string;
}

/** The current location resolved against the route table. */
export interface RouteMatch<C = unknown> {
  route: Route<C>;
  /** Decoded ":name" parameters. */
  params: Record<string, string>;
  /** Application path (without the base path). */
  path: string;
  /** Query string, including "?" when present. */
  search: string;
  /** Fragment, including "#" when present. */
  hash: string;
}

/** Browser dependencies of the router. */
export interface RouterEnv {
  location: { readonly pathname: string; readonly search: string; readonly hash: string };
  /** state: the state of the current entry (history.state), kept by a replacing navigation. */
  history: Pick<History, 'pushState' | 'replaceState'> & { readonly state?: unknown };
  addEventListener(type: 'popstate', listener: () => void): void;
  removeEventListener(type: 'popstate', listener: () => void): void;
  document?: {
    title: string;
    querySelector(selector: string): { focus(options?: FocusOptions): void } | null;
  };
  scrollTo?(x: number, y: number): void;
  /** Origin of the page, to recognise same-origin links (window.location.origin). */
  origin?: string;
}

/** Options of a router. */
export interface RouterOptions<C> {
  routes: readonly Route<C>[];
  /** Route rendered when no pattern matches. */
  notFound: Route<C>;
  /** Base path of the application ("/admin"), default "". */
  base?: string;
  /** Browser dependencies, default window. */
  env?: RouterEnv;
  /** Builds document.title, default t(route.titleKey). */
  title?: (match: RouteMatch<C>) => string;
  /** Polite announcement of a navigation (an aria-live region), called with the message. */
  announce?: (message: string) => void;
  /** Translation function, default the shared t(). */
  t?: (key: string, params?: Record<string, string | number>) => string;
  /** Waits for the DOM update before focusing, default svelte tick(). */
  afterRender?: () => Promise<void>;
}

/** Navigation options. */
export interface NavigateOptions {
  /** Replace the history entry instead of adding one. */
  replace?: boolean;
  /**
   * Bypass the navigation guards. Only for access-driven redirects (session expired, logout,
   * access change), which a leave guard must not be able to refuse.
   */
  force?: boolean;
}

/**
 * Called before an in-app navigation with the target application path; false refuses it.
 * A guard may ask the user (window.confirm) before answering.
 */
export type NavigationGuard = (path: string) => boolean;

/** A router instance. `current` is reactive. */
export interface Router<C = unknown> {
  readonly current: RouteMatch<C>;
  /** Base path of the application. */
  readonly base: string;
  /** Navigates to an application path ("/d/abc?x=1"), without the base path. */
  navigate(path: string, options?: NavigateOptions): Promise<void>;
  /** Full URL path of an application path (adds the base path). */
  href(path: string): string;
  /** Listens to back/forward navigation and sets the initial title. */
  start(): void;
  /** Stops listening. */
  stop(): void;
  /** Adds a navigation guard; returns the function that removes it. */
  addGuard(guard: NavigationGuard): () => void;
  /** Svelte action for internal links: <a href={router.href('/x')} use:link>. */
  link: (node: LinkNode) => { destroy(): void };
}

/** The parts of an anchor element the link action uses. */
export interface LinkNode {
  getAttribute(name: string): string | null;
  hasAttribute(name: string): boolean;
  addEventListener(type: 'click', listener: (event: LinkClick) => void): void;
  removeEventListener(type: 'click', listener: (event: LinkClick) => void): void;
}

/** The parts of a click event the link action uses. */
export interface LinkClick {
  defaultPrevented: boolean;
  button: number;
  metaKey: boolean;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  preventDefault(): void;
}

type Matcher = (path: string) => Record<string, string> | undefined;

function splitPath(path: string): string[] {
  return path.split('/').filter((s) => s !== '');
}

/** Compiles a route pattern to a matcher returning the decoded parameters. */
export function compilePattern(pattern: string): Matcher {
  const segments = splitPath(pattern);
  return (path) => {
    const parts = splitPath(path);
    if (parts.length !== segments.length) {
      return undefined;
    }
    const params: Record<string, string> = {};
    for (const [i, segment] of segments.entries()) {
      const part = parts[i] as string;
      if (segment.startsWith(':')) {
        let value: string;
        try {
          value = decodeURIComponent(part);
        } catch {
          return undefined;
        }
        params[segment.slice(1)] = value;
      } else if (segment !== part) {
        return undefined;
      }
    }
    return params;
  };
}

/** Normalises a base path: "" or "/admin" (leading slash, no trailing slash). */
export function normalizeBase(base: string | undefined): string {
  const trimmed = (base ?? '').replace(/\/+$/, '');
  return trimmed === '' ? '' : trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

/** Strips the base path from a URL path; undefined when the path is outside the base. */
export function stripBase(base: string, pathname: string): string | undefined {
  if (base === '') {
    return pathname || '/';
  }
  if (pathname === base) {
    return '/';
  }
  return pathname.startsWith(`${base}/`) ? pathname.slice(base.length) : undefined;
}

/** Resolves a path against a route table. */
export function matchRoutes<C>(
  routes: readonly Route<C>[],
  notFound: Route<C>,
  path: string | undefined,
): { route: Route<C>; params: Record<string, string> } {
  if (path !== undefined) {
    for (const route of routes) {
      const params = compilePattern(route.pattern)(path);
      if (params !== undefined) {
        return { route, params };
      }
    }
  }
  return { route: notFound, params: {} };
}

function splitUrl(url: string): { pathname: string; search: string; hash: string } {
  const hashAt = url.indexOf('#');
  const hash = hashAt === -1 ? '' : url.slice(hashAt);
  const rest = hashAt === -1 ? url : url.slice(0, hashAt);
  const searchAt = rest.indexOf('?');
  return {
    pathname: searchAt === -1 ? rest : rest.slice(0, searchAt),
    search: searchAt === -1 ? '' : rest.slice(searchAt),
    hash,
  };
}

function browserEnv(): RouterEnv {
  return {
    location: window.location,
    history: window.history,
    addEventListener: (type, listener) => window.addEventListener(type, listener),
    removeEventListener: (type, listener) => window.removeEventListener(type, listener),
    document,
    scrollTo: (x, y) => window.scrollTo(x, y),
    origin: window.location.origin,
  };
}

/** Creates a router. */
export function createRouter<C>(options: RouterOptions<C>): Router<C> {
  const env = options.env ?? browserEnv();
  const base = normalizeBase(options.base);
  const t = options.t ?? translate;
  const afterRender = options.afterRender ?? tick;
  const titleOf = options.title ?? ((m: RouteMatch<C>) => t(m.route.titleKey));

  function resolve(pathname: string, search: string, hash: string): RouteMatch<C> {
    const path = stripBase(base, pathname);
    const { route, params } = matchRoutes(options.routes, options.notFound, path);
    return { route, params, path: path ?? pathname, search, hash };
  }

  const location = env.location;
  let current = $state.raw<RouteMatch<C>>(resolve(location.pathname, location.search, location.hash));

  function setTitle(): string {
    const title = titleOf(current);
    if (env.document !== undefined) {
      env.document.title = title;
    }
    return title;
  }

  async function afterNavigation(): Promise<void> {
    const title = setTitle();
    await afterRender();
    env.scrollTo?.(0, 0);
    env.document?.querySelector('h1[tabindex="-1"]')?.focus({ preventScroll: true });
    options.announce?.(t('common.navigation.pageLoaded', { title }));
  }

  // A plain array: the guards are not reactive state.
  let guards: NavigationGuard[] = [];

  function allowed(path: string): boolean {
    for (const guard of guards) {
      if (!guard(path)) return false;
    }
    return true;
  }

  function onPopState(): void {
    const next = resolve(env.location.pathname, env.location.search, env.location.hash);
    if (!allowed(next.path + next.search + next.hash)) {
      // The browser already shows the new URL: put the current one back.
      env.history.pushState(ROUTER_ENTRY, '', href(current.path) + current.search + current.hash);
      return;
    }
    current = next;
    void afterNavigation();
  }

  function href(path: string): string {
    const normalized = path.startsWith('/') ? path : `/${path}`;
    return base === '' ? normalized : normalized === '/' ? `${base}/` : base + normalized;
  }

  async function navigate(path: string, navOptions: NavigateOptions = {}): Promise<void> {
    if (navOptions.force !== true && !allowed(path)) {
      return;
    }
    const url = href(path);
    const parts = splitUrl(url);
    const same =
      parts.pathname === env.location.pathname &&
      parts.search === env.location.search &&
      parts.hash === env.location.hash;
    if (navOptions.replace === true || same) {
      // A replaced entry keeps its origin: one added by the router stays a router entry.
      env.history.replaceState(isRouterEntry(env.history.state) ? ROUTER_ENTRY : null, '', url);
    } else {
      env.history.pushState(ROUTER_ENTRY, '', url);
    }
    current = resolve(parts.pathname, parts.search, parts.hash);
    await afterNavigation();
  }

  /** Application path of an internal link href, or undefined when the link is not internal. */
  function internalPath(raw: string | null): string | undefined {
    if (raw === null) {
      return undefined;
    }
    let value = raw;
    if (env.origin !== undefined && value.startsWith(`${env.origin}/`)) {
      value = value.slice(env.origin.length);
    }
    if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
      return undefined;
    }
    const parts = splitUrl(value);
    const path = stripBase(base, parts.pathname);
    return path === undefined ? undefined : path + parts.search + parts.hash;
  }

  function link(node: LinkNode): { destroy(): void } {
    const onClick = (event: LinkClick): void => {
      if (event.defaultPrevented || event.button !== 0) {
        return;
      }
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
        return;
      }
      const target = node.getAttribute('target');
      if ((target !== null && target !== '' && target !== '_self') || node.hasAttribute('download')) {
        return;
      }
      const path = internalPath(node.getAttribute('href'));
      if (path === undefined) {
        return;
      }
      event.preventDefault();
      void navigate(path);
    };
    node.addEventListener('click', onClick);
    return {
      destroy() {
        node.removeEventListener('click', onClick);
      },
    };
  }

  return {
    get current() {
      return current;
    },
    base,
    navigate,
    href,
    start() {
      env.addEventListener('popstate', onPopState);
      setTitle();
    },
    stop() {
      env.removeEventListener('popstate', onPopState);
    },
    addGuard(guard) {
      guards = [...guards, guard];
      return () => {
        guards = guards.filter((g) => g !== guard);
      };
    },
    link,
  };
}
