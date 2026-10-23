import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  compilePattern,
  createRouter,
  matchRoutes,
  normalizeBase,
  stripBase,
  type LinkClick,
  type LinkNode,
  type Route,
  type RouterEnv,
} from './router.svelte';

const home: Route<string> = {
  pattern: '/',
  component: 'Home',
  titleKey: 'deposit.title',
  helpTopic: 'deposit',
};
const download: Route<string> = { pattern: '/d/:token', component: 'Download', titleKey: 'download.title' };
const legal: Route<string> = { pattern: '/legal/:document', component: 'Legal', titleKey: 'legal.title' };
const notFound: Route<string> = { pattern: '*', component: 'NotFound', titleKey: 'common.notFound.title' };
const routes = [home, download, legal];

function fakeEnv(url = '/') {
  const listeners = new Set<() => void>();
  const focus = vi.fn();
  const heading = { focus } as { focus: typeof focus } | null;
  const env = {
    location: { pathname: '/', search: '', hash: '' },
    history: {
      pushState: vi.fn((_s: unknown, _u: string, next?: string | URL | null) => setUrl(String(next))),
      replaceState: vi.fn((_s: unknown, _u: string, next?: string | URL | null) => setUrl(String(next))),
    },
    addEventListener: vi.fn((_t: 'popstate', l: () => void) => listeners.add(l)),
    removeEventListener: vi.fn((_t: 'popstate', l: () => void) => listeners.delete(l)),
    document: { title: '', querySelector: vi.fn((_s: string) => heading) },
    scrollTo: vi.fn(),
    origin: 'https://transfer.entity-a.example.com',
  } satisfies RouterEnv;
  function setUrl(next: string): void {
    const u = new URL(next, 'https://transfer.entity-a.example.com');
    env.location.pathname = u.pathname;
    env.location.search = u.search;
    env.location.hash = u.hash;
  }
  setUrl(url);
  return {
    env,
    focus,
    listeners,
    pop(next: string) {
      setUrl(next);
      for (const l of listeners) l();
    },
  };
}

const t = (key: string, params?: Record<string, string | number>) =>
  params === undefined ? `[${key}]` : `[${key}|${Object.values(params).join(',')}]`;
const afterRender = () => Promise.resolve();

function fakeLink(attrs: Record<string, string>) {
  let handler: ((e: LinkClick) => void) | undefined;
  const node: LinkNode = {
    getAttribute: (name) => attrs[name] ?? null,
    hasAttribute: (name) => name in attrs,
    addEventListener: (_type, l) => {
      handler = l;
    },
    removeEventListener: () => {
      handler = undefined;
    },
  };
  return {
    node,
    click(init: Partial<LinkClick> = {}) {
      const event = {
        defaultPrevented: false,
        button: 0,
        metaKey: false,
        ctrlKey: false,
        shiftKey: false,
        altKey: false,
        preventDefault: vi.fn(),
        ...init,
      };
      handler?.(event);
      return event;
    },
    get attached() {
      return handler !== undefined;
    },
  };
}

describe('patterns', () => {
  it('matches literal segments and decodes parameters', () => {
    const m = compilePattern('/d/:token');
    expect(m('/d/abc')).toEqual({ token: 'abc' });
    expect(m('/d/a%20b')).toEqual({ token: 'a b' });
    expect(m('/d/abc/')).toEqual({ token: 'abc' });
    expect(m('/d')).toBeUndefined();
    expect(m('/d/a/b')).toBeUndefined();
    expect(m('/x/abc')).toBeUndefined();
    expect(m('/d/%E0%A4%A')).toBeUndefined();
    expect(compilePattern('/')('/')).toEqual({});
    expect(compilePattern('/')('')).toEqual({});
  });

  it('normalises and strips base paths', () => {
    expect(normalizeBase(undefined)).toBe('');
    expect(normalizeBase('/')).toBe('');
    expect(normalizeBase('admin/')).toBe('/admin');
    expect(normalizeBase('/admin')).toBe('/admin');
    expect(stripBase('', '/x')).toBe('/x');
    expect(stripBase('', '')).toBe('/');
    expect(stripBase('/admin', '/admin')).toBe('/');
    expect(stripBase('/admin', '/admin/')).toBe('/');
    expect(stripBase('/admin', '/admin/tenants/1')).toBe('/tenants/1');
    expect(stripBase('/admin', '/administrator')).toBeUndefined();
    expect(stripBase('/admin', '/d/x')).toBeUndefined();
  });

  it('resolves the first matching route or notFound', () => {
    expect(matchRoutes(routes, notFound, '/legal/privacy-policy')).toEqual({
      route: legal,
      params: { document: 'privacy-policy' },
    });
    expect(matchRoutes(routes, notFound, '/nope').route).toBe(notFound);
    expect(matchRoutes(routes, notFound, undefined).route).toBe(notFound);
  });
});

describe('createRouter', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('resolves the initial location and sets the title on start', () => {
    const { env } = fakeEnv('/d/tok?x=1#k=v');
    const router = createRouter({ routes, notFound, env, t, afterRender });
    expect(router.current.route).toBe(download);
    expect(router.current.params).toEqual({ token: 'tok' });
    expect(router.current.path).toBe('/d/tok');
    expect(router.current.search).toBe('?x=1');
    expect(router.current.hash).toBe('#k=v');
    router.start();
    expect(env.document.title).toBe('[download.title]');
    expect(env.addEventListener).toHaveBeenCalledWith('popstate', expect.any(Function));
    // No focus or announcement on the first render.
    expect(env.scrollTo).not.toHaveBeenCalled();
  });

  it('navigates: pushes history, sets title, scrolls, focuses the heading and announces', async () => {
    const { env, focus } = fakeEnv('/');
    const announce = vi.fn();
    const router = createRouter({ routes, notFound, env, t, afterRender, announce });
    await router.navigate('/legal/legal-notice');
    expect(env.history.pushState).toHaveBeenCalledWith(null, '', '/legal/legal-notice');
    expect(router.current.route).toBe(legal);
    expect(router.current.params).toEqual({ document: 'legal-notice' });
    expect(env.document.title).toBe('[legal.title]');
    expect(env.scrollTo).toHaveBeenCalledWith(0, 0);
    expect(env.document.querySelector).toHaveBeenCalledWith('h1[tabindex="-1"]');
    expect(focus).toHaveBeenCalledWith({ preventScroll: true });
    expect(announce).toHaveBeenCalledWith('[common.navigation.pageLoaded|[legal.title]]');
  });

  it('replaces history on request or for the same URL', async () => {
    const { env } = fakeEnv('/');
    const router = createRouter({ routes, notFound, env, t, afterRender });
    await router.navigate('/d/a', { replace: true });
    expect(env.history.replaceState).toHaveBeenCalledWith(null, '', '/d/a');
    await router.navigate('/d/a');
    expect(env.history.replaceState).toHaveBeenCalledTimes(2);
    expect(env.history.pushState).not.toHaveBeenCalled();
    await router.navigate('d/b?q=1#h');
    expect(env.history.pushState).toHaveBeenCalledWith(null, '', '/d/b?q=1#h');
    expect(router.current.search).toBe('?q=1');
    expect(router.current.hash).toBe('#h');
  });

  it('gives the notFound route to unknown paths', async () => {
    const { env } = fakeEnv('/unknown/path');
    const router = createRouter({ routes, notFound, env, t, afterRender });
    expect(router.current.route).toBe(notFound);
    expect(router.current.path).toBe('/unknown/path');
  });

  it('follows back and forward navigation until stopped', () => {
    const fake = fakeEnv('/');
    const router = createRouter({ routes, notFound, env: fake.env, t, afterRender });
    router.start();
    fake.pop('/d/zz');
    expect(router.current.params).toEqual({ token: 'zz' });
    expect(fake.env.document.title).toBe('[download.title]');
    router.stop();
    fake.pop('/');
    expect(router.current.route).toBe(download);
  });

  it('lets guards refuse navigate(), and removes them', async () => {
    const { env } = fakeEnv('/');
    const router = createRouter({ routes, notFound, env, t, afterRender });
    const seen: string[] = [];
    let allow = false;
    const remove = router.addGuard((path) => {
      seen.push(path);
      return allow;
    });
    const always = router.addGuard(() => true);
    await router.navigate('/d/a?x=1');
    expect(seen).toEqual(['/d/a?x=1']);
    expect(env.history.pushState).not.toHaveBeenCalled();
    expect(router.current.route).toBe(home);
    allow = true;
    await router.navigate('/d/a');
    expect(router.current.route).toBe(download);
    allow = false;
    remove();
    always();
    await router.navigate('/legal/x');
    expect(router.current.route).toBe(legal);
    expect(seen).toHaveLength(2);
  });

  it('puts the current URL back when a guard refuses back/forward navigation', () => {
    const fake = fakeEnv('/d/tok?x=1#h');
    const router = createRouter({ routes, notFound, env: fake.env, t, afterRender });
    router.start();
    const guard = vi.fn(() => false);
    router.addGuard(guard);
    fake.pop('/legal/legal-notice');
    expect(guard).toHaveBeenCalledWith('/legal/legal-notice');
    expect(router.current.route).toBe(download);
    expect(fake.env.history.pushState).toHaveBeenCalledWith(null, '', '/d/tok?x=1#h');
    expect(fake.env.location.pathname).toBe('/d/tok');
  });

  it('refuses a guarded link click after preventing the browser navigation', () => {
    const fake = fakeEnv('/');
    const router = createRouter({ routes, notFound, env: fake.env, t, afterRender });
    router.addGuard(() => false);
    const link = fakeLink({ href: '/d/abc' });
    router.link(link.node);
    expect(link.click().preventDefault).toHaveBeenCalled();
    expect(fake.env.history.pushState).not.toHaveBeenCalled();
    expect(router.current.route).toBe(home);
  });

  it('supports a base path', async () => {
    const adminHome: Route<string> = { pattern: '/', component: 'Dash', titleKey: 'admin.title' };
    const tenant: Route<string> = { pattern: '/tenants/:id', component: 'Tenant', titleKey: 'admin.tenant' };
    const fake = fakeEnv('/admin/');
    const router = createRouter({
      routes: [adminHome, tenant],
      notFound,
      base: '/admin/',
      env: fake.env,
      t,
      afterRender,
    });
    expect(router.base).toBe('/admin');
    expect(router.current.route).toBe(adminHome);
    expect(router.href('/')).toBe('/admin/');
    expect(router.href('/tenants/1')).toBe('/admin/tenants/1');
    expect(router.href('tenants/1')).toBe('/admin/tenants/1');
    await router.navigate('/tenants/t1');
    expect(fake.env.history.pushState).toHaveBeenCalledWith(null, '', '/admin/tenants/t1');
    expect(router.current.params).toEqual({ id: 't1' });
    expect(router.current.path).toBe('/tenants/t1');
    router.start();
    fake.pop('/elsewhere');
    expect(router.current.route).toBe(notFound);
    expect(router.current.path).toBe('/elsewhere');
  });

  it('uses a custom title builder and tolerates a missing heading or document', async () => {
    const fake = fakeEnv('/');
    fake.env.document.querySelector.mockReturnValue(null);
    const router = createRouter({
      routes,
      notFound,
      env: fake.env,
      t,
      afterRender,
      title: (m) => `${m.route.component} · Entity A`,
    });
    router.start();
    expect(fake.env.document.title).toBe('Home · Entity A');
    await router.navigate('/d/x');
    expect(fake.env.document.title).toBe('Download · Entity A');

    const bare: RouterEnv = {
      location: { pathname: '/', search: '', hash: '' },
      history: { pushState: vi.fn(), replaceState: vi.fn() },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
    const minimal = createRouter({ routes, notFound, env: bare, t, afterRender });
    minimal.start();
    await expect(minimal.navigate('/d/y')).resolves.toBeUndefined();
  });

  it('uses window, document, the shared t and svelte tick by default', async () => {
    const fake = fakeEnv('/legal/privacy-policy');
    vi.stubGlobal('window', {
      location: { ...fake.env.location, origin: fake.env.origin },
      history: fake.env.history,
      addEventListener: fake.env.addEventListener,
      removeEventListener: fake.env.removeEventListener,
      scrollTo: fake.env.scrollTo,
    });
    vi.stubGlobal('document', fake.env.document);
    const router = createRouter({ routes, notFound });
    expect(router.current.route).toBe(legal);
    router.start();
    expect(fake.env.addEventListener).toHaveBeenCalled();
    await router.navigate('/');
    expect(fake.env.history.pushState).toHaveBeenCalledWith(null, '', '/');
    expect(fake.env.scrollTo).toHaveBeenCalledWith(0, 0);
    expect(typeof fake.env.document.title).toBe('string');
  });
});

describe('link action', () => {
  function setup(base = '') {
    const fake = fakeEnv(base === '' ? '/' : `${base}/`);
    const router = createRouter({ routes, notFound, base, env: fake.env, t, afterRender });
    return { fake, router };
  }

  it('intercepts plain clicks on internal links', () => {
    const { fake, router } = setup();
    const link = fakeLink({ href: '/d/abc?x=1#y' });
    const action = router.link(link.node);
    const event = link.click();
    expect(event.preventDefault).toHaveBeenCalled();
    expect(fake.env.history.pushState).toHaveBeenCalledWith(null, '', '/d/abc?x=1#y');
    action.destroy();
    expect(link.attached).toBe(false);
  });

  it('accepts absolute same-origin hrefs', () => {
    const { fake, router } = setup();
    const link = fakeLink({ href: 'https://transfer.entity-a.example.com/legal/legal-notice' });
    router.link(link.node);
    expect(link.click().preventDefault).toHaveBeenCalled();
    expect(fake.env.history.pushState).toHaveBeenCalledWith(null, '', '/legal/legal-notice');
  });

  it('strips the base path of admin links and ignores links outside it', () => {
    const { fake, router } = setup('/admin');
    const inside = fakeLink({ href: '/admin/tenants/1' });
    router.link(inside.node);
    expect(inside.click().preventDefault).toHaveBeenCalled();
    expect(fake.env.history.pushState).toHaveBeenCalledWith(null, '', '/admin/tenants/1');
    const outside = fakeLink({ href: '/api/docs' });
    router.link(outside.node);
    expect(outside.click().preventDefault).not.toHaveBeenCalled();
  });

  it.each([
    [{ href: 'https://evil.example.com/d/x' }, {}],
    [{ href: '//evil.example.com/d/x' }, {}],
    [{ href: '/\\evil.example.com' }, {}],
    [{ href: 'mailto:a@example.com' }, {}],
    [{ href: 'javascript:alert(1)' }, {}],
    [{ href: 'relative/path' }, {}],
    [{}, {}],
    [{ href: '/d/x', target: '_blank' }, {}],
    [{ href: '/d/x', download: '' }, {}],
    [{ href: '/d/x' }, { button: 1 }],
    [{ href: '/d/x' }, { metaKey: true }],
    [{ href: '/d/x' }, { ctrlKey: true }],
    [{ href: '/d/x' }, { shiftKey: true }],
    [{ href: '/d/x' }, { altKey: true }],
    [{ href: '/d/x' }, { defaultPrevented: true }],
  ] as [Record<string, string>, Partial<LinkClick>][])('leaves %j %j to the browser', (attrs, init) => {
    const { fake, router } = setup();
    const link = fakeLink(attrs);
    router.link(link.node);
    expect(link.click(init).preventDefault).not.toHaveBeenCalled();
    expect(fake.env.history.pushState).not.toHaveBeenCalled();
  });

  it('intercepts links with an explicit _self or empty target', () => {
    for (const target of ['_self', '']) {
      const { router } = setup();
      const link = fakeLink({ href: '/d/x', target });
      router.link(link.node);
      expect(link.click().preventDefault).toHaveBeenCalled();
    }
  });
});
