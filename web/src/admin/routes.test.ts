import { describe, expect, it } from 'vitest';
import { matchRoutes, stripBase, type Route } from '../shared/router/router.svelte';
import { ADMIN_BASE, adminRoute, isHelpRoute, notFoundRoute, routes, type AdminRoute } from './routes';
import type { AdminScreenComponent } from './screens/types';

const bundles = import.meta.glob<Record<string, unknown>>('../locales/*/*.json', {
  eager: true,
  import: 'default',
});

/** Message of key ("area.a.b") in the bundles of lang, undefined when missing. */
function message(lang: string, key: string): unknown {
  const [area, ...path] = key.split('.');
  let node: unknown = bundles[`../locales/${lang}/${area}.json`];
  for (const part of path) {
    node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
  }
  return node;
}

function resolve(pathname: string): { route: AdminRoute; params: Record<string, string> } {
  const { route, params } = matchRoutes(routes, notFoundRoute, stripBase(ADMIN_BASE, pathname));
  return { route: adminRoute(route), params };
}

describe('admin routes', () => {
  it.each([
    ['/admin/', '/', 'auth', 'admin'],
    ['/admin', '/', 'auth', 'admin'],
    ['/admin/setup', '/setup', 'setup', 'setup'],
    ['/admin/login', '/login', 'anonymous', 'login'],
    ['/admin/activate', '/activate', 'any', 'activation'],
    ['/admin/account', '/account', 'auth', 'account'],
    ['/admin/tenants', '/tenants', 'auth', 'tenants'],
    ['/admin/tenants/new', '/tenants/new', 'super', 'tenant-create'],
    ['/admin/tenants/ten_1/general', '/tenants/:id/general', 'auth', 'tenant-general'],
    ['/admin/tenants/ten_1/branding', '/tenants/:id/branding', 'auth', 'tenant-branding'],
    ['/admin/tenants/ten_1/network', '/tenants/:id/network', 'auth', 'tenant-network'],
    ['/admin/tenants/ten_1/smtp', '/tenants/:id/smtp', 'auth', 'tenant-smtp'],
    ['/admin/tenants/ten_1/templates', '/tenants/:id/templates', 'auth', 'tenant-templates'],
    [
      '/admin/tenants/ten_1/templates/verification_code/fr',
      '/tenants/:id/templates/:key/:lang',
      'auth',
      'tenant-templates',
    ],
    ['/admin/tenants/ten_1/legal', '/tenants/:id/legal', 'auth', 'tenant-legal'],
    ['/admin/tenants/ten_1/legal/privacy/en', '/tenants/:id/legal/:document/:lang', 'auth', 'tenant-legal'],
    ['/admin/tenants/ten_1/transfers', '/tenants/:id/transfers', 'auth', 'tenant-transfers'],
    [
      '/admin/tenants/ten_1/transfers/trf_1',
      '/tenants/:id/transfers/:transferId',
      'auth',
      'tenant-transfers',
    ],
    ['/admin/tenants/ten_1/invitations', '/tenants/:id/invitations', 'auth', 'tenant-invitations'],
    ['/admin/tenants/ten_1/blocklist', '/tenants/:id/blocklist', 'auth', 'tenant-blocklist'],
    ['/admin/tenants/ten_1/tokens', '/tenants/:id/tokens', 'auth', 'tenant-tokens'],
    ['/admin/tenants/ten_1/tokens/new', '/tenants/:id/tokens/new', 'auth', 'tenant-tokens'],
    ['/admin/tenants/ten_1/webhooks', '/tenants/:id/webhooks', 'auth', 'tenant-webhooks'],
    ['/admin/tenants/ten_1/audit', '/tenants/:id/audit', 'auth', 'tenant-audit'],
    ['/admin/tenants/ten_1/stats', '/tenants/:id/stats', 'auth', 'tenant-stats'],
    ['/admin/tenants/ten_1/privacy', '/tenants/:id/privacy', 'auth', 'tenant-privacy'],
    ['/admin/admins', '/admins', 'super', 'admins'],
    ['/admin/admins/new', '/admins/new', 'super', 'admins'],
    ['/admin/admins/adm_1', '/admins/:id', 'super', 'admins'],
    ['/admin/system', '/system', 'super', 'system-overview'],
    ['/admin/system/', '/system', 'super', 'system-overview'],
    ['/admin/system/maintenance', '/system/maintenance', 'super', 'system-maintenance'],
    ['/admin/system/settings', '/system/settings', 'super', 'system-settings'],
    ['/admin/system/webhooks', '/system/webhooks', 'super', 'system-webhooks'],
    ['/admin/system/audit', '/system/audit', 'super', 'system-audit'],
    ['/admin/system/master-key', '/system/master-key', 'super', 'system-master-key'],
    ['/admin/system/unknown', '*', 'any', 'admin'],
    ['/admin/help', '/help', 'any', undefined],
    ['/admin/help/tenants', '/help/:topic', 'any', undefined],
    ['/admin/tenants/ten_1', '*', 'any', 'admin'],
    ['/admin/unknown', '*', 'any', 'admin'],
    ['/other', '*', 'any', 'admin'],
  ])('resolves %s', (pathname, pattern, access, helpTopic) => {
    const { route } = resolve(pathname);
    expect(route.pattern).toBe(pattern);
    expect(route.access).toBe(access);
    expect(route.helpTopic).toBe(helpTopic);
  });

  it('decodes the route parameters', () => {
    expect(resolve('/admin/tenants/ten%201/templates/transfer_notification/en').params).toEqual({
      id: 'ten 1',
      key: 'transfer_notification',
      lang: 'en',
    });
    expect(resolve('/admin/admins/adm_9').params).toEqual({ id: 'adm_9' });
    expect(resolve('/admin/tenants/ten_1/transfers/trf_%2F1').params).toEqual({
      id: 'ten_1',
      transferId: 'trf_/1',
    });
  });

  it('marks exactly the tenant routes (configuration and operations) for the tenant navigation', () => {
    for (const route of routes) {
      const isTenantPage = route.pattern.startsWith('/tenants/:id/');
      expect(route.tenantNav === true, route.pattern).toBe(isTenantPage);
      if (isTenantPage) {
        expect(route.pattern).toContain(':id');
      }
    }
  });

  it('reserves the creation and administrator routes to the super admin', () => {
    const superRoutes = routes.filter((r) => r.access === 'super').map((r) => r.pattern);
    expect(superRoutes).toEqual([
      '/tenants/new',
      '/admins',
      '/admins/new',
      '/admins/:id',
      '/system',
      '/system/maintenance',
      '/system/settings',
      '/system/webhooks',
      '/system/audit',
      '/system/master-key',
    ]);
  });

  it('marks exactly the system routes for the system navigation, never with the tenant one', () => {
    for (const route of [...routes, notFoundRoute]) {
      const isSystemPage = route.pattern === '/system' || route.pattern.startsWith('/system/');
      expect(route.systemNav === true, route.pattern).toBe(isSystemPage);
      if (isSystemPage) {
        expect(route.access, route.pattern).toBe('super');
        expect(route.tenantNav, route.pattern).toBeUndefined();
        expect(route.titleKey, route.pattern).toMatch(/^adminSystem\.[a-zA-Z]+\.title$/);
        expect(route.helpTopic, route.pattern).toMatch(/^system-/);
      }
    }
  });

  it('declares a unique pattern, a title and a help topic for every screen', () => {
    const patterns = routes.map((r) => r.pattern);
    expect(new Set(patterns).size).toBe(patterns.length);
    for (const route of routes) {
      expect(route.titleKey).toMatch(
        /^(admin|adminAuth|adminTenants|adminAccounts|adminOps|adminSystem|common)\./,
      );
      if (!isHelpRoute(route)) {
        expect(route.helpTopic, route.pattern).toMatch(/^[a-z][a-z-]*$/);
      }
    }
  });

  it.each(['en', 'fr'])('has a translated title without parameters for every route (%s)', (lang) => {
    for (const route of [...routes, notFoundRoute]) {
      const text = message(lang, route.titleKey);
      expect(typeof text, `${lang} ${route.titleKey}`).toBe('string');
      expect(text as string).not.toContain('{');
    }
  });

  it('treats a route without access level as the not found route', () => {
    const plain: Route<AdminScreenComponent> = {
      pattern: '/x',
      component: notFoundRoute.component,
      titleKey: 'common.notFound.title',
    };
    expect(adminRoute(plain)).toBe(notFoundRoute);
    expect(adminRoute(routes[0] as AdminRoute)).toBe(routes[0]);
  });

  it('recognises the help routes', () => {
    expect(isHelpRoute({ pattern: '/help' })).toBe(true);
    expect(isHelpRoute({ pattern: '/help/:topic' })).toBe(true);
    expect(isHelpRoute({ pattern: '/' })).toBe(false);
    expect(isHelpRoute({ pattern: '/helpers' })).toBe(false);
  });
});
