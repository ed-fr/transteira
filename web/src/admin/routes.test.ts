import { describe, expect, it } from 'vitest';
import { matchRoutes, stripBase } from '../shared/router/router.svelte';
import { ADMIN_BASE, notFoundRoute, routes } from './routes';

describe('admin routes', () => {
  it.each([
    ['/admin/', '/'],
    ['/admin', '/'],
    ['/admin/help', '/help'],
    ['/admin/help/tenants', '/help/:topic'],
    ['/admin/tenants', '*'],
    ['/other', '*'],
  ])('resolves %s', (pathname, pattern) => {
    expect(matchRoutes(routes, notFoundRoute, stripBase(ADMIN_BASE, pathname)).route.pattern).toBe(pattern);
  });
});
