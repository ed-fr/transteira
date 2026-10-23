import { describe, expect, it } from 'vitest';
import { matchRoutes } from '../shared/router/router.svelte';
import { isHelpRoute, notFoundRoute, routes } from './routes';

describe('public routes', () => {
  it.each([
    ['/', '/'],
    ['/d/dl_abc', '/d/:token'],
    ['/i/inv_abc', '/i/:token'],
    ['/invite', '/invite'],
    ['/legal/legal-notice', '/legal/:document'],
    ['/help', '/help'],
    ['/help/download', '/help/:topic'],
    ['/unknown/path', '*'],
  ])('resolves %s', (path, pattern) => {
    expect(matchRoutes(routes, notFoundRoute, path).route.pattern).toBe(pattern);
  });

  it('has a help topic on every screen except the help itself', () => {
    for (const route of [...routes, notFoundRoute]) {
      expect(isHelpRoute(route) || route.helpTopic !== undefined, route.pattern).toBe(true);
    }
    expect(isHelpRoute({ pattern: '/help/:topic' })).toBe(true);
    expect(isHelpRoute({ pattern: '/d/:token' })).toBe(false);
  });
});
