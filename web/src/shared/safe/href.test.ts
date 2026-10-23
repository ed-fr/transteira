import { describe, expect, it } from 'vitest';
import { SAFE_API_PREFIXES, safeApiHref, safeApiPath, safeUploadUrl, UPLOAD_PREFIX } from './href';

describe('safeApiHref', () => {
  it.each([
    '/api/v1/downloads/dl_7Hq2Wm9Zx4Lp1Vb8/files/fil_01JABCD9F1A2B3C4D5E6F7G8H9',
    '/api/v1/downloads/dl_7Hq2Wm9Zx4Lp1Vb8/archive',
    '/api/v1/tenant/assets/logo',
    '/api/v1/tenant/assets/background?v=3',
    '/api/v1/downloads/abc-_.~/x?name=a%20b&x=%2F',
  ])('accepts %s', (href) => {
    expect(safeApiHref(href)).toBe(href);
  });

  it.each([
    // Not a string or empty.
    undefined,
    null,
    42,
    {},
    '',
    // Schemes and absolute URLs.
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    ' javascript:alert(1)',
    'java\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox',
    'https://evil.example.com/api/v1/downloads/x',
    'http://localhost/api/v1/downloads/x',
    'file:///etc/passwd',
    // Protocol-relative and backslashes.
    '//evil.example.com/api/v1/downloads/x',
    '/\\evil.example.com/api/v1/downloads/x',
    '\\\\evil.example.com\\api',
    '/api/v1/downloads\\..\\admin',
    '/api/v1/downloads/x\\y',
    // Other prefixes or prefix only.
    '/api/v1/downloads/',
    '/api/v1/tenant/assets/',
    '/api/v1/downloads',
    '/api/v1/downloadsx/a',
    '/api/v1/admin/tenants',
    '/api/v2/downloads/x',
    'api/v1/downloads/x',
    './api/v1/downloads/x',
    '/API/V1/DOWNLOADS/x',
    '/?/api/v1/downloads/x',
    // Traversal, plain or encoded.
    '/api/v1/downloads/../admin/me',
    '/api/v1/downloads/./x',
    '/api/v1/downloads/x/..',
    '/api/v1/downloads/%2e%2e/admin',
    '/api/v1/downloads/%2E%2E/admin',
    '/api/v1/downloads/x%2F..%2Fadmin',
    '/api/v1/downloads/x%2f..',
    '/api/v1/downloads/x%5C..',
    '/api/v1/downloads/x%5c..',
    '/api/v1/downloads/%252e%252e/admin',
    '/api/v1/downloads/x%00',
    '/api/v1/downloads/x%0a',
    '/api/v1/downloads/x%7f',
    '/api/v1/downloads/x%',
    '/api/v1/downloads/x%zz',
    '/api/v1/downloads//evil',
    // Characters that have no place in an API link.
    '/api/v1/downloads/x y',
    '/api/v1/downloads/x\ny',
    '/api/v1/downloads/x\u0000',
    '/api/v1/downloads/x"onmouseover="alert(1)',
    '/api/v1/downloads/x<script>',
    '/api/v1/downloads/x#fragment',
    '/api/v1/downloads/é',
    '/api/v1/downloads/x`y',
    // Too long.
    `/api/v1/downloads/${'a'.repeat(2100)}`,
  ])('rejects %j', (href) => {
    expect(safeApiHref(href)).toBeUndefined();
  });

  it('exposes the accepted prefixes', () => {
    expect(SAFE_API_PREFIXES).toEqual(['/api/v1/downloads/', '/api/v1/tenant/assets/']);
  });
});

describe('safeUploadUrl', () => {
  it.each(['/api/v1/uploads/upl_01HZX', '/api/v1/uploads/upl_1?x=1'])('accepts %j', (url) => {
    expect(safeUploadUrl(url)).toBe(url);
  });

  it.each([
    undefined,
    '',
    'https://evil.example.org/api/v1/uploads/upl_1',
    '//evil.example.org/api/v1/uploads/upl_1',
    'javascript:alert(1)',
    '/api/v1/uploads/',
    '/api/v1/uploads/../admin/me',
    '/api/v1/uploads/%2e%2e/admin',
    '/api/v1/admin/tenants',
    '/admin/api/v1/uploads/upl_1',
    '/api/v1/downloads/dl_1',
    '/api/v1/uploads//upl_1',
  ])('rejects %j', (url) => {
    expect(safeUploadUrl(url)).toBeUndefined();
  });

  it('exposes the generic path filter', () => {
    expect(UPLOAD_PREFIX).toBe('/api/v1/uploads/');
    expect(safeApiPath('/x/y', ['/x/'])).toBe('/x/y');
    expect(safeApiPath('/x/y', ['/z/'])).toBeUndefined();
  });
});
