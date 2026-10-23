// Filter of every URL received from the API before it reaches an href or src attribute
// (web/README.md "CSP rules for contributors", threat model T-91). Svelte does not filter
// attribute values, so a javascript: or foreign URL from a compromised or confused server
// answer would otherwise be rendered as is.
//
// Only same-origin relative paths under the two prefixes the API hands out are accepted:
//   /api/v1/downloads/...      file and archive download links
//   /api/v1/tenant/assets/...  tenant logo and background image
// Anything else (absolute or protocol-relative URL, scheme, backslash, control or space
// character, dot segment, encoded slash, backslash or dot, fragment) gives undefined.
//
// safeUploadUrl applies the same rules to the tus upload URLs (/api/v1/uploads/...) before the
// upload engine sends file content to them.

/** Path prefixes accepted by safeApiHref. */
export const SAFE_API_PREFIXES: readonly string[] = ['/api/v1/downloads/', '/api/v1/tenant/assets/'];

/** Path prefix accepted by safeUploadUrl. */
export const UPLOAD_PREFIX = '/api/v1/uploads/';

// Path and query characters allowed in an accepted URL (RFC 3986 unreserved, sub-delims except
// those with no use here, ':', '@', '/', '?', '=', '&', and percent escapes).
const ALLOWED = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*$/;
const PERCENT = /%(?![0-9A-Fa-f]{2})/;
// Encoded '/', '\', '.', '%', NUL and other control characters are refused in the path.
const DANGEROUS_ESCAPE = /%(2[Ff]|5[Cc]|2[Ee]|25|[01][0-9A-Fa-f]|7[Ff])/;

/**
 * Returns href unchanged when it is a safe same-origin API path, undefined otherwise.
 * Use the result directly in href/src; render nothing (or a disabled control) on undefined.
 */
export function safeApiHref(href: unknown): string | undefined {
  return safeApiPath(href, SAFE_API_PREFIXES);
}

/** Returns url unchanged when it is a safe same-origin tus upload path, undefined otherwise. */
export function safeUploadUrl(url: unknown): string | undefined {
  return safeApiPath(url, [UPLOAD_PREFIX]);
}

/**
 * Returns href unchanged when it is a safe same-origin path under one of prefixes (each starts
 * and ends with "/"), undefined otherwise.
 */
export function safeApiPath(href: unknown, prefixes: readonly string[]): string | undefined {
  if (typeof href !== 'string' || href.length === 0 || href.length > 2048) {
    return undefined;
  }
  if (!ALLOWED.test(href) || PERCENT.test(href)) {
    return undefined;
  }
  const queryAt = href.indexOf('?');
  const path = queryAt === -1 ? href : href.slice(0, queryAt);
  if (!prefixes.some((prefix) => path.startsWith(prefix) && path.length > prefix.length)) {
    return undefined;
  }
  if (DANGEROUS_ESCAPE.test(path) || path.includes('//')) {
    return undefined;
  }
  if (path.split('/').some((segment) => segment === '.' || segment === '..')) {
    return undefined;
  }
  return href;
}
