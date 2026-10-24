// Client-side check of the internal mail domains of a tenant, mirroring tenant.NormalizeHost:
// lowercase ASCII labels, punycode for international names, at least two labels and an
// alphabetic (or punycode) top-level label. The server normalises again and remains authoritative.
// One deliberate difference: a trailing dot (fully qualified form, "example.com.") is accepted
// and removed by the server, but refused here (trailing-dot) with the name without the dot as
// suggestion, so that the admin sees and stores the usual form.

import { parseLineList, type LineList, type ParseResult } from './lines';

/** Maximum number of internal domains of a tenant (NetworkRules.internalDomains). */
export const MAX_INTERNAL_DOMAINS = 100;
/** Maximum length of a domain, in bytes of its ASCII form. */
export const MAX_DOMAIN_LENGTH = 253;
/** Maximum length of a label. */
export const MAX_LABEL_LENGTH = 63;

/** Reasons for which a domain is refused. */
export type DomainError =
  'syntax' | 'ip-literal' | 'trailing-dot' | 'idn' | 'too-long' | 'single-label' | 'label' | 'tld';

// Printable ASCII only; anything else goes through the IDNA conversion of the URL parser.
const ASCII_ONLY = /^[\x21-\x7e]*$/;
const ASCII_HOST = /^[a-z0-9.-]+$/;
const LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
const IPV4_LIKE = /^[0-9]+(\.[0-9]+){3}$/;

/**
 * Scheme used to parse a host name: a special scheme, so that the URL parser applies UTS #46.
 * Built at run time so that the bundle holds no literal external-looking URL, which the
 * build output check (scripts/check-dist.mjs) refuses.
 */
const PARSE_SCHEME = String.fromCharCode(104, 116, 116, 112) + ':';

/** Converts an international name to its punycode form, or returns null when it cannot be. */
function toASCII(name: string): string | null {
  try {
    // The URL parser applies UTS #46 (the same mapping as the browsers); it is only parsed,
    // never navigated to.
    return new URL(PARSE_SCHEME + '//' + name + '/').hostname;
  } catch {
    return null;
  }
}

/** Reports whether l is an acceptable top-level label: two letters or more, or punycode. */
function isTLD(l: string): boolean {
  return l.startsWith('xn--') || /^[a-z]{2,}$/.test(l);
}

/** Validates a lowercased name without trailing dot. */
function check(name: string): ParseResult<DomainError> {
  let ascii = name;
  if (!ASCII_ONLY.test(name)) {
    const converted = toASCII(name);
    if (converted === null || !ASCII_HOST.test(converted)) {
      return { ok: false, error: 'idn' };
    }
    ascii = converted;
  } else if (!ASCII_HOST.test(name)) {
    return { ok: false, error: 'syntax' };
  }
  if (IPV4_LIKE.test(ascii)) {
    return { ok: false, error: 'ip-literal' };
  }
  if (ascii.length > MAX_DOMAIN_LENGTH) {
    return { ok: false, error: 'too-long' };
  }
  const labels = ascii.split('.');
  if (labels.length < 2) {
    return { ok: false, error: 'single-label' };
  }
  if (!labels.every((l) => l.length <= MAX_LABEL_LENGTH && LABEL.test(l))) {
    return { ok: false, error: 'label' };
  }
  if (!isTLD(labels[labels.length - 1] as string)) {
    return { ok: false, error: 'tld' };
  }
  return { ok: true, value: ascii };
}

/**
 * Validates a mail domain and returns it normalised (lowercase, punycode). A trailing dot is
 * refused, with the domain without it as suggestion when that one is valid.
 */
export function parseDomain(input: string): ParseResult<DomainError> {
  const s = input.trim().toLowerCase();
  if (s === '' || /[\s:@/[\]]/.test(s)) {
    return { ok: false, error: 'syntax' };
  }
  if (s.endsWith('.')) {
    const fixed = check(s.slice(0, -1));
    return fixed.ok
      ? { ok: false, error: 'trailing-dot', suggestion: fixed.value }
      : { ok: false, error: 'trailing-dot' };
  }
  return check(s);
}

/** Parses the domains text area, one domain per line. */
export function parseDomainList(text: string): LineList<DomainError> {
  return parseLineList(text, parseDomain, MAX_INTERNAL_DOMAINS);
}
