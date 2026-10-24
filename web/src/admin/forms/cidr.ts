// Client-side check of the internal IP ranges of a tenant, mirroring netpolicy.ParsePrefix: a
// bare address is a single host, host bits must be zero, IPv6 zones are refused and IPv4-mapped
// prefixes become IPv4. The server normalises again and remains authoritative.

import { parseLineList, type LineList, type ParseResult } from './lines';

/** Maximum number of internal ranges of a tenant (NetworkRules.internalCidrs). */
export const MAX_INTERNAL_CIDRS = 500;

/** Reasons for which a range is refused. */
export type CidrError = 'syntax' | 'zone' | 'prefix-range' | 'host-bits';

/** The two catch-all ranges, which make every client internal. */
export const CATCH_ALL_CIDRS: readonly string[] = ['0.0.0.0/0', '::/0'];

interface Addr {
  v6: boolean;
  value: bigint;
}

const V4_PART = /^(0|[1-9][0-9]{0,2})$/;
const V6_GROUP = /^[0-9a-fA-F]{1,4}$/;
const BITS = /^(0|[1-9][0-9]{0,2})$/;

/** Parses a dotted IPv4 address without leading zeros. */
function parseV4(s: string): bigint | null {
  const parts = s.split('.');
  if (parts.length !== 4) {
    return null;
  }
  let v = 0n;
  for (const p of parts) {
    if (!V4_PART.test(p) || Number(p) > 255) {
      return null;
    }
    v = (v << 8n) | BigInt(p);
  }
  return v;
}

/** Parses the groups of one side of an IPv6 address; an IPv4 tail counts for two groups. */
function v6Groups(s: string, allowV4Tail: boolean): bigint[] | null {
  if (s === '') {
    return [];
  }
  const parts = s.split(':');
  const out: bigint[] = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i] as string;
    if (allowV4Tail && i === parts.length - 1 && p.includes('.')) {
      const v4 = parseV4(p);
      if (v4 === null) {
        return null;
      }
      out.push(v4 >> 16n, v4 & 0xffffn);
    } else if (V6_GROUP.test(p)) {
      out.push(BigInt(parseInt(p, 16)));
    } else {
      return null;
    }
  }
  return out;
}

/** Parses an IPv6 address (with at most one "::" and an optional IPv4 tail). */
function parseV6(s: string): bigint | null {
  const halves = s.split('::');
  if (halves.length > 2) {
    return null;
  }
  let groups: bigint[];
  if (halves.length === 2) {
    const left = v6Groups(halves[0] as string, false);
    const right = v6Groups(halves[1] as string, true);
    if (left === null || right === null || left.length + right.length > 7) {
      return null;
    }
    groups = [...left, ...Array<bigint>(8 - left.length - right.length).fill(0n), ...right];
  } else {
    const all = v6Groups(s, true);
    if (all === null || all.length !== 8) {
      return null;
    }
    groups = all;
  }
  return groups.reduce((acc, g) => (acc << 16n) | g, 0n);
}

function parseAddr(s: string): Addr | null {
  if (s.includes(':')) {
    const value = parseV6(s);
    return value === null ? null : { v6: true, value };
  }
  const value = parseV4(s);
  return value === null ? null : { v6: false, value };
}

function bitLen(a: Addr): number {
  return a.v6 ? 128 : 32;
}

/** Reports whether a is an IPv4-mapped IPv6 address (::ffff:a.b.c.d). */
function isMapped(a: Addr): boolean {
  return a.v6 && a.value >> 32n === 0xffffn;
}

function mask(value: bigint, bits: number, len: number): bigint {
  const host = (1n << BigInt(len - bits)) - 1n;
  return value & ~host;
}

/** Formats an IPv6 address as RFC 5952 (lowercase, longest zero run compressed). */
function formatV6(value: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) {
    groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  }
  let bestStart = -1;
  let bestLen = 1;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) {
      j++;
    }
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) {
    return hex.join(':');
  }
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
}

function formatV4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((s) => ((value >> s) & 0xffn).toString()).join('.');
}

/** Formats a prefix, unmapping an IPv4-mapped one of at least 96 bits. */
function formatPrefix(a: Addr, bits: number): string {
  if (isMapped(a) && bits >= 96) {
    return `${formatV4(a.value & 0xffffffffn)}/${bits - 96}`;
  }
  return `${a.v6 ? formatV6(a.value) : formatV4(a.value)}/${bits}`;
}

/**
 * Parses an IPv4 or IPv6 range ("10.0.0.0/8", "2001:db8::/32") or a bare address (a single
 * host) and returns its normalised form. A range with host bits set is refused, as by the server,
 * with the masked range as suggestion (it usually reveals a typo).
 */
export function parseCidr(input: string): ParseResult<CidrError> {
  const s = input.trim();
  if (s.includes('%')) {
    return { ok: false, error: 'zone' };
  }
  const slash = s.indexOf('/');
  const addr = parseAddr(slash < 0 ? s : s.slice(0, slash));
  if (addr === null) {
    return { ok: false, error: 'syntax' };
  }
  if (slash < 0) {
    return { ok: true, value: formatPrefix(addr, bitLen(addr)) };
  }
  const bitsText = s.slice(slash + 1);
  if (!BITS.test(bitsText)) {
    return { ok: false, error: 'syntax' };
  }
  const bits = Number(bitsText);
  if (bits > bitLen(addr)) {
    return { ok: false, error: 'prefix-range' };
  }
  const masked = mask(addr.value, bits, bitLen(addr));
  if (masked !== addr.value) {
    return { ok: false, error: 'host-bits', suggestion: formatPrefix({ ...addr, value: masked }, bits) };
  }
  return { ok: true, value: formatPrefix(addr, bits) };
}

/** Reports whether a normalised range covers every address of its family. */
export function isCatchAll(normalised: string): boolean {
  return CATCH_ALL_CIDRS.includes(normalised);
}

/** Result of the parsing of the ranges text area. */
export interface CidrList extends LineList<CidrError> {
  /** True when a valid line is a catch-all range: every client would be internal. */
  catchAll: boolean;
}

/** Parses the ranges text area, one range per line. */
export function parseCidrList(text: string): CidrList {
  const list = parseLineList(text, parseCidr, MAX_INTERNAL_CIDRS);
  return { ...list, catchAll: list.values.some(isCatchAll) };
}
