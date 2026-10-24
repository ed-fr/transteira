import { describe, expect, it } from 'vitest';
import { parseCidrList } from '../../forms/cidr';
import { parseDomainList } from '../../forms/domain';
import {
  cidrLineMessage,
  domainLineMessage,
  networkBody,
  networkWarnings,
  sameRules,
  validateNetwork,
  wasNormalized,
} from './network';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const fields = {
  internalCidrs: { id: 'cidrs', label: 'Ranges' },
  internalDomains: { id: 'domains', label: 'Domains' },
};

describe('line messages', () => {
  it('names the masked range of a range with host bits', () => {
    expect(
      cidrLineMessage({ line: 1, raw: '10.0.0.1/8', error: 'host-bits', suggestion: '10.0.0.0/8' }),
    ).toEqual({
      key: 'adminTenants.network.errors.cidr.hostBitsSuggestion',
      params: { network: '10.0.0.0/8' },
    });
  });

  it('has one range message per reason', () => {
    const keys = (['syntax', 'zone', 'prefix-range', 'host-bits'] as const).map(
      (error) => cidrLineMessage({ line: 2, raw: 'x', error }).key,
    );
    expect(keys).toEqual([
      'adminTenants.network.errors.cidr.syntax',
      'adminTenants.network.errors.cidr.zone',
      'adminTenants.network.errors.cidr.prefixRange',
      'adminTenants.network.errors.cidr.hostBits',
    ]);
  });

  it('names the domain without its trailing dot', () => {
    expect(
      domainLineMessage({ line: 1, raw: 'example.com.', error: 'trailing-dot', suggestion: 'example.com' }),
    ).toEqual({
      key: 'adminTenants.network.errors.domain.trailingDotSuggestion',
      params: { domain: 'example.com' },
    });
  });

  it('has one domain message per reason', () => {
    const errors = [
      'syntax',
      'ip-literal',
      'trailing-dot',
      'idn',
      'too-long',
      'single-label',
      'label',
      'tld',
    ] as const;
    expect(errors.map((error) => domainLineMessage({ line: 1, raw: 'x', error }).key)).toEqual([
      'adminTenants.network.errors.domain.syntax',
      'adminTenants.network.errors.domain.ipLiteral',
      'adminTenants.network.errors.domain.trailingDot',
      'adminTenants.network.errors.domain.idn',
      'adminTenants.network.errors.domain.tooLong',
      'adminTenants.network.errors.domain.singleLabel',
      'adminTenants.network.errors.domain.label',
      'adminTenants.network.errors.domain.tld',
    ]);
  });
});

describe('networkWarnings', () => {
  it('warns when both lists are empty', () => {
    expect(networkWarnings(parseCidrList(''), parseDomainList('')).map((w) => w.key)).toEqual([
      'adminTenants.network.warnings.emptyCidrs',
      'adminTenants.network.warnings.emptyDomains',
    ]);
  });

  it('warns about each catch-all range', () => {
    const w = networkWarnings(parseCidrList('0.0.0.0/0\n::/0\n10.0.0.0/8'), parseDomainList('example.com'));
    expect(w).toEqual([
      { key: 'adminTenants.network.warnings.catchAll', params: { range: '0.0.0.0/0' } },
      { key: 'adminTenants.network.warnings.catchAll', params: { range: '::/0' } },
    ]);
  });

  it('has no warning for ordinary lists', () => {
    expect(networkWarnings(parseCidrList('192.0.2.0/24'), parseDomainList('example.com'))).toEqual([]);
  });
});

describe('validateNetwork', () => {
  it('accepts valid lists', () => {
    expect(validateNetwork(parseCidrList('10.0.0.0/8'), parseDomainList('example.com'), fields, t)).toEqual(
      [],
    );
  });

  it('refuses invalid lines on both lists, in form order', () => {
    const errors = validateNetwork(parseCidrList('nope\nbad'), parseDomainList('-x'), fields, t);
    expect(errors).toEqual([
      { id: 'cidrs', label: 'Ranges', message: 'adminComponents.lineList.errorsTitle {"count":2}' },
      { id: 'domains', label: 'Domains', message: 'adminComponents.lineList.errorsTitle {"count":1}' },
    ]);
  });

  it('refuses too many entries', () => {
    const many = Array.from({ length: 101 }, (_, i) => `d${i}.example.com`).join('\n');
    expect(validateNetwork(parseCidrList(''), parseDomainList(many), fields, t)).toEqual([
      { id: 'domains', label: 'Domains', message: 'fieldErrors.too-many' },
    ]);
  });
});

describe('body, dirty and normalisation', () => {
  it('sends the normalised, deduplicated values', () => {
    expect(networkBody(parseCidrList('10.0.0.1\n10.0.0.1/32'), parseDomainList('Example.COM'))).toEqual({
      internalCidrs: ['10.0.0.1/32'],
      internalDomains: ['example.com'],
    });
  });

  it('compares rules in order', () => {
    const a = { internalCidrs: ['10.0.0.0/8'], internalDomains: ['example.com'] };
    expect(sameRules(a, { ...a })).toBe(true);
    expect(sameRules(a, { ...a, internalCidrs: [] })).toBe(false);
    expect(sameRules(a, { ...a, internalDomains: ['example.org'] })).toBe(false);
  });

  it('reports a normalisation when the saved values differ from the typed lines', () => {
    const saved = { internalCidrs: ['10.0.0.1/32'], internalDomains: ['example.com'] };
    expect(wasNormalized(' 10.0.0.1/32 \r\n\n', 'example.com', saved)).toBe(false);
    expect(wasNormalized('10.0.0.1', 'example.com', saved)).toBe(true);
    expect(wasNormalized('10.0.0.1/32', 'EXAMPLE.com', saved)).toBe(true);
  });
});
