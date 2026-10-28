import { describe, expect, it } from 'vitest';
import {
  MAX_RECIPIENT_DOMAINS,
  parseRuleList,
  recipientRulesBody,
  recipientRulesNormalized,
  recipientWarnings,
  sameRecipientRules,
  validateRecipientRules,
} from './recipientRules';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const fields = {
  allowedDomains: { id: 'allowed', label: 'Allowed' },
  deniedDomains: { id: 'denied', label: 'Denied' },
};

describe('recipient rules', () => {
  it('parses and normalises a list', () => {
    const list = parseRuleList('Example.ORG\n\nmail.example.net\nexample.org');
    expect(list.values).toEqual(['example.org', 'mail.example.net']);
    expect(list.duplicates).toEqual([4]);
  });

  it('refuses invalid lines and too many entries', () => {
    const bad = parseRuleList('example.org\nnot a domain');
    const ok = parseRuleList('');
    expect(validateRecipientRules(bad, ok, fields, t)).toEqual([
      { id: 'allowed', label: 'Allowed', message: 'adminComponents.lineList.invalidLines {"count":1}' },
    ]);
    const many = parseRuleList(
      Array.from({ length: MAX_RECIPIENT_DOMAINS + 1 }, (_v, i) => `d${i}.example.org`).join('\n'),
    );
    expect(validateRecipientRules(ok, many, fields, t)).toEqual([
      { id: 'denied', label: 'Denied', message: 'fieldErrors.too-many' },
    ]);
    expect(validateRecipientRules(ok, ok, fields, t)).toEqual([]);
  });

  it('warns about a domain in both lists and about a restricting allow list', () => {
    const allowed = parseRuleList('a.example.org\nb.example.org');
    const denied = parseRuleList('b.example.org');
    expect(recipientWarnings(allowed, denied)).toEqual([
      { key: 'adminTenants.recipientRules.warnings.both', params: { domain: 'b.example.org' } },
      { key: 'adminTenants.recipientRules.warnings.restricts', params: { count: 2 } },
    ]);
    expect(recipientWarnings(parseRuleList(''), denied)).toEqual([]);
  });

  it('builds the body and compares with the saved rules', () => {
    const body = recipientRulesBody(parseRuleList('A.example.org'), parseRuleList('b.example.org'));
    expect(body).toEqual({ allowedDomains: ['a.example.org'], deniedDomains: ['b.example.org'] });
    expect(sameRecipientRules(body, { ...body })).toBe(true);
    expect(sameRecipientRules(body, { allowedDomains: [], deniedDomains: ['b.example.org'] })).toBe(false);
    expect(recipientRulesNormalized('a.example.org', 'b.example.org\n', body)).toBe(false);
    expect(recipientRulesNormalized('A.example.org', 'b.example.org', body)).toBe(true);
  });
});
