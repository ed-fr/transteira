import { render } from 'svelte/server';
import { beforeAll, describe, expect, it } from 'vitest';
import { setLocale } from '../shared/i18n/i18n.svelte';
import HelpRules from './HelpRules.svelte';
import {
  durationsText,
  levelRuleItems,
  levelViews,
  limitItems,
  summaryItems,
  type HelpLevel,
  type HelpTenantRules,
  type RulesFormat,
} from './rules';

// Keys and parameters instead of sentences: the logic is checked apart from the translations.
const fmt: RulesFormat = {
  t: (key, params) => (params === undefined ? key : `${key}${JSON.stringify(params)}`),
  bytes: (n) => `${n}B`,
  list: (items) => items.join(' + '),
};

const noRules: HelpLevel['rules'] = {
  requireRecipientVerification: false,
  requirePassword: false,
  allowedExpiryDays: [1, 7, 30],
  internalRecipientsOnly: false,
  forceDeleteAfterFirstDownload: false,
  maxDownloads: null,
};

const level = (
  key: string,
  rules: Partial<HelpLevel['rules']> = {},
  extra: Partial<HelpLevel> = {},
): HelpLevel => ({
  key,
  label: key,
  isDefault: false,
  rules: { ...noRules, ...rules },
  ...extra,
});

const features = {
  remoteInternalDeposit: true,
  transferReply: false,
  recipientVerification: true,
  maxDownloads: false,
  folders: true,
  recipientRestrictions: true,
  antivirus: 'enabled' as const,
};

const tenant: HelpTenantRules = {
  name: 'Entity A',
  limits: { maxTransferBytes: 1024, expiryDays: [1, 7, 30] },
  features,
  confidentialityLevels: [
    level('public', {}, { isDefault: true }),
    level('confidential', { requirePassword: true }, { description: 'Sensitive data' }),
  ],
};

describe('rules in words', () => {
  it('words the durations like the deposit form', () => {
    expect(durationsText([1, 7], fmt)).toBe(
      'deposit.form.expiry.days{"count":1} + deposit.form.expiry.days{"count":7}',
    );
  });

  it('gives the size and the durations', () => {
    expect(limitItems(tenant, fmt)).toEqual([
      'help.rules.maxSize{"size":"1024B"}',
      `help.rules.durations{"durations":"${durationsText([1, 7, 30], fmt).replaceAll('"', '\\"')}"}`,
    ]);
  });

  it('lists every option on or off in the summary', () => {
    const items = summaryItems(tenant, fmt);
    expect(items.slice(2)).toEqual([
      'help.rules.features.remoteInternalDeposit.on',
      'help.rules.features.transferReply.off',
      'help.rules.features.recipientVerification.on',
      'help.rules.features.maxDownloads.off',
      'help.rules.features.folders.on',
      'help.rules.features.recipientRestrictions.on',
      'help.rules.features.antivirus.on',
    ]);
    const off = summaryItems(
      {
        ...tenant,
        features: {
          ...features,
          remoteInternalDeposit: false,
          transferReply: true,
          recipientRestrictions: false,
          antivirus: 'disabled',
        },
      },
      fmt,
    );
    expect(off).toContain('help.rules.features.remoteInternalDeposit.off');
    expect(off).toContain('help.rules.features.transferReply.on');
    expect(off).toContain('help.rules.features.recipientRestrictions.off');
    expect(off).toContain('help.rules.features.antivirus.off');
  });

  it('gives the size and durations only without features', () => {
    expect(summaryItems({ ...tenant, features: undefined }, fmt)).toHaveLength(2);
  });

  it('words every rule of a level', () => {
    const all = level('secret', {
      allowedExpiryDays: [1],
      requirePassword: true,
      requireRecipientVerification: true,
      internalRecipientsOnly: true,
      forceDeleteAfterFirstDownload: true,
      maxDownloads: 3,
    });
    expect(levelRuleItems(all, [1, 7, 30], fmt)).toEqual([
      `help.rules.levels.durations{"durations":"deposit.form.expiry.days{\\"count\\":1}"}`,
      'help.rules.levels.password',
      'help.rules.levels.recipientVerification',
      'help.rules.levels.internalRecipients',
      'help.rules.levels.deleteAfterFirst',
      'help.rules.levels.maxDownloads{"count":3}',
    ]);
    expect(levelRuleItems(level('open'), [1, 7, 30], fmt)).toEqual([]);
    // Durations the tenant does not offer are a difference too.
    expect(levelRuleItems(level('open'), [1, 7], fmt)).toHaveLength(1);
  });

  it('shows the levels with their label, description and default marker', () => {
    expect(levelViews(tenant, fmt)).toEqual([
      { key: 'public', label: 'public', description: undefined, isDefault: true, rules: [] },
      {
        key: 'confidential',
        label: 'confidential',
        description: 'Sensitive data',
        isDefault: false,
        rules: ['help.rules.levels.password'],
      },
    ]);
    const blank = levelViews(
      { ...tenant, confidentialityLevels: [level('a', {}, { description: ' ' }), level('b')] },
      fmt,
    );
    expect(blank[0]?.description).toBeUndefined();
  });

  it('shows nothing without levels or with a single level imposing nothing', () => {
    expect(levelViews({ ...tenant, confidentialityLevels: undefined }, fmt)).toEqual([]);
    expect(levelViews({ ...tenant, confidentialityLevels: [] }, fmt)).toEqual([]);
    expect(levelViews({ ...tenant, confidentialityLevels: [level('only')] }, fmt)).toEqual([]);
    expect(
      levelViews({ ...tenant, confidentialityLevels: [level('only', { requirePassword: true })] }, fmt),
    ).toHaveLength(1);
  });
});

describe('HelpRules', () => {
  beforeAll(async () => {
    await setLocale('en');
  });

  const html = (props: { set: 'summary' | 'limits' | 'levels'; rules?: HelpTenantRules }): string =>
    render(HelpRules, { props }).body.replace(/<!--.*?-->/g, '');

  it('renders nothing without rules', () => {
    for (const set of ['summary', 'limits', 'levels'] as const) {
      expect(html({ set })).not.toContain('<li');
    }
  });

  it('renders the summary with the tenant name and options', () => {
    const body = html({ set: 'summary', rules: tenant });
    expect(body).toContain('Rules applied by Entity A:');
    expect(body).toContain('Maximum size per transfer: 1 kB.');
    expect(body).toContain('Available durations: 1 day, 7 days, and 30 days.');
    expect(body).toContain('Recipients cannot reply to a transfer.');
    expect(body).toContain('Sending is restricted to some recipient domains.');
  });

  it('renders the limits as a list', () => {
    const body = html({ set: 'limits', rules: tenant });
    expect(body).toMatch(/^<ul[^>]*>/);
    expect(body).toContain('Maximum size per transfer');
    expect(body).not.toContain('Recipients cannot reply');
  });

  it('renders the levels, nothing for a single level imposing nothing', () => {
    const body = html({ set: 'levels', rules: tenant });
    expect(body).toContain('<strong>public</strong> (default)');
    expect(body).toContain('Sensitive data');
    expect(body).toContain('Password required.');
    expect(body).toContain('No additional rule.');
    expect(
      html({ set: 'levels', rules: { ...tenant, confidentialityLevels: [level('only')] } }),
    ).not.toContain('<li');
  });

  it('renders the values of the admins as text (T-232)', () => {
    const attack = '<img src=x onerror=alert(1)>';
    const body = html({
      set: 'levels',
      rules: {
        ...tenant,
        confidentialityLevels: [
          level('x', { requirePassword: true }, { label: attack, description: attack }),
        ],
      },
    });
    expect(body).not.toContain('<img');
    expect(body).toContain('&lt;img src=x onerror=alert(1)>');
    const summary = html({ set: 'summary', rules: { ...tenant, name: '<b>**Entity**</b>' } });
    expect(summary).not.toContain('<b>');
    expect(summary).toContain('&lt;b>**Entity**&lt;/b>');
  });
});
