import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  buildDropLinkPatch,
  DEFAULT_DEPOSITS_PER_HOUR,
  dateInputFrom,
  dropActionErrorMessage,
  dropCreateBody,
  dropFormFrom,
  dropFormTouched,
  dropLinkErrorOutcome,
  dropLinkStatus,
  dropPatchEmpty,
  dropStatusView,
  emptyDropLinkForm,
  isDropLinkManageable,
  levelLabel,
  levelOptions,
  parseDepositsPerHour,
  parseDropRecipient,
  parseDropRecipients,
  recipientLineMessage,
  sortDropLinks,
  validateDropLink,
  withoutSecret,
  type DropLink,
  type DropLinkFields,
  type TenantLevel,
} from './dropLinks';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const link = (extra: Partial<DropLink> = {}): DropLink => ({
  id: 'drl_1',
  label: 'Supplier invoices',
  recipients: ['accounting@entity-a.example.com'],
  validityDays: 7,
  confidentialityLevel: 'internal',
  enabled: true,
  maxDepositsPerHour: 20,
  unused: false,
  createdBy: 'adm_1',
  createdAt: '2026-11-04T09:00:00Z',
  updatedAt: '2026-11-04T09:00:00Z',
  lastUsedAt: null,
  revokedAt: null,
  ...extra,
});

const fields: DropLinkFields = {
  label: { id: 'f-label', label: 'Label' },
  recipients: { id: 'f-recipients', label: 'Recipients' },
  validityDays: { id: 'f-validity', label: 'Validity' },
  confidentialityLevel: { id: 'f-level', label: 'Level' },
  expiresAt: { id: 'f-expiry', label: 'Expiry' },
  maxDepositsPerHour: { id: 'f-cap', label: 'Cap' },
};

const view = (extra: Partial<ErrorView>): ErrorView => ({
  code: undefined,
  status: undefined,
  message: 'general',
  fields: {},
  attemptsRemaining: undefined,
  retryAfterSeconds: undefined,
  maxTransferBytes: undefined,
  files: undefined,
  ...extra,
});

describe('status', () => {
  it('puts revoked before disabled', () => {
    expect(dropLinkStatus(link())).toBe('active');
    expect(dropLinkStatus(link({ enabled: false }))).toBe('disabled');
    expect(dropLinkStatus(link({ enabled: false, revokedAt: '2026-11-05T00:00:00Z' }))).toBe('revoked');
  });

  it('labels each status and manages all but revoked links', () => {
    expect(dropStatusView('active')).toEqual({ variant: 'ok', key: 'opsDropLinks.status.active' });
    expect(dropStatusView('disabled').variant).toBe('warning');
    expect(dropStatusView('revoked').key).toBe('opsDropLinks.status.revoked');
    expect(isDropLinkManageable(link({ enabled: false }))).toBe(true);
    expect(isDropLinkManageable(link({ revokedAt: '2026-11-05T00:00:00Z' }))).toBe(false);
  });

  it('sorts active first, then disabled, then revoked, most recent first', () => {
    const a = link({ id: 'a', createdAt: '2026-01-01T00:00:00Z' });
    const b = link({ id: 'b', createdAt: '2026-02-01T00:00:00Z' });
    const c = link({ id: 'c', enabled: false });
    const d = link({ id: 'd', revokedAt: '2026-11-05T00:00:00Z' });
    expect(sortDropLinks([d, c, a, b]).map((l) => l.id)).toEqual(['b', 'a', 'c', 'd']);
  });
});

describe('recipients', () => {
  it('normalises and refuses addresses', () => {
    expect(parseDropRecipient(' Bob@Entity-A.example.com ')).toEqual({
      ok: true,
      value: 'bob@entity-a.example.com',
    });
    expect(parseDropRecipient('nope')).toEqual({ ok: false, error: 'email' });
    expect(parseDropRecipient(`${'a'.repeat(250)}@example.com`)).toEqual({ ok: false, error: 'too-long' });
    expect(recipientLineMessage({ line: 1, raw: 'x', error: 'email' }).key).toBe('fieldErrors.invalid-email');
    expect(recipientLineMessage({ line: 1, raw: 'x', error: 'too-long' }).key).toBe(
      'opsDropLinks.errors.recipientTooLong',
    );
  });

  it('parses a list with duplicates and the maximum', () => {
    const list = parseDropRecipients('a@example.com\nA@example.com\nb@example.com');
    expect(list.values).toEqual(['a@example.com', 'b@example.com']);
    const many = parseDropRecipients(Array.from({ length: 21 }, (_v, i) => `u${i}@example.com`).join('\n'));
    expect(many.tooMany).toBe(true);
  });
});

describe('forms', () => {
  it('starts with 7 days, the default level and enabled', () => {
    expect(emptyDropLinkForm()).toEqual({
      label: '',
      recipientText: '',
      validityDays: 7,
      level: '',
      enabled: true,
      expiry: '',
      maxDepositsPerHour: '20',
    });
    expect(dropFormTouched(emptyDropLinkForm())).toBe(false);
    expect(dropFormTouched({ ...emptyDropLinkForm(), label: 'x' })).toBe(true);
  });

  it('builds the creation body, with the level only when chosen', () => {
    const form = {
      label: ' Invoices ',
      recipientText: 'A@example.com',
      validityDays: 30,
      level: '',
      enabled: false,
      expiry: '',
      maxDepositsPerHour: '20',
    };
    expect(dropCreateBody(form)).toEqual({
      label: 'Invoices',
      recipients: ['a@example.com'],
      validityDays: 30,
      enabled: false,
      maxDepositsPerHour: 20,
    });
    expect(dropCreateBody({ ...form, level: 'internal' }).confidentialityLevel).toBe('internal');
  });

  it('builds a merge patch of the changed fields only, null level for the default', () => {
    const original = link();
    const form = dropFormFrom(original);
    expect(dropPatchEmpty(buildDropLinkPatch(original, form))).toBe(true);
    expect(
      buildDropLinkPatch(original, {
        ...form,
        label: 'New',
        recipientText: 'a@example.com\nb@example.com',
        validityDays: 1,
        level: '',
        enabled: false,
      }),
    ).toEqual({
      label: 'New',
      recipients: ['a@example.com', 'b@example.com'],
      validityDays: 1,
      confidentialityLevel: null,
      enabled: false,
    });
    expect(buildDropLinkPatch(link({ confidentialityLevel: null }), { ...form, level: '' })).toEqual({});
    expect(buildDropLinkPatch(link({ confidentialityLevel: null }), { ...form, level: 'internal' })).toEqual({
      confidentialityLevel: 'internal',
    });
  });

  it('validates the label and the recipients', () => {
    const ok = validateDropLink(dropFormFrom(link()), fields, t);
    expect(ok).toEqual([]);
    const bad = validateDropLink({ ...emptyDropLinkForm(), label: ' ' }, fields, t);
    expect(bad.map((e) => e.id)).toEqual(['f-label', 'f-recipients']);
    expect(
      validateDropLink(
        { ...emptyDropLinkForm(), label: 'x'.repeat(101), recipientText: 'bad' },
        fields,
        t,
      ).map((e) => e.message),
    ).toEqual([
      'opsDropLinks.errors.labelTooLong {"max":100}',
      'adminComponents.lineList.invalidLines {"count":1}',
    ]);
    const many = Array.from({ length: 21 }, (_v, i) => `u${i}@example.com`).join('\n');
    expect(
      validateDropLink({ ...emptyDropLinkForm(), label: 'x', recipientText: many }, fields, t)[0]?.message,
    ).toBe('opsDropLinks.errors.recipientsTooMany {"max":20}');
  });
});

describe('errors', () => {
  it('maps the limit and the conflict to general messages', () => {
    expect(dropLinkErrorOutcome(view({ code: 'drop-link-limit-reached' }), fields, t)).toEqual({
      ok: false,
      message: 'opsDropLinks.errors.limit',
    });
    expect(dropLinkErrorOutcome(view({ code: 'state-conflict', status: 409 }), fields, t)).toEqual({
      ok: false,
      message: 'opsDropLinks.errors.conflict',
    });
  });

  it('puts validation errors on their fields, with a general message for the others', () => {
    const fieldErrors = { 'recipients.2': { code: 'invalid', message: 'bad' } };
    expect(dropLinkErrorOutcome(view({ code: 'validation-failed', fields: fieldErrors }), fields, t)).toEqual(
      {
        ok: false,
        errors: [{ id: 'f-recipients', label: 'Recipients', message: 'bad' }],
      },
    );
    const mixed = { ...fieldErrors, other: { code: 'invalid', message: 'x' } };
    expect(dropLinkErrorOutcome(view({ code: 'validation-failed', fields: mixed }), fields, t)).toMatchObject(
      {
        ok: false,
        message: 'general',
      },
    );
    expect(dropLinkErrorOutcome(view({ code: 'internal-error' }), fields, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });

  it('describes a failed action', () => {
    expect(dropActionErrorMessage(view({ status: 404 }), t)).toBe('opsDropLinks.errors.notFound');
    expect(dropActionErrorMessage(view({ status: 409 }), t)).toBe('opsDropLinks.errors.conflict');
    expect(dropActionErrorMessage(view({ status: 500 }), t)).toBe('general');
  });
});

describe('levels and secrets', () => {
  const levels = [
    { key: 'internal', labels: { en: 'Internal', fr: 'Interne' } },
    { key: 'x', labels: {} },
  ] as unknown as TenantLevel[];

  it('labels levels in a language, falling back to English then the key', () => {
    expect(levelLabel(levels, 'internal', 'fr')).toBe('Interne');
    expect(levelLabel(levels, 'x', 'fr')).toBe('x');
    expect(levelLabel(levels, 'gone', 'fr')).toBe('gone');
    expect(levelOptions(levels, 'en', 'Default')[0]).toEqual({ value: '', label: 'Default' });
    expect(levelOptions(levels, 'en', 'Default')).toHaveLength(3);
  });

  it('drops the token and the url of a created link', () => {
    const created = { ...link(), token: 'ttd_x', url: 'https://t.example.com/drop/ttd_x' };
    const plain = withoutSecret(created);
    expect(plain).toEqual(link());
    expect(plain).not.toHaveProperty('token');
    expect(plain).not.toHaveProperty('url');
  });
});

describe('drop link expiry, hourly cap and unused', () => {
  const localEnd = (y: number, m: number, d: number): string =>
    new Date(y, m - 1, d, 23, 59, 59).toISOString();

  it('shows the defaults and the existing values in the form', () => {
    expect(emptyDropLinkForm()).toMatchObject({ expiry: '', maxDepositsPerHour: '20' });
    expect(DEFAULT_DEPOSITS_PER_HOUR).toBe(20);
    const f = dropFormFrom(link({ expiresAt: localEnd(2027, 3, 9), maxDepositsPerHour: 5 }));
    expect(f.expiry).toBe('2027-03-09');
    expect(f.maxDepositsPerHour).toBe('5');
    expect(dropFormFrom(link()).expiry).toBe('');
    expect(dropFormFrom(link({ expiresAt: null })).expiry).toBe('');
  });

  it('converts instants to local days', () => {
    expect(dateInputFrom(undefined)).toBe('');
    expect(dateInputFrom('nope')).toBe('');
    expect(dateInputFrom(localEnd(2027, 12, 31))).toBe('2027-12-31');
  });

  it('parses the cap within 1..1000', () => {
    expect(parseDepositsPerHour(' 20 ')).toBe(20);
    expect(parseDepositsPerHour('1')).toBe(1);
    expect(parseDepositsPerHour('1000')).toBe(1000);
    for (const bad of ['', '0', '1001', '1.5', '-3', 'abc']) {
      expect(parseDepositsPerHour(bad)).toBeUndefined();
    }
  });

  it('puts the expiry in the body only when set, and the cap always', () => {
    const base = { ...emptyDropLinkForm(), label: 'L', recipientText: 'a@entity-a.example.com' };
    const none = dropCreateBody(base);
    expect(none).not.toHaveProperty('expiresAt');
    expect(none.maxDepositsPerHour).toBe(20);
    const set = dropCreateBody({ ...base, expiry: '2027-03-09', maxDepositsPerHour: '50' });
    expect(set.expiresAt).toBe(localEnd(2027, 3, 9));
    expect(set.maxDepositsPerHour).toBe(50);
    expect(dropCreateBody({ ...base, maxDepositsPerHour: 'x' }).maxDepositsPerHour).toBe(20);
  });

  it('patches the expiry and the cap only when changed', () => {
    const l = link({ expiresAt: localEnd(2027, 3, 9) });
    expect(buildDropLinkPatch(l, dropFormFrom(l))).toEqual({});
    expect(buildDropLinkPatch(l, { ...dropFormFrom(l), expiry: '2027-04-01' })).toEqual({
      expiresAt: localEnd(2027, 4, 1),
    });
    expect(buildDropLinkPatch(l, { ...dropFormFrom(l), expiry: '' })).toEqual({ expiresAt: null });
    expect(buildDropLinkPatch(l, { ...dropFormFrom(l), expiry: 'garbage' })).toEqual({});
    const open = link();
    expect(buildDropLinkPatch(open, { ...dropFormFrom(open), expiry: '2027-04-01' })).toEqual({
      expiresAt: localEnd(2027, 4, 1),
    });
    expect(buildDropLinkPatch(open, { ...dropFormFrom(open), maxDepositsPerHour: '30' })).toEqual({
      maxDepositsPerHour: 30,
    });
    expect(buildDropLinkPatch(open, { ...dropFormFrom(open), maxDepositsPerHour: '0' })).toEqual({});
  });

  it('validates the expiry and the cap', () => {
    const now = new Date(2026, 10, 6, 12, 0, 0);
    const form = { ...emptyDropLinkForm(), label: 'L', recipientText: 'a@entity-a.example.com' };
    expect(validateDropLink(form, fields, t, now)).toEqual([]);
    expect(validateDropLink({ ...form, expiry: '2026-11-06' }, fields, t, now)).toEqual([]);
    expect(validateDropLink({ ...form, expiry: '2026-11-05' }, fields, t, now)[0]).toMatchObject({
      id: 'f-expiry',
      message: 'opsDropLinks.errors.expiryPast',
    });
    expect(validateDropLink({ ...form, expiry: '2026-02-31' }, fields, t, now)[0]?.message).toBe(
      'opsDropLinks.errors.expiryInvalid',
    );
    const bad = validateDropLink({ ...form, maxDepositsPerHour: '5000' }, fields, t, now);
    expect(bad[0]?.id).toBe('f-cap');
    expect(bad[0]?.message).toContain('opsDropLinks.errors.capInvalid');
    expect(validateDropLink(form, fields, t)).toEqual([]);
  });

  it('reports an expired link, after revoked and before disabled', () => {
    const now = new Date('2026-11-06T12:00:00Z');
    expect(dropLinkStatus(link({ expiresAt: '2026-11-05T00:00:00Z' }), now)).toBe('expired');
    expect(dropLinkStatus(link({ expiresAt: '2026-11-07T00:00:00Z' }), now)).toBe('active');
    expect(dropLinkStatus(link({ expiresAt: 'bad' }), now)).toBe('active');
    expect(dropLinkStatus(link({ expiresAt: null }), now)).toBe('active');
    expect(dropLinkStatus(link({ expiresAt: '2026-11-05T00:00:00Z', enabled: false }), now)).toBe('expired');
    expect(
      dropLinkStatus(link({ expiresAt: '2026-11-05T00:00:00Z', revokedAt: '2026-11-01T00:00:00Z' }), now),
    ).toBe('revoked');
    expect(dropStatusView('expired')).toEqual({ variant: 'warning', key: 'opsDropLinks.status.expired' });
    const order = sortDropLinks(
      [
        link({ id: 'r', revokedAt: '2026-11-01T00:00:00Z' }),
        link({ id: 'e', expiresAt: '2026-11-05T00:00:00Z' }),
        link({ id: 'd', enabled: false }),
        link({ id: 'a' }),
      ],
      now,
    ).map((l) => l.id);
    expect(order).toEqual(['a', 'd', 'e', 'r']);
    expect(isDropLinkManageable(link({ expiresAt: '2026-11-05T00:00:00Z' }))).toBe(true);
  });
});
