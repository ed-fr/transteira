import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import en from '../../../locales/en/sysProvisioning.json';
import fr from '../../../locales/fr/sysProvisioning.json';
import {
  committedBytes,
  createBody,
  createErrorOutcome,
  emptyCreateForm,
  parseMaxTenants,
  parseRange,
  parseRangeList,
  parseSuffix,
  parseSuffixList,
  rangeLineMessage,
  revokeErrorMessage,
  sortTokens,
  suffixLineMessage,
  tenantsText,
  validateCreate,
  type CreateForm,
  type ProvisioningFields,
  type ProvisioningToken,
} from './provisioningTokens';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const NOW = new Date('2026-11-01T10:00:00Z');

const fields: ProvisioningFields = {
  name: { id: 'f-name', label: 'Name' },
  allowedCidrs: { id: 'f-cidrs', label: 'Ranges' },
  allowedFqdnSuffixes: { id: 'f-suffixes', label: 'Suffixes' },
  maxTenants: { id: 'f-tenants', label: 'Tenants' },
  maxStorageQuotaBytes: { id: 'f-quota', label: 'Quota' },
  maxTransferBytes: { id: 'f-transfer', label: 'Transfer' },
  expiresAt: { id: 'f-expiry', label: 'Expiry' },
  code: { id: 'f-code', label: 'Code' },
};

function token(over: Partial<ProvisioningToken> = {}): ProvisioningToken {
  return {
    id: 'prv_1',
    name: 'Provider',
    prefix: 'ttp_EXAM',
    allowedCidrs: ['198.51.100.0/24'],
    allowedFqdnSuffixes: ['.transfer.example.com'],
    maxStorageQuotaBytes: 2 ** 40,
    maxTenants: 10,
    tenantsCreated: 3,
    createdBy: 'adm_1',
    createdAt: '2026-10-01T10:00:00Z',
    ...over,
  };
}

function valid(over: Partial<CreateForm> = {}): CreateForm {
  return {
    name: 'Provider',
    cidrText: '198.51.100.0/24',
    suffixText: '.transfer.example.com',
    maxTenants: '10',
    maxStorageQuotaBytes: 2 ** 40,
    maxTransferBytes: null,
    expiry: '',
    mode: 'totp',
    code: '123 456',
    ...over,
  };
}

function view(over: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'general',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...over,
  };
}

describe('ranges', () => {
  it('accepts a CIDR and refuses the catch-all ranges', () => {
    expect(parseRange('198.51.100.0/24')).toEqual({ ok: true, value: '198.51.100.0/24' });
    expect(parseRange('0.0.0.0/0')).toEqual({ ok: false, error: 'catch-all' });
    expect(parseRange('::/0')).toEqual({ ok: false, error: 'catch-all' });
    expect(parseRange('nope')).toMatchObject({ ok: false, error: 'syntax' });
  });

  it('parses the list and translates the line errors', () => {
    const list = parseRangeList('198.51.100.0/24\n0.0.0.0/0\nnope');
    expect(list.values).toEqual(['198.51.100.0/24']);
    expect(list.errors.map((e) => e.error)).toEqual(['catch-all', 'syntax']);
    expect(rangeLineMessage(list.errors[0]!).key).toBe('sysProvisioning.errors.catchAll');
    expect(rangeLineMessage(list.errors[1]!).key).toBe('adminTenants.network.errors.cidr.syntax');
  });
});

describe('suffixes', () => {
  it.each([
    ['.transfer.example.com', '.transfer.example.com'],
    ['  .Transfer.Example.COM ', '.transfer.example.com'],
  ])('accepts %s', (input, expected) => {
    expect(parseSuffix(input)).toEqual({ ok: true, value: expected });
  });

  it.each([
    ['transfer.example.com', 'dot'],
    ['.com', 'invalid'],
    ['.', 'invalid'],
    ['.bad_label.example.com', 'invalid'],
  ])('refuses %s', (input, error) => {
    expect(parseSuffix(input)).toMatchObject({ ok: false, error });
  });

  it('parses the list and translates the line errors', () => {
    const list = parseSuffixList('.a.example.com\nb.example.com\n.com\n.a.example.com');
    expect(list.values).toEqual(['.a.example.com']);
    expect(list.duplicates).toEqual([4]);
    expect(list.errors.map((e) => suffixLineMessage(e).key)).toEqual([
      'sysProvisioning.errors.suffixDot',
      'sysProvisioning.errors.suffixInvalid',
    ]);
  });
});

describe('numbers and committed volume', () => {
  it.each([
    ['5', 5],
    [' 12 ', 12],
    ['', null],
    ['0', null],
    ['-1', null],
    ['1.5', null],
    ['abc', null],
    ['99999999999999999999', null],
  ])('parseMaxTenants(%j)', (input, expected) => {
    expect(parseMaxTenants(input)).toBe(expected);
  });

  it('multiplies the tenants by the quota, null while one is missing', () => {
    expect(committedBytes(10, 2 ** 40)).toBe(10 * 2 ** 40);
    expect(committedBytes(null, 2 ** 40)).toBeNull();
    expect(committedBytes(10, null)).toBeNull();
    expect(committedBytes(Number.MAX_VALUE, Number.MAX_VALUE)).toBe('large');
    expect(committedBytes(2 ** 30, 2 ** 30)).toBe('large');
  });

  it('shows the tenant counter', () => {
    expect(tenantsText(token())).toBe('3 / 10');
  });
});

describe('sortTokens', () => {
  it('puts active tokens first, then expired, then revoked, newest first', () => {
    const rows = sortTokens(
      [
        token({ id: 'revoked', revokedAt: '2026-10-02T00:00:00Z' }),
        token({ id: 'expired', expiresAt: '2026-10-05T00:00:00Z' }),
        token({ id: 'old', createdAt: '2026-09-01T00:00:00Z' }),
        token({ id: 'new', createdAt: '2026-10-20T00:00:00Z' }),
      ],
      NOW,
    );
    expect(rows.map((r) => r.id)).toEqual(['new', 'old', 'expired', 'revoked']);
  });
});

describe('createBody', () => {
  it('sends the normalised values and the TOTP code without spaces', () => {
    expect(createBody(valid())).toEqual({
      name: 'Provider',
      allowedCidrs: ['198.51.100.0/24'],
      allowedFqdnSuffixes: ['.transfer.example.com'],
      maxStorageQuotaBytes: 2 ** 40,
      maxTenants: 10,
      code: '123456',
    });
  });

  it('adds the optional caps and expiry, and sends a recovery code instead of the TOTP code', () => {
    const body = createBody(
      valid({ maxTransferBytes: 2 ** 30, expiry: '2027-01-15', mode: 'recovery', code: ' abcd-efgh ' }),
    );
    expect(body.maxTransferBytes).toBe(2 ** 30);
    expect(body.expiresAt).toBeDefined();
    expect(body.recoveryCode).toBe('abcd-efgh');
    expect(body).not.toHaveProperty('code');
  });
});

describe('validateCreate', () => {
  it('accepts a complete form', () => {
    expect(validateCreate(valid(), fields, t, NOW)).toEqual([]);
  });

  it('lists every missing field in the order of the form', () => {
    const errors = validateCreate(emptyCreateForm(), fields, t, NOW);
    expect(errors.map((e) => e.id)).toEqual([
      'f-name',
      'f-cidrs',
      'f-suffixes',
      'f-tenants',
      'f-quota',
      'f-code',
    ]);
  });

  it('reports invalid lists, number, expiry and code', () => {
    const errors = validateCreate(
      valid({
        name: 'x'.repeat(101),
        cidrText: '0.0.0.0/0',
        suffixText: '.com',
        maxTenants: '0',
        expiry: '2020-01-01',
        code: '12',
      }),
      fields,
      t,
      NOW,
    );
    expect(errors.map((e) => e.id)).toEqual([
      'f-name',
      'f-cidrs',
      'f-suffixes',
      'f-tenants',
      'f-expiry',
      'f-code',
    ]);
  });

  it('refuses too many tenants, too many lines, and a long recovery code', () => {
    const many = Array.from({ length: 101 }, (_, i) => `10.0.${i}.0/24`).join('\n');
    const errors = validateCreate(
      valid({ cidrText: many, maxTenants: '100001', mode: 'recovery', code: 'x'.repeat(40) }),
      fields,
      t,
      NOW,
    );
    expect(errors.map((e) => e.id)).toEqual(['f-cidrs', 'f-tenants', 'f-code']);
  });
});

describe('createErrorOutcome', () => {
  const sent = { cidrText: '198.51.100.0/24\n198.51.101.0/24', suffixText: '.a.example.com\n.b.example.com' };

  it('puts a wrong code on the code field, with the attempts left', () => {
    const outcome = createErrorOutcome(
      view({ code: 'invalid-credentials', status: 401, attemptsRemaining: 1 }),
      fields,
      sent,
      t,
    );
    expect(outcome).toMatchObject({ ok: false, errors: [{ id: 'f-code' }] });
    if (!outcome.ok) {
      expect(outcome.errors?.[0]?.message).toContain('adminAuth.totp.attemptsRemaining');
    }
  });

  it('puts a wrong code without attempts count on the code field alone', () => {
    const outcome = createErrorOutcome(view({ status: 401 }), fields, sent, t);
    if (outcome.ok) {
      throw new Error('expected a failure');
    }
    expect(outcome.errors?.[0]?.message).toBe('adminAuth.totp.invalid');
  });

  it('places field errors, the list entries by line, and the recovery code on the code field', () => {
    const outcome = createErrorOutcome(
      view({
        code: 'validation-failed',
        status: 400,
        fields: {
          'allowedFqdnSuffixes.1': { code: 'invalid', message: 'bad suffix' },
          'allowedCidrs.0': { code: 'invalid', message: 'bad range' },
          maxTenants: { code: 'invalid', message: 'bad number' },
          recoveryCode: { code: 'invalid', message: 'bad code' },
          name: { code: 'required', message: 'needed' },
          'name.extra': { code: 'x', message: 'ignored' },
        },
      }),
      fields,
      sent,
      t,
    );
    if (outcome.ok) {
      throw new Error('expected a failure');
    }
    expect(outcome.message).toBeUndefined();
    expect(outcome.errors?.map((e) => e.id)).toEqual([
      'f-name',
      'f-cidrs',
      'f-suffixes',
      'f-tenants',
      'f-code',
    ]);
    expect(outcome.errors?.[1]?.message).toContain('"line":1');
    expect(outcome.errors?.[2]?.message).toContain('"line":2');
  });

  it('points at the position when the line of an entry cannot be told, and adds a general message for unknown fields', () => {
    const outcome = createErrorOutcome(
      view({
        code: 'validation-failed',
        fields: {
          'allowedCidrs.9': { code: 'invalid', message: 'bad range' },
          unknown: { code: 'invalid', message: 'who knows' },
        },
      }),
      fields,
      sent,
      t,
    );
    if (outcome.ok) {
      throw new Error('expected a failure');
    }
    expect(outcome.message).toBe('general');
    expect(outcome.errors?.[0]?.message).toContain('opsTokens.errors.entry');
  });

  it('shows the general message otherwise, the rate limit included', () => {
    expect(
      createErrorOutcome(view({ code: 'rate-limited', status: 429, message: 'slow down' }), fields, sent, t),
    ).toEqual({
      ok: false,
      message: 'slow down',
    });
  });
});

describe('revokeErrorMessage', () => {
  it('says the token is gone on a 404, otherwise the general message', () => {
    expect(revokeErrorMessage(view({ status: 404 }), t)).toBe('sysProvisioning.errors.notFound');
    expect(revokeErrorMessage(view({ status: 500, message: 'boom' }), t)).toBe('boom');
  });
});

describe('locale bundles', () => {
  function keys(node: unknown, prefix = ''): string[] {
    if (typeof node !== 'object' || node === null) {
      return [prefix];
    }
    return Object.entries(node).flatMap(([k, v]) => keys(v, prefix === '' ? k : `${prefix}.${k}`));
  }

  it('hold the same keys in French and in English', () => {
    expect(keys(fr).sort()).toEqual(keys(en).sort());
  });
});
