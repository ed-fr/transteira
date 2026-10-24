import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import en from '../../../locales/en/opsTokens.json';
import fr from '../../../locales/fr/opsTokens.json';
import { parseCidr } from '../../forms/cidr';
import {
  buildTokenPatch,
  createBody,
  createFormTouched,
  editFormFrom,
  emptyCreateForm,
  expiryFromDate,
  hasAllAnyAddress,
  hasAnyAddress,
  isManageable,
  lineOfEntry,
  parseSender,
  parseSenderList,
  parseTokenCidrList,
  prefixLabel,
  revokeErrorMessage,
  senderLineMessage,
  sendersText,
  sortTokens,
  statusView,
  todayInput,
  tokenCidrLineMessage,
  tokenErrorOutcome,
  tokenFieldErrors,
  tokenStatus,
  validateCreate,
  validateEdit,
  validateExpiry,
  withAnyAddress,
  type ApiToken,
  type TokenStatus,
} from './tokens';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const fields = {
  name: { id: 'name', label: 'Name' },
  allowedCidrs: { id: 'cidrs', label: 'Ranges' },
  allowedSenders: { id: 'senders', label: 'Senders' },
  expiresAt: { id: 'expiry', label: 'Expiry' },
};

const NOW = new Date(2026, 9, 24, 12, 0, 0);

function token(over: Partial<ApiToken> = {}): ApiToken {
  return {
    id: 'tok_01JABCJ5M6N7P8Q9R0S1T2V3V4',
    name: 'Nightly ERP export',
    prefix: 'tt_EXAM',
    allowedCidrs: ['10.10.20.15/32'],
    allowedSenders: ['reporting@entity-a.example.com'],
    createdBy: 'admin.entity-a',
    createdAt: '2026-10-01T08:00:00Z',
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    ...over,
  };
}

function view(over: Partial<ErrorView> = {}): ErrorView {
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

function hasKey(bundle: unknown, key: string): boolean {
  const parts = key.replace(/^opsTokens\./, '').split('.');
  let node: unknown = bundle;
  for (const p of parts) {
    if (typeof node !== 'object' || node === null || !Object.hasOwn(node, p)) {
      return false;
    }
    node = (node as Record<string, unknown>)[p];
  }
  return typeof node === 'string';
}

describe('tokenStatus', () => {
  it('is active without expiry nor revocation', () => {
    expect(tokenStatus(token(), NOW)).toBe('active');
    expect(tokenStatus({ expiresAt: undefined, revokedAt: undefined }, NOW)).toBe('active');
  });

  it('is expired once the expiry is reached', () => {
    expect(tokenStatus(token({ expiresAt: NOW.toISOString() }), NOW)).toBe('expired');
    expect(tokenStatus(token({ expiresAt: '2026-01-01T00:00:00Z' }), NOW)).toBe('expired');
    expect(tokenStatus(token({ expiresAt: '2027-01-01T00:00:00Z' }), NOW)).toBe('active');
  });

  it('ignores an unreadable expiry', () => {
    expect(tokenStatus(token({ expiresAt: 'soon' }), NOW)).toBe('active');
  });

  it('puts the revocation first', () => {
    expect(
      tokenStatus(token({ revokedAt: '2026-10-02T00:00:00Z', expiresAt: '2026-01-01T00:00:00Z' }), NOW),
    ).toBe('revoked');
  });

  it('maps each status to a badge with a translated label', () => {
    const all: TokenStatus[] = ['active', 'expired', 'revoked'];
    expect(all.map((s) => statusView(s).variant)).toEqual(['ok', 'warning', 'missing']);
    for (const s of all) {
      expect(hasKey(en, statusView(s).key)).toBe(true);
    }
  });

  it('manages active tokens only', () => {
    expect(isManageable(token(), NOW)).toBe(true);
    expect(isManageable(token({ revokedAt: '2026-10-02T00:00:00Z' }), NOW)).toBe(false);
  });

  it('sorts active tokens first, then the most recent', () => {
    const a = token({ id: 'a', createdAt: '2026-10-01T00:00:00Z' });
    const b = token({ id: 'b', createdAt: '2026-10-05T00:00:00Z' });
    const r = token({ id: 'r', createdAt: '2026-10-10T00:00:00Z', revokedAt: '2026-10-11T00:00:00Z' });
    const e = token({ id: 'e', createdAt: '2026-10-09T00:00:00Z', expiresAt: '2026-10-20T00:00:00Z' });
    expect(sortTokens([r, a, e, b], NOW).map((x) => x.id)).toEqual(['b', 'a', 'e', 'r']);
  });

  it('shows the prefix with an ellipsis', () => {
    expect(prefixLabel('tt_EXAM')).toBe('tt_EXAM…');
  });

  it('describes the senders, or the internal domains when empty', () => {
    expect(sendersText(token({ allowedSenders: [] }), t)).toBe('opsTokens.list.anySender');
    expect(sendersText(token({ allowedSenders: ['a@example.com', 'example.org'] }), t)).toBe(
      'a@example.com, example.org',
    );
  });
});

describe('parseSender', () => {
  it('accepts and normalises an address', () => {
    expect(parseSender(' Reporting@Entity-A.Example.com ')).toEqual({
      ok: true,
      value: 'reporting@entity-a.example.com',
    });
  });

  it('accepts and normalises a domain', () => {
    expect(parseSender('Example.COM')).toEqual({ ok: true, value: 'example.com' });
  });

  it('refuses an invalid address', () => {
    expect(parseSender('a b@example.com')).toEqual({ ok: false, error: 'email' });
    expect(parseSender('a@localhost')).toEqual({ ok: false, error: 'email' });
    expect(parseSender('a@1.2.3.4')).toEqual({ ok: false, error: 'email' });
  });

  it('refuses an invalid domain, with a suggestion for a trailing dot', () => {
    expect(parseSender('not a domain')).toEqual({ ok: false, error: 'domain' });
    expect(parseSender('example.com.')).toEqual({ ok: false, error: 'domain', suggestion: 'example.com' });
  });

  it('refuses a too long entry', () => {
    expect(parseSender(`${'a'.repeat(250)}@example.com`)).toEqual({ ok: false, error: 'too-long' });
  });

  it('parses a list with duplicates and errors', () => {
    const list = parseSenderList('a@example.com\nA@example.com\nbad entry\n\nexample.org');
    expect(list.values).toEqual(['a@example.com', 'example.org']);
    expect(list.duplicates).toEqual([2]);
    expect(list.errors.map((e) => e.line)).toEqual([3]);
  });

  it('has a translated message per reason', () => {
    const msgs = [
      senderLineMessage({ line: 1, raw: 'x', error: 'email' }),
      senderLineMessage({ line: 1, raw: 'x', error: 'domain' }),
      senderLineMessage({ line: 1, raw: 'x', error: 'too-long' }),
      senderLineMessage({ line: 1, raw: 'x.com.', error: 'domain', suggestion: 'x.com' }),
    ];
    expect(msgs[3]).toEqual({
      key: 'opsTokens.errors.sender.domainSuggestion',
      params: { domain: 'x.com' },
    });
    for (const m of msgs) {
      expect(hasKey(en, m.key)).toBe(true);
      expect(hasKey(fr, m.key)).toBe(true);
    }
  });

  it('reuses the range messages of the network screen', () => {
    expect(tokenCidrLineMessage({ line: 1, raw: 'x', error: 'syntax' }).key).toBe(
      'adminTenants.network.errors.cidr.syntax',
    );
  });
});

describe('any address', () => {
  it('detects a catch-all range', () => {
    expect(hasAnyAddress(['10.0.0.0/8'])).toBe(false);
    expect(hasAnyAddress(['10.0.0.0/8', '::/0'])).toBe(true);
    expect(hasAnyAddress(parseTokenCidrList('0.0.0.0/0').values)).toBe(true);
  });

  it('reports when both catch-all ranges are present (shortcut disabled)', () => {
    expect(hasAllAnyAddress(['::/0'])).toBe(false);
    expect(hasAllAnyAddress(['10.0.0.0/8', '0.0.0.0/0'])).toBe(false);
    expect(hasAllAnyAddress(parseTokenCidrList('0.0.0.0/0\n::/0').values)).toBe(true);
  });

  it('adds both catch-all ranges, keeping the typed lines', () => {
    expect(withAnyAddress('')).toBe('0.0.0.0/0\n::/0');
    expect(withAnyAddress('10.0.0.0/8\n\n')).toBe('10.0.0.0/8\n0.0.0.0/0\n::/0');
    expect(withAnyAddress('::/0')).toBe('::/0\n0.0.0.0/0');
    expect(withAnyAddress('0.0.0.0/0\n::/0')).toBe('0.0.0.0/0\n::/0');
  });
});

describe('expiry', () => {
  it('converts a date to the end of that local day', () => {
    const iso = expiryFromDate('2027-06-30');
    expect(iso).toBe(new Date(2027, 5, 30, 23, 59, 59).toISOString());
  });

  it('gives nothing for an empty or invalid date', () => {
    expect(expiryFromDate('')).toBeUndefined();
    expect(expiryFromDate('2027-02-30')).toBeUndefined();
    expect(expiryFromDate('30/06/2027')).toBeUndefined();
  });

  it('accepts an empty date and requires a future day', () => {
    expect(validateExpiry('', NOW)).toBeUndefined();
    expect(validateExpiry('nope', NOW)).toBe('invalid');
    expect(validateExpiry('2026-10-23', NOW)).toBe('past');
    // Today is still valid until its end.
    expect(validateExpiry('2026-10-24', NOW)).toBeUndefined();
    expect(validateExpiry('2026-10-24', new Date(2026, 9, 24, 23, 59, 59))).toBe('past');
    expect(validateExpiry('2027-01-01', NOW)).toBeUndefined();
  });

  it('gives today as minimum of the date input', () => {
    expect(todayInput(new Date(2026, 0, 5, 1, 0, 0))).toBe('2026-01-05');
    expect(todayInput(NOW)).toBe('2026-10-24');
  });
});

describe('createBody', () => {
  it('sends the normalised lists and the trimmed name, without expiry by default', () => {
    expect(
      createBody({
        name: '  ERP ',
        cidrText: '10.10.20.15\n10.10.20.15/32\nbad',
        senderText: 'Reporting@example.com',
        expiry: '',
      }),
    ).toEqual({
      name: 'ERP',
      allowedCidrs: ['10.10.20.15/32'],
      allowedSenders: ['reporting@example.com'],
    });
  });

  it('sends an empty sender list and the expiry when chosen', () => {
    const body = createBody({
      name: 'x',
      cidrText: withAnyAddress(''),
      senderText: '',
      expiry: '2027-06-30',
    });
    expect(body.allowedCidrs).toEqual(['0.0.0.0/0', '::/0']);
    expect(body.allowedSenders).toEqual([]);
    expect(body.expiresAt).toBe(new Date(2027, 5, 30, 23, 59, 59).toISOString());
  });

  it('tells whether the form was touched', () => {
    expect(createFormTouched(emptyCreateForm())).toBe(false);
    expect(createFormTouched({ ...emptyCreateForm(), expiry: '2027-01-01' })).toBe(true);
  });
});

describe('buildTokenPatch', () => {
  it('is empty when nothing changed', () => {
    const tok = token();
    expect(buildTokenPatch(tok, editFormFrom(tok))).toEqual({});
  });

  it('sends only the changed fields', () => {
    const tok = token();
    expect(buildTokenPatch(tok, { ...editFormFrom(tok), name: ' Renamed ' })).toEqual({ name: 'Renamed' });
    expect(buildTokenPatch(tok, { ...editFormFrom(tok), cidrText: '10.10.20.16' })).toEqual({
      allowedCidrs: ['10.10.20.16/32'],
    });
  });

  it('sends an emptied sender list as []', () => {
    const tok = token();
    expect(buildTokenPatch(tok, { ...editFormFrom(tok), senderText: '  ' })).toEqual({ allowedSenders: [] });
  });

  it('does not count a reformatted list as a change', () => {
    const tok = token();
    expect(
      buildTokenPatch(tok, { ...editFormFrom(tok), senderText: 'REPORTING@entity-a.example.com\n' }),
    ).toEqual({});
  });
});

describe('validation', () => {
  const valid = { name: 'ERP', cidrText: '10.0.0.0/8', senderText: '', expiry: '' };

  it('accepts a valid form', () => {
    expect(validateCreate(valid, fields, t, NOW)).toEqual([]);
    expect(validateEdit(valid, fields, t)).toEqual([]);
  });

  it('requires a name of 100 characters at most', () => {
    expect(validateEdit({ ...valid, name: ' ' }, fields, t)).toEqual([
      { id: 'name', label: 'Name', message: 'fieldErrors.required' },
    ]);
    expect(validateEdit({ ...valid, name: 'x'.repeat(101) }, fields, t)[0]?.message).toBe(
      'opsTokens.errors.nameTooLong {"max":100}',
    );
    // Characters are code points, as the server counts them: 100 emoji (200 UTF-16 units) pass.
    expect(validateEdit({ ...valid, name: '🔑'.repeat(100) }, fields, t)).toEqual([]);
    expect(validateEdit({ ...valid, name: '🔑'.repeat(101) }, fields, t)[0]?.message).toBe(
      'opsTokens.errors.nameTooLong {"max":100}',
    );
  });

  it('requires at least one valid range, at most 100', () => {
    expect(validateEdit({ ...valid, cidrText: '' }, fields, t)[0]?.message).toBe(
      'opsTokens.errors.cidrsRequired',
    );
    expect(validateEdit({ ...valid, cidrText: '10.0.0.0/8\nbad' }, fields, t)[0]?.message).toBe(
      'adminComponents.lineList.invalidLines {"count":1}',
    );
    const many = Array.from({ length: 101 }, (_, i) => `10.0.${i}.0/24`).join('\n');
    expect(validateEdit({ ...valid, cidrText: many }, fields, t)[0]?.message).toBe('fieldErrors.too-many');
  });

  it('refuses invalid senders', () => {
    expect(validateEdit({ ...valid, senderText: 'bad entry' }, fields, t)).toEqual([
      { id: 'senders', label: 'Senders', message: 'adminComponents.lineList.invalidLines {"count":1}' },
    ]);
  });

  it('refuses an invalid or past expiry on creation', () => {
    expect(validateCreate({ ...valid, expiry: '2026-10-01' }, fields, t, NOW)).toEqual([
      { id: 'expiry', label: 'Expiry', message: 'opsTokens.errors.expiryPast' },
    ]);
    expect(validateCreate({ ...valid, expiry: 'x' }, fields, t, NOW)[0]?.message).toBe(
      'opsTokens.errors.expiryInvalid',
    );
  });

  it('ignores the expiry without its field', () => {
    const { expiresAt: _ignored, ...noExpiry } = fields;
    expect(validateCreate({ ...valid, expiry: 'x' }, noExpiry, t, NOW)).toEqual([]);
  });
});

describe('errors', () => {
  const sent = {
    cidrText: '10.0.0.0/8\n\nbad\n10.0.0.0/8\n192.0.2.0/24',
    senderText: 'a@example.com\nexample.org',
  };

  it('finds the line of an entry of the list sent', () => {
    expect(lineOfEntry(sent.cidrText, parseCidr, 0)).toBe(1);
    expect(lineOfEntry(sent.cidrText, parseCidr, 1)).toBe(5);
    expect(lineOfEntry(sent.cidrText, parseCidr, 2)).toBeUndefined();
  });

  it('points an entry error at its line', () => {
    const r = tokenFieldErrors(
      view({
        fields: {
          'allowedCidrs.1': { code: 'invalid-format', message: 'Bad format.' },
          'allowedSenders.1': { code: 'invalid-format', message: 'Bad sender.' },
          name: { code: 'invalid-format', message: 'Bad name.' },
        },
      }),
      fields,
      sent,
      t,
    );
    expect(r.unmatched).toEqual([]);
    expect(r.errors).toEqual([
      { id: 'name', label: 'Name', message: 'Bad name.' },
      {
        id: 'cidrs',
        label: 'Ranges',
        message: 'adminComponents.lineList.lineError {"line":5,"message":"Bad format."}',
      },
      {
        id: 'senders',
        label: 'Senders',
        message: 'adminComponents.lineList.lineError {"line":2,"message":"Bad sender."}',
      },
    ]);
  });

  it('names the position when the line cannot be found, and keeps the first error per field', () => {
    const r = tokenFieldErrors(
      view({
        fields: {
          'allowedCidrs.9': { code: 'invalid-format', message: 'Bad.' },
          'allowedCidrs.0': { code: 'invalid-format', message: 'Ignored.' },
          allowedSenders: { code: 'too-many', message: 'Too many.' },
          expiresAt: { code: 'invalid-format', message: 'Past.' },
          other: { code: 'unknown', message: 'Unknown.' },
        },
      }),
      fields,
      sent,
      t,
    );
    expect(r.errors.map((e) => e.message)).toEqual([
      'opsTokens.errors.entry {"position":10,"message":"Bad."}',
      'Too many.',
      'Past.',
    ]);
    expect(r.unmatched).toEqual(['other']);
  });

  it('maps a validation failure to field errors only when all are placed', () => {
    const placed = view({
      code: 'validation-failed',
      status: 400,
      fields: { name: { code: 'invalid-format', message: 'Bad name.' } },
    });
    expect(tokenErrorOutcome(placed, fields, sent, t)).toEqual({
      ok: false,
      errors: [{ id: 'name', label: 'Name', message: 'Bad name.' }],
    });
    const unplaced = view({
      code: 'validation-failed',
      status: 400,
      fields: { foo: { code: 'invalid-format', message: 'x' } },
    });
    expect(tokenErrorOutcome(unplaced, fields, sent, t)).toEqual({
      ok: false,
      message: 'general',
      errors: [],
    });
  });

  it('reports a revoked token on 409', () => {
    expect(tokenErrorOutcome(view({ code: 'state-conflict', status: 409 }), fields, sent, t)).toEqual({
      ok: false,
      message: 'opsTokens.errors.revoked',
    });
    expect(tokenErrorOutcome(view({ status: 409 }), fields, sent, t)).toEqual({
      ok: false,
      message: 'opsTokens.errors.revoked',
    });
  });

  it('shows the general message otherwise', () => {
    expect(tokenErrorOutcome(view({ code: 'forbidden', status: 403 }), fields, sent, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });

  it('maps revocation errors', () => {
    expect(revokeErrorMessage(view({ status: 404, code: 'not-found' }), t)).toBe('opsTokens.errors.notFound');
    expect(revokeErrorMessage(view({ status: 500 }), t)).toBe('general');
  });

  it('has every runtime message key in both languages', () => {
    const keys = [
      'opsTokens.errors.cidrsRequired',
      'opsTokens.errors.nameTooLong',
      'opsTokens.errors.expiryInvalid',
      'opsTokens.errors.expiryPast',
      'opsTokens.errors.entry',
      'opsTokens.errors.revoked',
      'opsTokens.errors.notFound',
      'opsTokens.list.anySender',
    ];
    for (const key of keys) {
      expect(hasKey(en, key), key).toBe(true);
      expect(hasKey(fr, key), key).toBe(true);
    }
  });
});
