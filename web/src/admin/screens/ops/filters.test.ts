import { describe, expect, expectTypeOf, it } from 'vitest';
import type { QueryParams } from '../../../shared/api/client';
import type { operations } from '../../../shared/api/schema';
import {
  ACTION_MAX_LENGTH,
  ACTOR_MAX_LENGTH,
  AUDIT_FILTERS,
  BLOCKLIST_FILTERS,
  DEFAULT_LIMIT,
  INVITATION_FILTERS,
  TRANSFER_FILTERS,
  dayToInstant,
  filtersToApiParams,
  filtersToForm,
  filtersToQuery,
  formToFilters,
  isDay,
  isEmail,
  isEmpty,
  parseFilters,
  pathWithFilters,
  validateFilters,
  type AuditFilters,
  type BlocklistKind,
  type InvitationStatus,
  type TransferFilters,
  type TransferStatus,
} from './filters';

/** Query parameters accepted by the typed client for an operation. */
type ClientQuery<O extends keyof operations> = NonNullable<operations[O]['parameters']['query']> &
  QueryParams;

describe('isDay', () => {
  it('accepts real calendar days only', () => {
    expect(isDay('2026-10-24')).toBe(true);
    expect(isDay('2024-02-29')).toBe(true);
    expect(isDay('2023-02-29')).toBe(false);
    expect(isDay('2026-13-01')).toBe(false);
    expect(isDay('2026-00-10')).toBe(false);
    expect(isDay('2026-04-31')).toBe(false);
    expect(isDay('0999-01-01')).toBe(false);
    expect(isDay('2026-1-1')).toBe(false);
    expect(isDay('2026-10-24T00:00:00Z')).toBe(false);
    expect(isDay('')).toBe(false);
  });
});

describe('isEmail', () => {
  it('is the deposit form check (bare address, at most 254 characters)', () => {
    expect(isEmail('alice@entity-a.example.com')).toBe(true);
    expect(isEmail('Alice <alice@example.com>')).toBe(false);
    expect(isEmail(`${'a'.repeat(243)}@example.com`)).toBe(false);
  });
});

describe('dayToInstant', () => {
  it('converts in UTC', () => {
    expect(dayToInstant('2026-10-01', 'start', 'UTC')).toBe('2026-10-01T00:00:00.000Z');
    expect(dayToInstant('2026-10-01', 'end', 'UTC')).toBe('2026-10-01T23:59:59.999Z');
  });

  it('converts in a positive offset, across daylight saving changes', () => {
    expect(dayToInstant('2026-01-15', 'start', 'Europe/Paris')).toBe('2026-01-14T23:00:00.000Z');
    expect(dayToInstant('2026-07-15', 'start', 'Europe/Paris')).toBe('2026-07-14T22:00:00.000Z');
    // 23-hour day (spring forward) and 25-hour day (fall back).
    expect(dayToInstant('2026-03-29', 'start', 'Europe/Paris')).toBe('2026-03-28T23:00:00.000Z');
    expect(dayToInstant('2026-03-29', 'end', 'Europe/Paris')).toBe('2026-03-29T21:59:59.999Z');
    expect(dayToInstant('2026-10-25', 'start', 'Europe/Paris')).toBe('2026-10-24T22:00:00.000Z');
    expect(dayToInstant('2026-10-25', 'end', 'Europe/Paris')).toBe('2026-10-25T22:59:59.999Z');
  });

  it('converts in negative and fractional offsets', () => {
    expect(dayToInstant('2026-10-01', 'start', 'America/New_York')).toBe('2026-10-01T04:00:00.000Z');
    expect(dayToInstant('2026-12-31', 'end', 'America/New_York')).toBe('2027-01-01T04:59:59.999Z');
    expect(dayToInstant('2026-10-01', 'start', 'Asia/Kolkata')).toBe('2026-09-30T18:30:00.000Z');
  });

  it('handles an offset change between midnight and the same wall time in UTC', () => {
    // Sydney leaves daylight saving time on 2026-04-05 at 03:00 local (16:00Z the day before).
    expect(dayToInstant('2026-04-05', 'start', 'Australia/Sydney')).toBe('2026-04-04T13:00:00.000Z');
  });

  it('gives the first instant after a skipped midnight', () => {
    // Sao Paulo skipped 2018-11-04 00:00 (clocks went to 01:00, UTC-2).
    expect(dayToInstant('2018-11-04', 'start', 'America/Sao_Paulo')).toBe('2018-11-04T03:00:00.000Z');
    expect(dayToInstant('2018-11-03', 'end', 'America/Sao_Paulo')).toBe('2018-11-04T02:59:59.999Z');
  });

  it('crosses month and year ends', () => {
    expect(dayToInstant('2024-02-28', 'end', 'UTC')).toBe('2024-02-28T23:59:59.999Z');
    expect(dayToInstant('2023-02-28', 'end', 'UTC')).toBe('2023-02-28T23:59:59.999Z');
    expect(dayToInstant('2026-12-31', 'end', 'UTC')).toBe('2026-12-31T23:59:59.999Z');
  });

  it('uses the local time zone by default and for an unknown zone', () => {
    const local = new Date(2026, 9, 1, 0, 0, 0, 0).toISOString();
    const localEnd = new Date(2026, 9, 1, 23, 59, 59, 999).toISOString();
    expect(dayToInstant('2026-10-01', 'start')).toBe(local);
    expect(dayToInstant('2026-10-01', 'end')).toBe(localEnd);
    expect(dayToInstant('2026-10-01', 'start', 'Not/A_Zone')).toBe(local);
  });

  it('rejects an invalid day', () => {
    expect(dayToInstant('2026-02-30', 'start', 'UTC')).toBeUndefined();
    expect(dayToInstant('yesterday', 'end')).toBeUndefined();
  });
});

describe('parseFilters', () => {
  it('reads valid transfer filters', () => {
    const q = new URLSearchParams('status=available&email=alice@example.com&createdAfter=2026-10-01');
    expect(parseFilters(TRANSFER_FILTERS, q)).toEqual({
      status: 'available',
      email: 'alice@example.com',
      createdAfter: '2026-10-01',
    });
  });

  it('accepts a string, with or without "?"', () => {
    expect(parseFilters(INVITATION_FILTERS, '?status=pending')).toEqual({ status: 'pending' });
    expect(parseFilters(BLOCKLIST_FILTERS, 'kind=sha256')).toEqual({ kind: 'sha256' });
  });

  it('drops unknown parameters, unknown enum values and empty values', () => {
    expect(parseFilters(TRANSFER_FILTERS, 'status=bogus&foo=bar&email=&createdAfter=%20')).toEqual({});
    expect(parseFilters(INVITATION_FILTERS, 'status=Pending')).toEqual({});
    expect(parseFilters(BLOCKLIST_FILTERS, 'kind=ip')).toEqual({});
  });

  it('drops invalid emails and dates', () => {
    expect(parseFilters(TRANSFER_FILTERS, 'email=not-an-email&createdAfter=2026-02-30')).toEqual({});
    expect(parseFilters(TRANSFER_FILTERS, 'createdAfter=2026-10-01T00:00:00Z')).toEqual({});
  });

  it('trims values', () => {
    expect(parseFilters(AUDIT_FILTERS, 'actor=%20bob%20')).toEqual({ actor: 'bob' });
  });

  it('checks the audit action pattern and lengths', () => {
    expect(parseFilters(AUDIT_FILTERS, 'action=transfer.deleted')).toEqual({ action: 'transfer.deleted' });
    expect(parseFilters(AUDIT_FILTERS, 'action=Transfer.Deleted')).toEqual({});
    expect(parseFilters(AUDIT_FILTERS, 'action=transfer')).toEqual({});
    expect(parseFilters(AUDIT_FILTERS, `action=a.${'b'.repeat(ACTION_MAX_LENGTH)}`)).toEqual({});
    const actor = 'é'.repeat(ACTOR_MAX_LENGTH);
    expect(parseFilters(AUDIT_FILTERS, new URLSearchParams({ actor }))).toEqual({ actor });
    expect(parseFilters(AUDIT_FILTERS, new URLSearchParams({ actor: `${actor}x` }))).toEqual({});
  });

  it('drops both dates of an inverted period', () => {
    expect(parseFilters(AUDIT_FILTERS, 'from=2026-10-10&to=2026-10-01&actor=bob')).toEqual({ actor: 'bob' });
    expect(parseFilters(AUDIT_FILTERS, 'from=2026-10-01&to=2026-10-01')).toEqual({
      from: '2026-10-01',
      to: '2026-10-01',
    });
  });

  it('keeps the first of repeated parameters', () => {
    expect(parseFilters(INVITATION_FILTERS, 'status=used&status=revoked')).toEqual({ status: 'used' });
  });
});

describe('filtersToQuery and pathWithFilters', () => {
  it('writes in spec order and omits empty values', () => {
    const filters: AuditFilters = { to: '2026-10-19', actor: '', action: 'admin.login', from: '2026-10-01' };
    expect(filtersToQuery(AUDIT_FILTERS, filters)).toBe('action=admin.login&from=2026-10-01&to=2026-10-19');
    expect(filtersToQuery(AUDIT_FILTERS, {})).toBe('');
  });

  it('encodes values', () => {
    expect(filtersToQuery(TRANSFER_FILTERS, { email: 'a+b@example.com' })).toBe('email=a%2Bb%40example.com');
  });

  it('round-trips through parseFilters', () => {
    const filters: TransferFilters = {
      status: 'rejected',
      email: 'a+b@example.com',
      createdAfter: '2026-10-01',
    };
    expect(parseFilters(TRANSFER_FILTERS, filtersToQuery(TRANSFER_FILTERS, filters))).toEqual(filters);
    const audit: AuditFilters = { action: 'file.not_scanned', actor: 'Jean Dupont & co', from: '2026-01-01' };
    expect(parseFilters(AUDIT_FILTERS, filtersToQuery(AUDIT_FILTERS, audit))).toEqual(audit);
  });

  it('builds an application path', () => {
    expect(pathWithFilters('/tenants/t1/invitations', INVITATION_FILTERS, {})).toBe(
      '/tenants/t1/invitations',
    );
    expect(pathWithFilters('/tenants/t1/invitations', INVITATION_FILTERS, { status: 'used' })).toBe(
      '/tenants/t1/invitations?status=used',
    );
  });
});

describe('filtersToApiParams', () => {
  it('adds the default limit', () => {
    expect(filtersToApiParams(BLOCKLIST_FILTERS, {})).toEqual({ limit: DEFAULT_LIMIT });
  });

  it('converts dates in the given time zone', () => {
    expect(
      filtersToApiParams(
        AUDIT_FILTERS,
        { action: 'admin.login', from: '2026-10-01', to: '2026-10-19' },
        {
          timeZone: 'Europe/Paris',
        },
      ),
    ).toEqual({
      action: 'admin.login',
      from: '2026-09-30T22:00:00.000Z',
      to: '2026-10-19T21:59:59.999Z',
      limit: 50,
    });
    expect(
      filtersToApiParams(
        TRANSFER_FILTERS,
        { status: 'available', createdAfter: '2026-10-01' },
        { timeZone: 'UTC' },
      ),
    ).toEqual({ status: 'available', createdAfter: '2026-10-01T00:00:00.000Z', limit: 50 });
  });

  it('drops invalid and empty values', () => {
    const filters = { status: 'nope', email: ' ', createdAfter: '2026-99-01' } as unknown as TransferFilters;
    expect(filtersToApiParams(TRANSFER_FILTERS, filters)).toEqual({ limit: 50 });
  });

  it('passes the cursor and clamps the limit', () => {
    expect(
      filtersToApiParams(INVITATION_FILTERS, { status: 'pending' }, { cursor: 'abc', limit: 500 }),
    ).toEqual({
      status: 'pending',
      limit: 200,
      cursor: 'abc',
    });
    expect(filtersToApiParams(INVITATION_FILTERS, {}, { cursor: '', limit: 0 })).toEqual({ limit: 1 });
    expect(filtersToApiParams(INVITATION_FILTERS, {}, { limit: 12.7 })).toEqual({ limit: 12 });
    expect(filtersToApiParams(INVITATION_FILTERS, {}, { limit: Number.NaN })).toEqual({ limit: 50 });
  });

  it('accepts an undefined cursor', () => {
    expect(filtersToApiParams(INVITATION_FILTERS, {}, { cursor: undefined })).toEqual({ limit: 50 });
  });

  it('types enum filters with their values, accepted by the typed client', () => {
    expectTypeOf(filtersToApiParams(TRANSFER_FILTERS, {}).status).toEqualTypeOf<TransferStatus | undefined>();
    expectTypeOf(filtersToApiParams(INVITATION_FILTERS, {}).status).toEqualTypeOf<
      InvitationStatus | undefined
    >();
    expectTypeOf(filtersToApiParams(BLOCKLIST_FILTERS, {}).kind).toEqualTypeOf<BlocklistKind | undefined>();
    expectTypeOf(filtersToApiParams(TRANSFER_FILTERS, {})).toExtend<ClientQuery<'listTenantTransfers'>>();
    expectTypeOf(filtersToApiParams(INVITATION_FILTERS, {})).toExtend<ClientQuery<'listTenantInvitations'>>();
    expectTypeOf(filtersToApiParams(BLOCKLIST_FILTERS, {})).toExtend<ClientQuery<'listBlocklist'>>();
  });
});

describe('validateFilters', () => {
  it('accepts an empty form and valid values', () => {
    expect(validateFilters(AUDIT_FILTERS, {})).toEqual([]);
    expect(validateFilters(AUDIT_FILTERS, { action: '', actor: '  ', from: '', to: '' })).toEqual([]);
    expect(
      validateFilters(TRANSFER_FILTERS, {
        status: 'available',
        email: ' a@example.com ',
        createdAfter: '2026-10-01',
      }),
    ).toEqual([]);
  });

  it('reports each kind of error in spec order', () => {
    expect(
      validateFilters(TRANSFER_FILTERS, { createdAfter: '2026-02-31', email: 'nope', status: 'x' }),
    ).toEqual([
      { field: 'status', code: 'invalid-format' },
      { field: 'email', code: 'invalid-email' },
      { field: 'createdAfter', code: 'invalid-format' },
    ]);
    expect(validateFilters(AUDIT_FILTERS, { action: 'login', actor: 'x'.repeat(321) })).toEqual([
      { field: 'action', code: 'invalid-format' },
      { field: 'actor', code: 'too-long' },
    ]);
    expect(validateFilters(AUDIT_FILTERS, { action: `${'a'.repeat(32)}.${'b'.repeat(32)}` })).toEqual([
      { field: 'action', code: 'too-long' },
    ]);
  });

  it('reports an inverted period on the end field', () => {
    expect(validateFilters(AUDIT_FILTERS, { from: '2026-10-10', to: '2026-10-09' })).toEqual([
      { field: 'to', code: 'range' },
    ]);
    expect(validateFilters(AUDIT_FILTERS, { from: '2026-10-10', to: '2026-10-10' })).toEqual([]);
    expect(validateFilters(AUDIT_FILTERS, { to: '2026-10-09' })).toEqual([]);
    // An invalid start is reported once, without a range error.
    expect(validateFilters(AUDIT_FILTERS, { from: '9999-99-99', to: '2026-10-09' })).toEqual([
      { field: 'from', code: 'invalid-format' },
    ]);
  });
});

describe('form helpers', () => {
  it('converts a valid form to filters', () => {
    expect(formToFilters(AUDIT_FILTERS, { action: ' admin.login ', actor: '', from: '2026-10-01' })).toEqual({
      action: 'admin.login',
      from: '2026-10-01',
    });
    expect(formToFilters(AUDIT_FILTERS, { from: '2026-10-02', to: '2026-10-01' })).toBeUndefined();
  });

  it('fills the form from filters', () => {
    expect(filtersToForm(TRANSFER_FILTERS, { status: 'expired' })).toEqual({
      status: 'expired',
      email: '',
      createdAfter: '',
    });
  });

  it('reports empty filters', () => {
    expect(isEmpty({})).toBe(true);
    expect(isEmpty({ status: undefined, email: '' })).toBe(true);
    expect(isEmpty({ status: 'used' })).toBe(false);
  });
});
