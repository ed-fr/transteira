import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  ERASED_ACTION,
  ERASED_KEYS,
  KEPT_KEYS,
  auditLinkPath,
  confirmTextFor,
  eraseFailure,
  hasData,
  normalizeAddress,
  reportRows,
  requestBody,
  searchFailure,
  summaryRows,
  validateAddress,
  type DataSubjectEraseReport,
  type DataSubjectSummary,
} from './privacy';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;
const format = (n: number): string => `#${n}`;
const ref = { id: 'email', label: 'Email address' };

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

const empty: DataSubjectSummary = {
  email: 'carol@customer.example.net',
  verifiedAddress: false,
  transfersAsSender: 0,
  transfersAsRecipient: 0,
  invitations: 0,
  auditEvents: 0,
  securityEvents: 0,
};

describe('address', () => {
  it('trims the address in the body', () => {
    expect(normalizeAddress('  a@example.com ')).toBe('a@example.com');
    expect(requestBody(' carol@customer.example.net ')).toEqual({ email: 'carol@customer.example.net' });
  });

  it('validates the address', () => {
    expect(validateAddress('a@example.com', ref, t)).toEqual([]);
    expect(validateAddress('  ', ref, t)).toEqual([
      { id: 'email', label: 'Email address', message: 'fieldErrors.required' },
    ]);
    expect(validateAddress('not-an-address', ref, t)[0]?.message).toBe('fieldErrors.invalid-email');
    expect(validateAddress(`${'a'.repeat(250)}@example.com`, ref, t)[0]?.message).toBe(
      'fieldErrors.too-long',
    );
  });

  it('asks for the exact address searched', () => {
    expect(confirmTextFor(' carol@customer.example.net ')).toBe('carol@customer.example.net');
  });
});

describe('summary', () => {
  it('reports whether data was found', () => {
    expect(hasData(empty)).toBe(false);
    expect(hasData({ ...empty, securityEvents: 3 })).toBe(false);
    expect(hasData({ ...empty, verifiedAddress: true })).toBe(true);
    expect(hasData({ ...empty, transfersAsSender: 1 })).toBe(true);
    expect(hasData({ ...empty, transfersAsRecipient: 1 })).toBe(true);
    expect(hasData({ ...empty, invitations: 1 })).toBe(true);
    expect(hasData({ ...empty, auditEvents: 1 })).toBe(true);
  });

  it('builds the summary rows without the security log', () => {
    const rows = summaryRows(
      {
        ...empty,
        verifiedAddress: true,
        transfersAsSender: 2,
        transfersAsRecipient: 3,
        invitations: 4,
        auditEvents: 7,
      },
      t,
      format,
    );
    expect(rows).toEqual([
      { id: 'verifiedAddress', term: 'opsPrivacy.summary.verifiedAddress', value: 'opsPrivacy.yes' },
      { id: 'transfersAsSender', term: 'opsPrivacy.summary.transfersAsSender', value: '#2' },
      { id: 'transfersAsRecipient', term: 'opsPrivacy.summary.transfersAsRecipient', value: '#3' },
      { id: 'invitations', term: 'opsPrivacy.summary.invitations', value: '#4' },
      { id: 'auditEvents', term: 'opsPrivacy.summary.auditEvents', value: '#7' },
    ]);
    expect(summaryRows(empty, t, format)[0]?.value).toBe('opsPrivacy.no');
  });

  it('builds the report rows', () => {
    const report: DataSubjectEraseReport = {
      transfersDeleted: 1,
      recipientEntriesRemoved: 3,
      verifiedAddressDeleted: false,
      invitationsDeleted: 2,
      logEntriesPseudonymised: 7,
    };
    expect(reportRows(report, t, format)).toEqual([
      {
        id: 'verifiedAddressDeleted',
        term: 'opsPrivacy.report.verifiedAddressDeleted',
        value: 'opsPrivacy.no',
      },
      { id: 'transfersDeleted', term: 'opsPrivacy.report.transfersDeleted', value: '#1' },
      { id: 'recipientEntriesRemoved', term: 'opsPrivacy.report.recipientEntriesRemoved', value: '#3' },
      { id: 'invitationsDeleted', term: 'opsPrivacy.report.invitationsDeleted', value: '#2' },
      { id: 'logEntriesPseudonymised', term: 'opsPrivacy.report.logEntriesPseudonymised', value: '#7' },
    ]);
    expect(reportRows({ ...report, verifiedAddressDeleted: true }, t, format)[0]?.value).toBe(
      'opsPrivacy.yes',
    );
  });

  it('lists what is erased and what is kept', () => {
    expect(ERASED_KEYS.length).toBe(5);
    expect(KEPT_KEYS).toContain('opsPrivacy.erase.kept.blocklist');
    expect(KEPT_KEYS).toContain('opsPrivacy.erase.kept.backups');
  });
});

describe('errors', () => {
  it('maps a search validation error to the field', () => {
    expect(
      searchFailure(
        view({
          code: 'validation-failed',
          status: 400,
          fields: { email: { code: 'invalid-email', message: 'm' } },
        }),
        ref,
        t,
      ),
    ).toEqual({
      ok: false,
      errors: [{ id: 'email', label: 'Email address', message: 'fieldErrors.invalid-email' }],
    });
    expect(
      searchFailure(
        view({
          code: 'validation-failed',
          status: 400,
          fields: { email: { code: 'too-long', message: 'long' } },
        }),
        ref,
        t,
      ),
    ).toEqual({ ok: false, errors: [{ id: 'email', label: 'Email address', message: 'long' }] });
  });

  it('gives the general message for other search errors', () => {
    expect(searchFailure(view({ code: 'validation-failed', status: 400 }), ref, t)).toEqual({
      ok: false,
      message: 'general',
    });
    expect(searchFailure(view({ code: 'not-found', status: 404 }), ref, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });

  it('explains a 409 with the delay', () => {
    expect(eraseFailure(view({ code: 'state-conflict', status: 409, retryAfterSeconds: 30 }), t)).toBe(
      'opsPrivacy.erase.conflict {"wait":"opsTransfers.wait.seconds {\\"count\\":30}"}',
    );
    expect(eraseFailure(view({ code: 'state-conflict', status: 409 }), t)).toBe(
      'opsPrivacy.erase.conflictNow',
    );
    expect(eraseFailure(view({ code: 'state-conflict', status: 409, retryAfterSeconds: 0 }), t)).toBe(
      'opsPrivacy.erase.conflictNow',
    );
  });

  it('maps erasure validation and other errors', () => {
    expect(
      eraseFailure(
        view({
          code: 'validation-failed',
          status: 400,
          fields: { email: { code: 'invalid-email', message: 'm' } },
        }),
        t,
      ),
    ).toBe('fieldErrors.invalid-email');
    expect(
      eraseFailure(
        view({
          code: 'validation-failed',
          status: 400,
          fields: { email: { code: 'required', message: 'req' } },
        }),
        t,
      ),
    ).toBe('req');
    expect(eraseFailure(view({ code: 'validation-failed', status: 400 }), t)).toBe('general');
    expect(eraseFailure(view({ code: 'state-conflict', status: 400 }), t)).toBe('general');
    expect(eraseFailure(view({ status: 500 }), t)).toBe('general');
  });
});

describe('audit link', () => {
  it('opens the audit log filtered on the erasures', () => {
    expect(ERASED_ACTION).toBe('data_subject.erased');
    expect(auditLinkPath('ten_A/1')).toBe('/tenants/ten_A%2F1/audit?action=data_subject.erased');
  });
});
