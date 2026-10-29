import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  auditPath,
  canDelete,
  canResend,
  createdVia,
  dateOr,
  deleteBody,
  deleteFailure,
  detailPath,
  filesText,
  instantToDay,
  originLabel,
  rateLimitedText,
  recipientsSummary,
  resendBody,
  resendFailure,
  resultText,
  scanView,
  trackedDownloads,
  selectAll,
  selectedCount,
  senderIpText,
  statusOptions,
  statusView,
  submitFilters,
} from './transfers';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

function view(partial: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'server message',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...partial,
  };
}

describe('filters wiring', () => {
  it('validates the form and returns the path to navigate to', () => {
    expect(
      submitFilters(
        '/tenants/t1/transfers',
        { status: 'available', email: ' a@example.com ', createdAfter: '' },
        t,
      ),
    ).toEqual({
      ok: true,
      path: '/tenants/t1/transfers?status=available&email=a%40example.com',
    });
    expect(submitFilters('/p', { status: '', email: '', createdAfter: '' }, t)).toEqual({
      ok: true,
      path: '/p',
    });
  });

  it('reports a message per invalid field and the first one', () => {
    const out = submitFilters('/p', { status: 'nope', email: 'bad', createdAfter: '2026-02-30' }, t);
    expect(out).toEqual({
      ok: false,
      first: 'status',
      errors: {
        status: 'fieldErrors.invalid-format',
        email: 'fieldErrors.invalid-email',
        createdAfter: 'fieldErrors.invalid-format',
      },
    });
    const long = submitFilters(
      '/p',
      { status: '', email: `${'a'.repeat(250)}@example.com`, createdAfter: '' },
      t,
    );
    expect(long.ok).toBe(false);
  });

  it('lists the status options with "any" first', () => {
    const options = statusOptions(t);
    expect(options[0]).toEqual({ value: '', label: 'opsTransfers.list.statusAny' });
    expect(options.map((o) => o.value)).toEqual([
      '',
      'uploading',
      'scanning',
      'available',
      'rejected',
      'expired',
      'deleted',
    ]);
    expect(options[3]?.label).toBe('opsTransfers.status.available');
  });

  it('describes the result', () => {
    expect(resultText(3, false, t)).toBe('opsTransfers.list.loaded {"count":3}');
    expect(resultText(50, true, t)).toBe('opsTransfers.list.loadedMore {"count":50}');
  });
});

describe('labels and badges', () => {
  it('maps the statuses, unknown ones to a neutral badge with the raw text', () => {
    expect(statusView('available', t)).toEqual({ variant: 'ok', label: 'opsTransfers.status.available' });
    expect(statusView('rejected', t).variant).toBe('error');
    expect(statusView('expired', t).variant).toBe('warning');
    expect(statusView('uploading', t).variant).toBe('info');
    expect(statusView('archived', t)).toEqual({ variant: 'info', label: 'archived' });
    expect(statusView('toString', t)).toEqual({ variant: 'info', label: 'toString' });
  });

  it('maps the antivirus results', () => {
    expect(scanView('clean', t)).toEqual({ variant: 'ok', label: 'opsTransfers.scan.clean' });
    expect(scanView('infected', t).variant).toBe('error');
    expect(scanView('not_scanned_too_large', t).variant).toBe('warning');
    expect(scanView('not_scanned_encrypted', t).variant).toBe('warning');
    expect(scanView('scan_error', t).variant).toBe('error');
    expect(scanView('pending', t).variant).toBe('info');
    expect(scanView('scanning', t).variant).toBe('info');
    expect(scanView('quarantined', t)).toEqual({ variant: 'info', label: 'quarantined' });
  });

  it('labels the origins', () => {
    expect(originLabel('api', t)).toBe('opsTransfers.origin.api');
    expect(originLabel('reply', t)).toBe('reply');
  });

  it('summarises the recipients', () => {
    expect(recipientsSummary(['a@example.com'], t)).toEqual({
      shown: ['a@example.com'],
      more: 0,
      text: 'a@example.com',
    });
    expect(
      recipientsSummary(['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com'], t),
    ).toEqual({
      shown: ['a@example.com', 'b@example.com'],
      more: 2,
      text: 'opsTransfers.list.moreRecipients {"list":"a@example.com, b@example.com","count":2}',
    });
    expect(recipientsSummary([], t)).toEqual({ shown: [], more: 0, text: '' });
    expect(recipientsSummary(['a@example.com'], t, -1).more).toBe(1);
  });

  it('formats files, dates, origin references and IPs', () => {
    expect(filesText(2, 2048, t, (n) => `${n} B`)).toBe(
      'opsTransfers.list.filesSize {"count":2,"size":"2048 B"}',
    );
    const fmt = (d: string): string => `D(${d})`;
    expect(dateOr(null, 'none', fmt)).toBe('none');
    expect(dateOr(undefined, 'none', fmt)).toBe('none');
    expect(dateOr('', 'none', fmt)).toBe('none');
    expect(dateOr('2026-10-01T00:00:00Z', 'none', fmt)).toBe('D(2026-10-01T00:00:00Z)');
    expect(createdVia({ invitationId: 'inv_1' })).toEqual({ kind: 'invitation', id: 'inv_1' });
    expect(createdVia({ apiTokenId: 'tok_1' })).toEqual({ kind: 'token', id: 'tok_1' });
    expect(createdVia({ invitationId: '', apiTokenId: '' })).toBeUndefined();
    expect(createdVia({})).toBeUndefined();
    expect(senderIpText('192.0.2.1', t)).toBe('192.0.2.1');
    expect(senderIpText(null, t)).toBe('opsTransfers.detail.unknownIp');
    expect(senderIpText(undefined, t)).toBe('opsTransfers.detail.unknownIp');
    expect(senderIpText('', t)).toBe('opsTransfers.detail.unknownIp');
  });
});

describe('paths', () => {
  it('builds the detail path', () => {
    expect(detailPath('t 1', 'trf/1')).toBe('/tenants/t%201/transfers/trf%2F1');
  });

  it('converts an instant to a calendar day', () => {
    expect(instantToDay('2026-10-19T23:30:00Z', 'UTC')).toBe('2026-10-19');
    expect(instantToDay('2026-10-19T23:30:00Z', 'Europe/Paris')).toBe('2026-10-20');
    expect(instantToDay('2026-10-19T12:00:00Z', 'Not/AZone')).toMatch(/^2026-10-(19|20)$/);
    expect(instantToDay('2026-10-19T12:00:00Z')).toMatch(/^2026-10-(19|20)$/);
    expect(instantToDay('not a date')).toBeUndefined();
  });

  it('links to the audit log from the creation day', () => {
    expect(auditPath('t1', '2026-10-19T16:00:00Z', 'UTC')).toBe('/tenants/t1/audit?from=2026-10-19');
    expect(auditPath('t1', 'invalid')).toBe('/tenants/t1/audit');
  });
});

describe('actions', () => {
  it('shows the actions allowed by the status', () => {
    expect(canResend('available')).toBe(true);
    expect(canResend('scanning')).toBe(false);
    expect(canDelete('available')).toBe(true);
    expect(canDelete('uploading')).toBe(true);
    expect(canDelete('expired')).toBe(false);
    expect(canDelete('deleted')).toBe(false);
  });

  it('builds the resend body', () => {
    const recipients = ['a@example.com', 'b@example.com', 'c@example.com'];
    expect(selectAll(recipients)).toEqual({
      'a@example.com': true,
      'b@example.com': true,
      'c@example.com': true,
    });
    expect(resendBody(recipients, selectAll(recipients))).toBeUndefined();
    expect(resendBody(recipients, {})).toBeUndefined();
    expect(
      resendBody(recipients, { 'c@example.com': true, 'a@example.com': true, 'b@example.com': false }),
    ).toEqual({
      recipients: ['a@example.com', 'c@example.com'],
    });
    expect(selectedCount(recipients, { 'a@example.com': true, 'x@example.com': true })).toBe(1);
  });

  it('maps the resend errors', () => {
    expect(resendFailure(view({ status: 400, code: 'validation-failed' }), t)).toEqual({
      kind: 'not-recipient',
      message: 'opsTransfers.resend.errors.notRecipient',
    });
    expect(resendFailure(view({ status: 409, code: 'state-conflict' }), t).kind).toBe('not-available');
    expect(resendFailure(view({ status: 429, code: 'rate-limited', retryAfterSeconds: 120 }), t)).toEqual({
      kind: 'rate-limited',
      message: 'opsTransfers.resend.errors.rateLimitedNoDelay',
      retryAfterSeconds: 120,
    });
    expect(resendFailure(view({ status: 429, retryAfterSeconds: 0 }), t).retryAfterSeconds).toBeUndefined();
    expect(resendFailure(view({ status: 503, code: 'mail-unavailable' }), t)).toEqual({
      kind: 'mail-unavailable',
      message: 'opsTransfers.resend.errors.mailUnavailable',
    });
    expect(resendFailure(view({ status: 500 }), t)).toEqual({ kind: 'other', message: 'server message' });
    expect(resendFailure(view({ status: 400, code: 'other' }), t).kind).toBe('other');
  });

  it('writes the rate limit message with the remaining wait', () => {
    expect(rateLimitedText(30, t)).toBe(
      'opsTransfers.resend.errors.rateLimited {"wait":"opsTransfers.wait.seconds {\\"count\\":30}"}',
    );
    expect(rateLimitedText(0, t)).toBe('opsTransfers.resend.errors.rateLimitedOver');
  });

  it('builds the delete body', () => {
    expect(deleteBody('  ')).toBeUndefined();
    expect(deleteBody(' Wrong recipient ')).toEqual({ reason: 'Wrong recipient' });
  });

  it('maps the delete errors', () => {
    expect(deleteFailure(view({ status: 409, retryAfterSeconds: 5 }), t)).toBe(
      'opsTransfers.delete.errors.uploading {"wait":"opsTransfers.wait.seconds {\\"count\\":5}"}',
    );
    expect(deleteFailure(view({ status: 409 }), t)).toBe('opsTransfers.delete.errors.uploadingNoDelay');
    expect(deleteFailure(view({ status: 404 }), t)).toBe('opsTransfers.delete.errors.notFound');
    expect(
      deleteFailure(view({ status: 400, fields: { reason: { code: 'too-long', message: 'too long' } } }), t),
    ).toBe('too long');
    expect(deleteFailure(view({ status: 400 }), t)).toBe('server message');
    expect(deleteFailure(view({ status: 500 }), t)).toBe('server message');
  });
});

describe('trackedDownloads', () => {
  const files = [{ id: 'f1', name: 'report.pdf' }];
  const base = { email: 'a@example.com', verifiedAt: null, firstDownloadedAt: null, lastDownloadedAt: null };

  it('maps file ids to names and null to the archive label', () => {
    const rows = trackedDownloads(
      {
        ...base,
        downloads: [
          { fileId: 'f1', firstAt: '2026-01-01T10:00:00Z', lastAt: '2026-01-02T10:00:00Z', count: 2 },
          { fileId: null, firstAt: '2026-01-03T10:00:00Z', lastAt: '2026-01-03T10:00:00Z', count: 1 },
          { fileId: 'gone', firstAt: '2026-01-03T10:00:00Z', lastAt: '2026-01-03T10:00:00Z', count: 1 },
          { firstAt: '2026-01-04T10:00:00Z', lastAt: '2026-01-04T10:00:00Z', count: 3 },
        ],
      },
      files,
      'ZIP archive',
    );
    expect(rows.map((r) => r.label)).toEqual(['report.pdf', 'ZIP archive', 'gone', 'ZIP archive']);
    expect(rows[0]).toMatchObject({ count: 2, lastAt: '2026-01-02T10:00:00Z' });
  });

  it('returns nothing without downloads', () => {
    expect(trackedDownloads({ ...base, downloads: [] }, files, 'ZIP')).toEqual([]);
  });
});
