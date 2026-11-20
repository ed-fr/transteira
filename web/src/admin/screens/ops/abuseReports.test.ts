import { describe, expect, it } from 'vitest';
import {
  addressText,
  afterUpdate,
  canDeleteReportedSecret,
  categoryLabel,
  isErasedAddress,
  loadedText,
  noteTooLong,
  reportStatusView,
  reporterText,
  reportSubject,
  statusFilterOptions,
  updateBody,
  type AbuseReport,
} from './abuseReports';
import { emptyList, receivePage } from './paging';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key}:${Object.values(params).join(',')}`;

const report = (over: Partial<AbuseReport> = {}): AbuseReport => ({
  id: 'abr_1',
  transferId: 'trf_1',
  senderEmail: 'alice@entity-a.example.com',
  reporterVerified: false,
  category: 'phishing',
  status: 'open',
  reportedAt: '2026-10-27T08:40:00Z',
  ...over,
});

describe('labels', () => {
  it('labels known categories and keeps unknown ones as is', () => {
    expect(categoryLabel('malware', t)).toBe('abuse.category.malware');
    expect(categoryLabel('future', t)).toBe('future');
  });

  it('badges statuses', () => {
    expect(reportStatusView('open', t).variant).toBe('warning');
    expect(reportStatusView('closed', t).variant).toBe('ok');
    expect(reportStatusView('weird', t)).toEqual({ variant: 'info', label: 'weird' });
  });

  it('offers all statuses then each one', () => {
    expect(statusFilterOptions(t).map((o) => o.value)).toEqual(['', 'open', 'closed']);
  });
});

describe('reporter', () => {
  it('shows the verified address', () => {
    expect(reporterText(report({ reporterVerified: true, reportedBy: 'c@x.example' }), t)).toBe(
      'opsAbuse.reporter.verified:c@x.example',
    );
  });

  it('shows the recipient link number when unverified', () => {
    expect(reporterText(report({ recipientIndex: 2, reportedBy: null }), t)).toBe(
      'opsAbuse.reporter.recipientLink:2',
    );
  });

  it('says shared link otherwise', () => {
    expect(reporterText(report({ recipientIndex: null }), t)).toBe('opsAbuse.reporter.sharedLink');
  });

  it('names the anonymous reader of an express secret, never the shared link of a transfer', () => {
    const secret = report({
      transferId: undefined,
      senderEmail: undefined,
      secretId: 'sec_1',
      reportedBy: null,
    });
    expect(reporterText(secret, t)).toBe('opsAbuse.reporter.secretReader');
    expect(reporterText({ ...secret, recipientIndex: null }, t)).toBe('opsAbuse.reporter.secretReader');
  });

  it('recognises erased addresses', () => {
    expect(isErasedAddress('erased-0123456789abcdef')).toBe(true);
    expect(addressText('erased-0123456789abcdef', t)).toBe('opsAbuse.erasedAddress');
    expect(addressText('a@b.example', t)).toBe('a@b.example');
  });
});

describe('update', () => {
  it('sends the note only when closing', () => {
    expect(updateBody('closed', '  done ')).toEqual({ status: 'closed', note: 'done' });
    expect(updateBody('closed', ' ')).toEqual({ status: 'closed' });
    expect(updateBody('open', 'x')).toEqual({ status: 'open' });
  });

  it('limits the note to 1000 characters', () => {
    expect(noteTooLong('a'.repeat(1000))).toBe(false);
    expect(noteTooLong('a'.repeat(1001))).toBe(true);
  });

  it('replaces the row, or drops it when the filter excludes it', () => {
    const list = receivePage({ ...emptyList<AbuseReport>(), generation: 1 }, 1, { items: [report()] });
    const closed = report({ status: 'closed' });
    expect(afterUpdate(list, closed, undefined).items[0]?.status).toBe('closed');
    expect(afterUpdate(list, closed, 'open').items).toEqual([]);
    expect(afterUpdate(list, closed, 'closed').items).toHaveLength(1);
  });
});

describe('result text', () => {
  it('counts the reports loaded, and says when more are available', () => {
    expect(loadedText(2, false, t)).toBe('opsAbuse.loaded:2');
    expect(loadedText(25, true, t)).toBe('opsAbuse.loadedMore:25');
  });
});

describe('deletion of the reported secret', () => {
  const secret = report({ transferId: undefined, secretId: 'sec_1' });

  it('is offered to an admin who may change the tenant, on a secret report only', () => {
    expect(canDeleteReportedSecret(secret, 'delegated_admin')).toBe(true);
    expect(canDeleteReportedSecret(secret, 'super_admin')).toBe(true);
    expect(canDeleteReportedSecret(report(), 'super_admin')).toBe(false);
    expect(canDeleteReportedSecret(undefined, 'super_admin')).toBe(false);
  });

  it('is never offered to the auditor, nor before the profile is known', () => {
    expect(canDeleteReportedSecret(secret, 'auditor')).toBe(false);
    expect(canDeleteReportedSecret(secret, undefined)).toBe(false);
  });
});

describe('subject', () => {
  it('names the express secret, the transfer, or says unknown', () => {
    expect(reportSubject({ secretId: 'sec_1' }, t)).toBe('opsAbuse.subject.secret:sec_1');
    expect(reportSubject({ transferId: 'trf_1' }, t)).toBe('opsAbuse.subject.transfer:trf_1');
    expect(reportSubject({}, t)).toBe('opsAbuse.subject.unknown');
  });
});
