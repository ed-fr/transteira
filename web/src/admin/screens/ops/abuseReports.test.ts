import { describe, expect, it } from 'vitest';
import {
  addressText,
  afterUpdate,
  categoryLabel,
  isErasedAddress,
  noteTooLong,
  reportStatusView,
  reporterText,
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
