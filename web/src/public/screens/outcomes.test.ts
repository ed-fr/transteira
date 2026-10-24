import { describe, expect, it } from 'vitest';
import { ApiProblem, NetworkError, type Problem } from '../../shared/api/client';
import {
  downloadView,
  inviteFailure,
  isNetworkFailure,
  isNoSession,
  isNotScanned,
  loadFailure,
  looksLikeEmail,
  unlockFailure,
  type PublicFile,
  type PublicTransfer,
  RECHECK_INTERVAL_MS,
  shouldRecheck,
} from './outcomes';

function problem(status: number, extra: Partial<Problem> = {}): ApiProblem {
  return new ApiProblem(status, { type: 'about:blank', title: 't', status, ...extra } as Problem);
}

function file(overrides: Partial<PublicFile> = {}): PublicFile {
  return {
    id: 'fil_1',
    name: 'report.pdf',
    size: 100,
    sha256: 'a'.repeat(64),
    scanStatus: 'clean',
    downloadUrl: '/api/v1/downloads/dl_x/files/fil_1',
    ...overrides,
  };
}

function transfer(overrides: Partial<PublicTransfer> = {}): PublicTransfer {
  return {
    senderEmail: 'alice@entity-a.example.com',
    expiresAt: '2026-11-01T00:00:00Z',
    passwordProtected: false,
    locked: false,
    ...overrides,
  };
}

describe('loadFailure', () => {
  it('classifies 404, 410 and the rest', () => {
    expect(loadFailure(problem(404))).toBe('not-found');
    expect(loadFailure(problem(410))).toBe('gone');
    expect(loadFailure(problem(500))).toBe('error');
    expect(loadFailure(new NetworkError(new Error('x')))).toBe('error');
    expect(loadFailure('boom')).toBe('error');
  });
});

describe('unlockFailure', () => {
  it('classifies every answer', () => {
    expect(unlockFailure(problem(401, { attemptsRemaining: 2 }))).toEqual({
      kind: 'wrong',
      attemptsRemaining: 2,
    });
    expect(unlockFailure(problem(429, { retryAfterSeconds: 900 }))).toEqual({
      kind: 'locked',
      retryAfterSeconds: 900,
    });
    expect(unlockFailure(problem(400))).toEqual({ kind: 'required' });
    expect(unlockFailure(problem(404))).toEqual({ kind: 'not-found' });
    expect(unlockFailure(problem(410))).toEqual({ kind: 'gone' });
    expect(unlockFailure(problem(403))).toEqual({ kind: 'error' });
    expect(unlockFailure(new Error('x'))).toEqual({ kind: 'error' });
  });
});

describe('inviteFailure', () => {
  it('classifies every answer', () => {
    const invalid = problem(400, {
      errors: [{ field: '/email', code: 'invalid-email' }],
    } as Partial<Problem>);
    expect(inviteFailure(invalid)).toEqual({ kind: 'invalid', fields: ['/email'] });
    expect(inviteFailure(problem(400))).toEqual({ kind: 'invalid', fields: [] });
    expect(inviteFailure(problem(401))).toEqual({ kind: 'session' });
    expect(inviteFailure(problem(403, { code: 'csrf-invalid' }))).toEqual({ kind: 'session' });
    expect(inviteFailure(problem(403, { code: 'invitation-not-allowed' }))).toEqual({ kind: 'not-allowed' });
    expect(inviteFailure(problem(403, { code: 'deposit-not-allowed' }))).toEqual({ kind: 'refused' });
    expect(inviteFailure(problem(403))).toEqual({ kind: 'refused' });
    expect(inviteFailure(problem(429, { retryAfterSeconds: 30 }))).toEqual({
      kind: 'rate-limited',
      retryAfterSeconds: 30,
    });
    expect(inviteFailure(problem(503))).toEqual({ kind: 'maintenance' });
    expect(inviteFailure(problem(500))).toEqual({ kind: 'error' });
    expect(inviteFailure(new NetworkError(new Error('x')))).toEqual({ kind: 'error' });
  });
});

describe('session and network helpers', () => {
  it('recognises a missing session and a network failure', () => {
    expect(isNoSession(problem(401))).toBe(true);
    expect(isNoSession(problem(500))).toBe(false);
    expect(isNoSession(new Error('x'))).toBe(false);
    expect(isNetworkFailure(new NetworkError(new Error('x')))).toBe(true);
    expect(isNetworkFailure(problem(500))).toBe(false);
  });
});

describe('downloadView', () => {
  it('filters every link through safeApiHref', () => {
    const view = downloadView(
      transfer({
        files: [file(), file({ id: 'fil_2', downloadUrl: 'javascript:alert(1)' })],
        archiveUrl: '/api/v1/downloads/dl_x/archive',
        totalBytes: 200,
      }),
    );
    expect(view.files.map((f) => f.href)).toEqual(['/api/v1/downloads/dl_x/files/fil_1', undefined]);
    expect(view.archiveHref).toBe('/api/v1/downloads/dl_x/archive');
    expect(view.totalBytes).toBe(200);
    expect(view.hasUnscanned).toBe(false);
    expect(view.deleteAfterFirstDownload).toBe(false);
  });

  it('rejects a foreign archive URL and computes the total when absent', () => {
    const view = downloadView(
      transfer({
        files: [file({ size: 10 }), file({ id: 'fil_2', size: 5, scanStatus: 'not_scanned_too_large' })],
        archiveUrl: 'https://evil.example/archive',
        deleteAfterFirstDownload: true,
      }),
    );
    expect(view.archiveHref).toBeUndefined();
    expect(view.totalBytes).toBe(15);
    expect(view.hasUnscanned).toBe(true);
    expect(view.deleteAfterFirstDownload).toBe(true);
  });

  it('has no archive link without files', () => {
    const view = downloadView(transfer({ archiveUrl: '/api/v1/downloads/dl_x/archive' }));
    expect(view.files).toEqual([]);
    expect(view.archiveHref).toBeUndefined();
    expect(view.totalBytes).toBe(0);
  });
});

describe('isNotScanned', () => {
  it('flags the files delivered without analysis', () => {
    expect(isNotScanned('not_scanned_too_large')).toBe(true);
    expect(isNotScanned('not_scanned_encrypted')).toBe(true);
    expect(isNotScanned('clean')).toBe(false);
  });
});

describe('looksLikeEmail', () => {
  it('accepts plausible addresses only', () => {
    expect(looksLikeEmail(' bob@partner.example.org ')).toBe(true);
    expect(looksLikeEmail('bob@partner')).toBe(false);
    expect(looksLikeEmail('bob partner@example.org')).toBe(false);
    expect(looksLikeEmail('')).toBe(false);
  });
});

describe('shouldRecheck', () => {
  it('checks again at most once per interval', () => {
    expect(RECHECK_INTERVAL_MS).toBe(60_000);
    expect(shouldRecheck(1_000, 60_999)).toBe(false);
    expect(shouldRecheck(1_000, 61_000)).toBe(true);
    expect(shouldRecheck(0, 5, 5)).toBe(true);
  });
});
