import { describe, expect, it } from 'vitest';
import { ApiProblem, NetworkError, type Problem } from '../../shared/api/client';
import { downloadLoadFailure, downloadView, unlockFailure, type PublicTransfer } from './outcomes';

function problem(status: number, code?: string): ApiProblem {
  return new ApiProblem(status, {
    type: 'about:blank',
    title: 't',
    status,
    ...(code === undefined ? {} : { code }),
  } as Problem);
}

describe('maximum number of downloads', () => {
  it('tells 410 max-downloads-reached from an expired transfer', () => {
    expect(downloadLoadFailure(problem(410, 'max-downloads-reached'))).toBe('max-downloads');
    expect(downloadLoadFailure(problem(410, 'transfer-gone'))).toBe('gone');
    expect(downloadLoadFailure(problem(404))).toBe('not-found');
    expect(downloadLoadFailure(new NetworkError(new Error('x')))).toBe('error');
    expect(unlockFailure(problem(410, 'max-downloads-reached'))).toEqual({ kind: 'max-downloads' });
    expect(unlockFailure(problem(410))).toEqual({ kind: 'gone' });
  });

  it('exposes the level label and the downloads left', () => {
    const base: PublicTransfer = {
      senderEmail: 'alice@entity-a.example.com',
      expiresAt: '2026-11-01T00:00:00Z',
      passwordProtected: false,
      locked: false,
    };
    const view = downloadView({
      ...base,
      downloadsRemaining: 2,
      confidentialityLevel: { key: 'confidential', label: 'Confidential' },
    });
    expect(view.levelLabel).toBe('Confidential');
    expect(view.downloadsRemaining).toBe(2);
    const plain = downloadView(base);
    expect(plain.levelLabel).toBeUndefined();
    expect(plain.downloadsRemaining).toBeUndefined();
  });
});
