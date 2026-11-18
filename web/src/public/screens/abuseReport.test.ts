import { describe, expect, it, vi } from 'vitest';
import { ApiProblem, type ApiClient, type Problem } from '../../shared/api/client';
import {
  ABUSE_CATEGORIES,
  categoryOptions,
  messageFits,
  messageLength,
  reportBody,
  reportFailure,
  reportFailureKey,
  reportIntroKey,
  sendAbuseReport,
} from './abuseReport';

const problem = (status: number): ApiProblem =>
  new ApiProblem(status, { type: 'about:blank', title: 't', status } as Problem);

describe('abuse report', () => {
  it('lists the six categories', () => {
    expect(ABUSE_CATEGORIES).toHaveLength(6);
    expect(categoryOptions((k) => k).map((o) => o.label)).toContain('abuse.category.phishing');
  });

  it('builds the body', () => {
    expect(reportBody('spam', '  ')).toEqual({ category: 'spam' });
    expect(reportBody('spam', ' hello ')).toEqual({ category: 'spam', message: 'hello' });
  });

  it('counts the message in code points', () => {
    expect(messageLength('😀😀')).toBe(2);
    expect(messageFits('a'.repeat(1000))).toBe(true);
    expect(messageFits('a'.repeat(1001))).toBe(false);
  });

  it('classifies errors', () => {
    expect(reportFailure(problem(429))).toEqual({ kind: 'rate-limited' });
    expect(reportFailure(problem(404))).toEqual({ kind: 'not-found' });
    expect(reportFailure(problem(410))).toEqual({ kind: 'gone' });
    expect(reportFailure(problem(400))).toEqual({ kind: 'invalid' });
    expect(reportFailure(problem(500))).toEqual({ kind: 'error' });
    expect(reportFailure(new Error('x'))).toEqual({ kind: 'error' });
    expect(reportFailureKey({ kind: 'not-found' })).toBe('download.report.errors.notFound');
    expect(reportFailureKey({ kind: 'rate-limited' })).toBe('download.report.errors.rateLimited');
    expect(reportFailureKey({ kind: 'gone' })).toBe('download.report.errors.gone');
  });

  it('words the end of an express secret and the introduction per target', () => {
    expect(reportFailureKey({ kind: 'gone' }, 'secret')).toBe('secret.reveal.report.gone');
    expect(reportFailureKey({ kind: 'gone' }, 'transfer')).toBe('download.report.errors.gone');
    expect(reportFailureKey({ kind: 'not-found' }, 'secret')).toBe('download.report.errors.notFound');
    expect(reportIntroKey('secret')).toBe('secret.reveal.report.intro');
    expect(reportIntroKey('transfer')).toBe('download.report.intro');
  });

  it('posts to the path of the target, with the category and the message only', async () => {
    const post = vi.fn(async () => ({ status: 202, data: undefined, headers: new Headers() }));
    const api = { post } as unknown as Pick<ApiClient, 'post'>;
    await sendAbuseReport(api, 'transfer', 'dl_abc', { category: 'spam' });
    expect(post).toHaveBeenLastCalledWith('/downloads/{linkToken}/abuse-reports', {
      path: { linkToken: 'dl_abc' },
      body: { category: 'spam' },
    });
    const token = 'tts_' + 'a'.repeat(43);
    await sendAbuseReport(api, 'secret', token, { category: 'phishing', message: 'fake bank' });
    expect(post).toHaveBeenLastCalledWith('/secret-links/{secretToken}/abuse-reports', {
      path: { secretToken: token },
      body: { category: 'phishing', message: 'fake bank' },
    });
  });
});
