import { describe, expect, it, vi } from 'vitest';
import { ApiProblem } from '../../shared/api/client';
import {
  AccessTokenHolder,
  extendFailure,
  extensionOptions,
  isSessionExpired,
  openAccessLink,
  parseAccessToken,
  phaseAfterError,
  requestFailure,
  sessionStartFailure,
  statusKey,
} from './logic';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-10-27T10:00:00Z');
const iso = (ms: number): string => new Date(ms).toISOString();
const problem = (status: number, extra: Record<string, unknown> = {}): ApiProblem =>
  new ApiProblem(status, { type: 'x', title: 'x', status, ...extra } as never);

describe('parseAccessToken', () => {
  it('reads the token of the fragment', () => {
    expect(parseAccessToken('#mta_Hq7Lm2Zx9Vb4Kd1RTp6Yw3Nc8')).toBe('mta_Hq7Lm2Zx9Vb4Kd1RTp6Yw3Nc8');
  });
  it.each(['', '#', '#mta_short', '#other_Hq7Lm2Zx9Vb4Kd1RTp6Yw3Nc8', '#mta_Hq7Lm2Zx9Vb4Kd1RTp6Yw3Nc8&x=1'])(
    'rejects %j',
    (hash) => {
      expect(parseAccessToken(hash)).toBeUndefined();
    },
  );
});

describe('extensionOptions', () => {
  it('offers the durations that move forward and stay within extendableTo', () => {
    const expires = iso(NOW + 2 * DAY);
    expect(extensionOptions(NOW, expires, iso(NOW + 30 * DAY))).toEqual([7, 30]);
    expect(extensionOptions(NOW, expires, iso(NOW + 10 * DAY))).toEqual([7]);
    expect(extensionOptions(NOW, expires, iso(NOW + 7 * DAY))).toEqual([7]);
  });
  it('tolerates the delay between the answer of the server and the rendering', () => {
    // extendableTo was now + 30 days for the server a few seconds earlier.
    const expires = iso(NOW + 2 * DAY);
    expect(extensionOptions(NOW, expires, iso(NOW - 5000 + 30 * DAY))).toEqual([7, 30]);
    expect(extensionOptions(NOW, expires, iso(NOW - 2 * 60 * 60 * 1000 + 30 * DAY))).toEqual([7]);
  });
  it('offers nothing without extendableTo or when the limit is reached', () => {
    expect(extensionOptions(NOW, iso(NOW + DAY), undefined)).toEqual([]);
    expect(extensionOptions(NOW, iso(NOW + 30 * DAY), iso(NOW + 30 * DAY))).toEqual([]);
    expect(extensionOptions(NOW, iso(NOW + DAY), 'garbage')).toEqual([]);
  });
  it('copes with a missing or invalid current expiry', () => {
    expect(extensionOptions(NOW, undefined, iso(NOW + 8 * DAY))).toEqual([1, 7]);
    expect(extensionOptions(NOW, 'garbage', iso(NOW + DAY))).toEqual([1]);
  });
});

describe('error classification', () => {
  it('session expiry', () => {
    expect(isSessionExpired(problem(401))).toBe(true);
    expect(isSessionExpired(problem(404))).toBe(false);
    expect(isSessionExpired(new Error('x'))).toBe(false);
    expect(phaseAfterError(problem(401))).toEqual({ kind: 'request', notice: 'expired-session' });
    expect(phaseAfterError(problem(500))).toBeUndefined();
  });
  it('link request', () => {
    expect(requestFailure(problem(429, { retryAfterSeconds: 30 }))).toEqual({
      kind: 'rate-limited',
      retryAfterSeconds: 30,
    });
    expect(requestFailure(problem(503, { code: 'mail-unavailable' }))).toEqual({ kind: 'mail-unavailable' });
    expect(requestFailure(problem(400))).toEqual({ kind: 'invalid-email' });
    expect(requestFailure(problem(503))).toEqual({ kind: 'error' });
    expect(requestFailure(new Error('x'))).toEqual({ kind: 'error' });
  });
  it('session start', () => {
    expect(sessionStartFailure(problem(410, { code: 'access-link-invalid' }))).toBe('invalid-link');
    expect(sessionStartFailure(problem(400))).toBe('invalid-link');
    expect(sessionStartFailure(problem(429))).toBe('rate-limited');
    expect(sessionStartFailure(problem(500))).toBe('error');
    expect(sessionStartFailure(new Error('x'))).toBe('error');
  });
  it('extension', () => {
    expect(extendFailure(problem(409, { code: 'extension-limit-reached' }))).toEqual({
      kind: 'limit-reached',
    });
    expect(extendFailure(problem(409, { code: 'state-conflict' }))).toEqual({ kind: 'conflict' });
    expect(
      extendFailure(
        problem(400, { errors: [{ field: 'expiryDays', code: 'not-allowed', allowed: [1, 'x', 7] }] }),
      ),
    ).toEqual({ kind: 'not-allowed', allowed: [1, 7] });
    expect(extendFailure(problem(400, { errors: [{ field: 'expiryDays', code: 'not-allowed' }] }))).toEqual({
      kind: 'not-allowed',
      allowed: [],
    });
    expect(extendFailure(problem(400))).toEqual({ kind: 'error' });
    expect(extendFailure(problem(404))).toEqual({ kind: 'not-found' });
    expect(extendFailure(new Error('x'))).toEqual({ kind: 'error' });
  });
  it('status key', () => {
    expect(statusKey('scanning')).toBe('myTransfers.status.scanning');
    expect(statusKey('available')).toBe('myTransfers.status.available');
  });
});

const LINK_A = 'mta_EXAMPLEaaaaaaaaaaaaaaaaaaaaaa';
const LINK_B = 'mta_EXAMPLEbbbbbbbbbbbbbbbbbbbbbb';

describe('AccessTokenHolder', () => {
  it('keeps the token of the fragment for a retry without the fragment', () => {
    const holder = new AccessTokenHolder();
    expect(holder.take('')).toBeUndefined();
    expect(holder.take(`#${LINK_A}`)).toBe(LINK_A);
    // The fragment is gone from the address bar: the retry gets the same token.
    expect(holder.take('')).toBe(LINK_A);
    expect(holder.take('#mta_short')).toBe(LINK_A);
  });
  it('replaces the pending token with a new fragment token', () => {
    const holder = new AccessTokenHolder();
    holder.take(`#${LINK_A}`);
    expect(holder.take(`#${LINK_B}`)).toBe(LINK_B);
  });
  it('forgets the token once cleared', () => {
    const holder = new AccessTokenHolder();
    holder.take(`#${LINK_A}`);
    holder.clear();
    expect(holder.take('')).toBeUndefined();
  });
});

describe('openAccessLink', () => {
  const alice = { email: 'alice@entity-a.example.com', expiresAt: '2026-10-27T11:00:00Z' };
  const mallory = { email: 'mallory@entity-a.example.com', expiresAt: '2026-10-27T11:05:00Z' };

  it('exchanges the token when no session is active', async () => {
    const api = { current: vi.fn().mockRejectedValue(problem(401)), start: vi.fn().mockResolvedValue(alice) };
    await expect(openAccessLink(api, LINK_A, false)).resolves.toEqual({ kind: 'signed-in', ...alice });
    expect(api.start).toHaveBeenCalledWith(LINK_A);
  });
  it('asks before replacing an active session (login CSRF)', async () => {
    const api = { current: vi.fn().mockResolvedValue(alice), start: vi.fn().mockResolvedValue(mallory) };
    await expect(openAccessLink(api, LINK_A, false)).resolves.toEqual({ kind: 'confirm-switch', ...alice });
    expect(api.start).not.toHaveBeenCalled();
  });
  it('switches once confirmed, without checking the active session', async () => {
    const api = { current: vi.fn().mockResolvedValue(alice), start: vi.fn().mockResolvedValue(mallory) };
    await expect(openAccessLink(api, LINK_A, true)).resolves.toEqual({ kind: 'signed-in', ...mallory });
    expect(api.current).not.toHaveBeenCalled();
  });
  it('exchanges the token when the session check fails on the network', async () => {
    const api = {
      current: vi.fn().mockRejectedValue(new TypeError('offline')),
      start: vi.fn().mockResolvedValue(alice),
    };
    await expect(openAccessLink(api, LINK_A, false)).resolves.toEqual({ kind: 'signed-in', ...alice });
  });
  it.each([
    [problem(410, { code: 'access-link-invalid' }), 'invalid-link'],
    [problem(400), 'invalid-link'],
    [problem(429), 'invalid-link'],
    [problem(500), 'error'],
    [new TypeError('offline'), 'error'],
  ])('classifies a failed exchange %#', async (err, kind) => {
    const api = { current: vi.fn().mockRejectedValue(problem(401)), start: vi.fn().mockRejectedValue(err) };
    await expect(openAccessLink(api, LINK_A, false)).resolves.toEqual({ kind });
  });
  it('retries the same token after a network error', async () => {
    const holder = new AccessTokenHolder();
    const start = vi.fn().mockRejectedValueOnce(new TypeError('offline')).mockResolvedValueOnce(alice);
    const api = { current: vi.fn().mockRejectedValue(problem(401)), start };
    const first = holder.take(`#${LINK_A}`);
    expect(first).toBe(LINK_A);
    await expect(openAccessLink(api, first ?? '', false)).resolves.toEqual({ kind: 'error' });
    const retry = holder.take(''); // the fragment was removed from the address bar
    expect(retry).toBe(LINK_A);
    await expect(openAccessLink(api, retry ?? '', false)).resolves.toEqual({ kind: 'signed-in', ...alice });
    expect(start).toHaveBeenNthCalledWith(2, LINK_A);
  });
});
