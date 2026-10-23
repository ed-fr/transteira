import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiProblem, NetworkError, type Method, type Problem } from '../api/client';
import {
  finalizeAndWait,
  IdempotencyKey,
  pollDelay,
  uploadSpecs,
  waitForDecision,
  type FinalizeOutcome,
  type RequestClient,
  type SenderTransfer,
} from './finalize';

function transfer(
  status: SenderTransfer['status'],
  files: Partial<SenderTransfer['files'][number]>[] = [],
): SenderTransfer {
  return {
    id: 'trf_1',
    status,
    senderEmail: 'a@entity-a.example.com',
    recipients: ['b@entity-a.example.com'],
    expiryDays: 7,
    passwordProtected: false,
    deleteAfterFirstDownload: false,
    totalBytes: 0,
    createdAt: '2026-10-23T10:00:00Z',
    files: files.map((f, i) => ({ id: `fil_${i}`, name: `f${i}`, size: 10, scanStatus: 'pending', ...f })),
  };
}

function problem(status: number, code: Problem['code'], extra: Partial<Problem> = {}): ApiProblem {
  return new ApiProblem(status, { type: 'about:blank', title: 't', status, code, ...extra } as Problem);
}

type Step = SenderTransfer | Error;

/** Fake client answering finalize and get from scripted queues. */
function client(finalize: Step[], get: Step[]): { api: RequestClient; calls: string[] } {
  const calls: string[] = [];
  const api: RequestClient = {
    async request<T>(method: Method, path: string) {
      calls.push(`${method} ${path}`);
      const queue = method === 'POST' ? finalize : get;
      const step = queue.length > 1 ? queue.shift() : queue[0];
      if (step === undefined) throw new Error('unexpected request');
      if (step instanceof Error) throw step;
      return { status: method === 'POST' ? 202 : 200, data: step as T, headers: new Headers() };
    },
  };
  return { api, calls };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('IdempotencyKey', () => {
  it('keeps one key per submission and renews it', () => {
    let n = 0;
    const key = new IdempotencyKey(() => `k${++n}`);
    expect(key.value).toBe('k1');
    expect(key.value).toBe('k1');
    expect(key.renew()).toBe('k2');
    expect(key.value).toBe('k2');
  });

  it('uses crypto.randomUUID by default', () => {
    const key = new IdempotencyKey();
    expect(key.value).toMatch(/^[0-9a-f-]{36}$/);
    const first = key.value;
    expect(key.renew()).not.toBe(first);
  });
});

describe('uploadSpecs', () => {
  it('builds specs in the declared order, content optional for complete files', () => {
    const a = new Blob(['0123456789']);
    const t = transfer('uploading', [
      { uploadUrl: '/u/0', uploadOffset: 4 },
      { uploadUrl: '/u/1', uploadOffset: 10 },
      { uploadUrl: '/u/2' },
      {},
    ]);
    expect(uploadSpecs(t, [a, undefined, a], true)).toEqual([
      { name: 'f0', size: 10, uploadUrl: '/u/0', offset: 4, file: a },
      { name: 'f1', size: 10, uploadUrl: '/u/1', offset: 10 },
      { name: 'f2', size: 10, uploadUrl: '/u/2', offset: 0, file: a },
      { name: 'f3', size: 10, uploadUrl: '', offset: 0 },
    ]);
  });

  it('leaves the offsets undefined when resuming, so that the engine asks the server', () => {
    const a = new Blob(['0123456789']);
    const t = transfer('uploading', [{ uploadUrl: '/u/0', uploadOffset: 4 }]);
    expect(uploadSpecs(t, [a])).toEqual([{ name: 'f0', size: 10, uploadUrl: '/u/0', file: a }]);
  });
});

describe('pollDelay', () => {
  it('backs off from 2 s to 10 s', () => {
    expect([0, 1, 2, 3, 4].map(pollDelay)).toEqual([2000, 4000, 8000, 10000, 10000]);
  });
});

describe('finalizeAndWait', () => {
  it('finalizes then polls until available', async () => {
    const { api, calls } = client(
      [transfer('scanning')],
      [transfer('scanning'), transfer('scanning'), transfer('available')],
    );
    const updates: string[] = [];
    const p = finalizeAndWait(api, 'trf/1', { onUpdate: (t) => updates.push(t.status) });
    await vi.advanceTimersByTimeAsync(1999);
    expect(calls).toEqual(['POST /transfers/trf%2F1/finalize']);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(4000);
    expect(calls).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(8000);
    const out = await p;
    expect(out).toMatchObject({ kind: 'available', transfer: { status: 'available' } });
    expect(updates).toEqual(['scanning', 'scanning', 'scanning', 'available']);
  });

  it('returns rejected and transfer-gone', async () => {
    const rejected = finalizeAndWait(client([transfer('rejected')], []).api, 't');
    await expect(rejected).resolves.toMatchObject({ kind: 'rejected' });
    const gone = finalizeAndWait(client([transfer('scanning')], [transfer('expired')]).api, 't');
    await vi.advanceTimersByTimeAsync(2000);
    await expect(gone).resolves.toEqual({ kind: 'failed', code: 'transfer-gone' });
    const deleted = finalizeAndWait(client([transfer('deleted')], []).api, 't');
    await expect(deleted).resolves.toEqual({ kind: 'failed', code: 'transfer-gone' });
  });

  it('signals upload-incomplete and blocked files', async () => {
    const inc = await finalizeAndWait(
      client([problem(409, 'upload-incomplete', { files: ['a'] })], []).api,
      't',
    );
    expect(inc).toEqual({ kind: 'upload-incomplete', files: ['a'] });
    const inc2 = await finalizeAndWait(client([problem(409, 'upload-incomplete')], []).api, 't');
    expect(inc2).toEqual({ kind: 'upload-incomplete', files: [] });
    const blocked = await finalizeAndWait(
      client([problem(403, 'blocked-file', { files: ['x.exe'] })], []).api,
      't',
    );
    expect(blocked).toEqual({ kind: 'blocked', files: ['x.exe'] });
    const blocked2 = await finalizeAndWait(client([problem(403, 'blocked-file')], []).api, 't');
    expect(blocked2).toEqual({ kind: 'blocked', files: [] });
  });

  it('fails on checksum-mismatch and other fatal problems', async () => {
    const out = await finalizeAndWait(client([problem(409, 'checksum-mismatch')], []).api, 't');
    expect(out).toEqual({ kind: 'failed', code: 'checksum-mismatch', status: 409 });
    const noCode = await finalizeAndWait(client([new ApiProblem(400, undefined)], []).api, 't');
    expect(noCode).toEqual({ kind: 'failed', code: 'internal-error', status: 400 });
  });

  it('continues polling when a lost finalize answer causes state-conflict', async () => {
    const { api, calls } = client(
      [new NetworkError(new Error('reset')), problem(409, 'state-conflict')],
      [transfer('scanning'), transfer('available')],
    );
    const p = finalizeAndWait(api, 't');
    await vi.advanceTimersByTimeAsync(2000); // retry finalize
    await vi.advanceTimersByTimeAsync(2000); // poll
    await expect(p).resolves.toMatchObject({ kind: 'available' });
    expect(calls).toEqual([
      'POST /transfers/t/finalize',
      'POST /transfers/t/finalize',
      'GET /transfers/t',
      'GET /transfers/t',
    ]);
  });

  it('fails on state-conflict while still uploading or when the read fails', async () => {
    const a = await finalizeAndWait(
      client([problem(409, 'state-conflict')], [transfer('uploading')]).api,
      't',
    );
    expect(a).toEqual({ kind: 'failed', code: 'state-conflict', status: 409 });
    const b = await finalizeAndWait(
      client([problem(409, 'state-conflict')], [problem(404, 'not-found')]).api,
      't',
    );
    expect(b).toEqual({ kind: 'failed', code: 'not-found', status: 404 });
  });

  it('retries transient finalize errors, honouring Retry-After, then gives up', async () => {
    const { api, calls } = client(
      [problem(503, 'maintenance', { retryAfterSeconds: 5 }), problem(500, 'internal-error')],
      [],
    );
    const p = finalizeAndWait(api, 't', { finalizeAttempts: 3 });
    await vi.advanceTimersByTimeAsync(4999);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(4000);
    await expect(p).resolves.toEqual({ kind: 'failed', code: 'internal-error', status: 500 });
    expect(calls).toHaveLength(3);

    const net = finalizeAndWait(client([new NetworkError(null)], []).api, 't', { finalizeAttempts: 1 });
    await expect(net).resolves.toEqual({ kind: 'failed', code: 'network' });
  });

  it('keeps polling through transient read errors and stops on fatal ones', async () => {
    const { api, calls } = client(
      [transfer('scanning')],
      [new NetworkError(null), problem(429, 'rate-limited', { retryAfterSeconds: 3 }), transfer('available')],
    );
    const p = finalizeAndWait(api, 't');
    await vi.advanceTimersByTimeAsync(2000);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(calls).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(3000);
    await expect(p).resolves.toMatchObject({ kind: 'available' });

    const fatal = finalizeAndWait(client([transfer('scanning')], [problem(401, 'unauthenticated')]).api, 't');
    await vi.advanceTimersByTimeAsync(2000);
    await expect(fatal).resolves.toEqual({ kind: 'failed', code: 'unauthenticated', status: 401 });
  });

  it('stops when the signal is aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      finalizeAndWait(client([transfer('scanning')], []).api, 't', { signal: controller.signal }),
    ).resolves.toEqual({
      kind: 'stopped',
    });

    // During polling wait.
    const c2 = new AbortController();
    const p2 = finalizeAndWait(client([transfer('scanning')], [transfer('scanning')]).api, 't', {
      signal: c2.signal,
    });
    await vi.advanceTimersByTimeAsync(100);
    c2.abort();
    await expect(p2).resolves.toEqual({ kind: 'stopped' });

    // A request rejected because of the abort.
    const c3 = new AbortController();
    const abortingFinalize: RequestClient = {
      async request() {
        c3.abort();
        throw new NetworkError(new Error('aborted'));
      },
    };
    await expect(finalizeAndWait(abortingFinalize, 't', { signal: c3.signal })).resolves.toEqual({
      kind: 'stopped',
    });

    const c4 = new AbortController();
    let first = true;
    const abortingRead: RequestClient = {
      async request<T>() {
        if (first) {
          first = false;
          return { status: 202, data: transfer('scanning') as T, headers: new Headers() };
        }
        c4.abort();
        throw new NetworkError(new Error('aborted'));
      },
    };
    const p4: Promise<FinalizeOutcome> = finalizeAndWait(abortingRead, 't', { signal: c4.signal });
    await vi.advanceTimersByTimeAsync(2000);
    await expect(p4).resolves.toEqual({ kind: 'stopped' });
  });
});

describe('waitForDecision', () => {
  it('polls without finalizing until the transfer is decided', async () => {
    const { api, calls } = client([], [transfer('scanning'), transfer('available')]);
    const updates: string[] = [];
    const p = waitForDecision(api, 'trf/1', { onUpdate: (t) => updates.push(t.status) });
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toEqual(['GET /transfers/trf%2F1']);
    await vi.advanceTimersByTimeAsync(2000);
    await expect(p).resolves.toMatchObject({ kind: 'available' });
    expect(updates).toEqual(['scanning', 'available']);
    expect(calls.every((c) => c.startsWith('GET'))).toBe(true);
  });

  it('retries a transient first read and fails on a fatal one', async () => {
    const { api } = client([], [new NetworkError(null), transfer('rejected')]);
    const p = waitForDecision(api, 't');
    await vi.advanceTimersByTimeAsync(10_000);
    await expect(p).resolves.toMatchObject({ kind: 'rejected' });

    const fatal = await waitForDecision(client([], [problem(404, 'not-found')]).api, 't');
    expect(fatal).toEqual({ kind: 'failed', code: 'not-found', status: 404 });

    const controller = new AbortController();
    controller.abort();
    await expect(
      waitForDecision(client([], [transfer('scanning')]).api, 't', { signal: controller.signal }),
    ).resolves.toEqual({ kind: 'stopped' });
  });
});
