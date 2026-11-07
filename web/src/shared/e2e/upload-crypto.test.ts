import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { E2EError } from './errors';
import { decryptBytes } from './decrypt';
import { MIN_CHUNK_SIZE, ciphertextSize, importTransferKey, prepareFileEncryption } from './tte2';
import {
  HASH_SLICE_SIZE,
  UploadCryptoCore,
  FileChangedError,
  abortError,
  errorResponse,
  isAbortError,
  isFileChangedError,
  responseError,
  type CryptoRequest,
  type CryptoResponse,
} from './upload-crypto-core';
import { serveUploadCrypto, type WorkerScope } from './upload-crypto-serve';
import {
  WorkerUploadCrypto,
  createInThreadUploadCrypto,
  openUploadCrypto,
  type WorkerLike,
} from './upload-crypto';

const K = new Uint8Array(32).map((_, i) => i + 1);
const SALT = new Uint8Array(16).fill(7);

function bytes(n: number, seed = 1): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 131 + seed) & 0xff;
  return out;
}

const hex = (data: Uint8Array): string => createHash('sha256').update(data).digest('hex');

/** A fake Worker running serveUploadCrypto in the same thread, asynchronously like postMessage. */
function bridgedWorker() {
  const posted: CryptoRequest[] = [];
  const transfers: Transferable[][] = [];
  const scope: WorkerScope = {
    onmessage: null,
    postMessage(message, transfer) {
      if (transfer !== undefined) transfers.push(transfer);
      setTimeout(() => worker.onmessage?.({ data: message }), 0);
    },
  };
  serveUploadCrypto(scope);
  const worker: WorkerLike & { terminated: boolean } = {
    terminated: false,
    onmessage: null,
    onerror: null,
    postMessage(message) {
      posted.push(message);
      setTimeout(() => scope.onmessage?.({ data: message }), 0);
    },
    terminate() {
      worker.terminated = true;
    },
  };
  return { worker, posted, transfers };
}

async function workerCrypto() {
  const bridge = bridgedWorker();
  const crypto = new WorkerUploadCrypto(bridge.worker);
  await crypto.init(await importTransferKey(K));
  return { crypto, ...bridge };
}

describe('UploadCryptoCore', () => {
  it('hashes a file in slices and reports the progress', async () => {
    const data = bytes(HASH_SLICE_SIZE + 5);
    const core = new UploadCryptoCore(K);
    const progress: number[] = [];
    await expect(
      core.hash(
        0,
        new Blob([data]),
        MIN_CHUNK_SIZE,
        (n) => progress.push(n),
        () => false,
      ),
    ).resolves.toBe(hex(data));
    expect(progress).toEqual([HASH_SLICE_SIZE, HASH_SLICE_SIZE + 5]);
    await expect(
      core.hash(
        0,
        new Blob([]),
        MIN_CHUNK_SIZE,
        () => {},
        () => false,
      ),
    ).resolves.toBe(hex(new Uint8Array(0)));
  });

  it('stops hashing when aborted', async () => {
    const core = new UploadCryptoCore(K);
    await expect(
      core.hash(
        0,
        new Blob([bytes(10)]),
        MIN_CHUNK_SIZE,
        () => {},
        () => true,
      ),
    ).rejects.toSatisfy(isAbortError);
    let calls = 0;
    await expect(
      core.hash(
        0,
        new Blob([]),
        MIN_CHUNK_SIZE,
        () => {},
        () => ++calls > 0,
      ),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('encrypts the ranges exactly like prepareFileEncryption', async () => {
    const data = bytes(3 * MIN_CHUNK_SIZE + 17);
    const file = new Blob([data]);
    const core = new UploadCryptoCore(K);
    await core.hash(
      2,
      file,
      MIN_CHUNK_SIZE,
      () => {},
      () => false,
    );
    const size = await core.prepare(2, file, SALT, MIN_CHUNK_SIZE);
    expect(size).toBe(ciphertextSize(data.length, MIN_CHUNK_SIZE));
    const ref = await prepareFileEncryption(K, 2, file, { chunkSize: MIN_CHUNK_SIZE, salt: SALT });
    await expect(core.range(2, 0, size)).resolves.toEqual(await ref.range(0, size));
    await expect(core.range(2, 100, 70_000)).resolves.toEqual(await ref.range(100, 70_000));
    await expect(core.range(1, 0, 1)).rejects.toThrow('file 1 not prepared');
    core.clear();
    await expect(core.range(2, 0, 1)).rejects.toThrow('not prepared');
  });
});

describe('nonce reuse guard', () => {
  it('refuses to prepare a file that was not hashed with the stream chunk size', async () => {
    const core = new UploadCryptoCore(K);
    const file = new Blob([bytes(10)]);
    await expect(core.prepare(0, file, SALT, MIN_CHUNK_SIZE)).rejects.toThrow('file 0 not hashed');
    await core.hash(
      0,
      file,
      MIN_CHUNK_SIZE,
      () => {},
      () => false,
    );
    await expect(core.prepare(0, file, SALT, 2 * MIN_CHUNK_SIZE)).rejects.toThrow('not hashed');
    await expect(core.prepare(0, new Blob([bytes(11)]), SALT, MIN_CHUNK_SIZE)).rejects.toSatisfy(
      isFileChangedError,
    );
    await expect(
      core.hash(
        0,
        file,
        1000,
        () => {},
        () => false,
      ),
    ).rejects.toMatchObject({
      code: 'invalid-chunk-size',
    });
    // A failed hash forgets the digests of the index.
    await expect(core.prepare(0, file, SALT, MIN_CHUNK_SIZE)).rejects.toThrow('not hashed');
    core.clear();
    await expect(core.prepare(0, file, SALT, MIN_CHUNK_SIZE)).rejects.toThrow('not hashed');
  });

  it('never encrypts a chunk whose plaintext changed since the hash pass', async () => {
    const original = bytes(3 * MIN_CHUNK_SIZE + 5);
    const changed = new Uint8Array(original);
    changed[2 * MIN_CHUNK_SIZE + 1]! ^= 1;
    const core = new UploadCryptoCore(K);
    await core.hash(
      1,
      new Blob([original]),
      MIN_CHUNK_SIZE,
      () => {},
      () => false,
    );
    const size = await core.prepare(1, new Blob([changed]), SALT, MIN_CHUNK_SIZE);
    const ref = await prepareFileEncryption(K, 1, new Blob([original]), {
      chunkSize: MIN_CHUNK_SIZE,
      salt: SALT,
    });
    // The chunks before the change are still the same.
    await expect(core.range(1, 0, 32 + 2 * (MIN_CHUNK_SIZE + 16))).resolves.toEqual(
      await ref.range(0, 32 + 2 * (MIN_CHUNK_SIZE + 16)),
    );
    const err = await core.range(1, 0, size).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(FileChangedError);
    expect(isFileChangedError(err)).toBe(true);
    expect((err as Error).message).toContain('file 1 changed since it was hashed (chunk 2)');
    expect(isFileChangedError(new Error('x'))).toBe(false);
    expect(isFileChangedError('FileChangedError')).toBe(false);
  });

  it('checks an empty file and the last partial chunk', async () => {
    const core = new UploadCryptoCore(K);
    await core.hash(
      0,
      new Blob([]),
      MIN_CHUNK_SIZE,
      () => {},
      () => false,
    );
    const size = await core.prepare(0, new Blob([]), SALT, MIN_CHUNK_SIZE);
    await expect(decryptBytes({ key: K, index: 0 }, await core.range(0, 0, size))).resolves.toEqual(
      new Uint8Array(0),
    );
    const data = bytes(HASH_SLICE_SIZE + 3);
    await core.hash(
      1,
      new Blob([data]),
      MIN_CHUNK_SIZE,
      () => {},
      () => false,
    );
    const big = await core.prepare(1, new Blob([data]), SALT, MIN_CHUNK_SIZE);
    const tail = await core.range(1, big - 100, big);
    const ref = await prepareFileEncryption(K, 1, new Blob([data]), {
      chunkSize: MIN_CHUNK_SIZE,
      salt: SALT,
    });
    expect(tail).toEqual(await ref.range(big - 100, big));
  });

  it('reports a change through the Worker as a FileChangedError', async () => {
    const { crypto } = await workerCrypto();
    await crypto.hash(0, new Blob([bytes(100)]), MIN_CHUNK_SIZE);
    const size = await crypto.prepare(0, new Blob([bytes(100, 2)]), SALT, MIN_CHUNK_SIZE);
    await expect(crypto.range(0, 0, size)).rejects.toSatisfy(isFileChangedError);
  });
});

describe('error messages', () => {
  it('round-trips E2E errors, plain errors and other values', () => {
    const e2e = responseError(
      errorResponse(1, new E2EError('bad-header', 'salt')) as CryptoResponse & { kind: 'error' },
    );
    expect(e2e).toBeInstanceOf(E2EError);
    expect(e2e).toMatchObject({ code: 'bad-header', message: 'tte2: bad-header: salt' });
    const abort = responseError(errorResponse(2, abortError()) as CryptoResponse & { kind: 'error' });
    expect(isAbortError(abort)).toBe(true);
    expect(errorResponse(3, 'boom')).toEqual({ id: 3, kind: 'error', name: 'Error', message: 'boom' });
    expect(isAbortError('AbortError')).toBe(false);
  });
});

describe('in-thread UploadCrypto', () => {
  it('hashes, prepares and encrypts, then refuses once disposed', async () => {
    const data = bytes(1000);
    const crypto = createInThreadUploadCrypto(await importTransferKey(K));
    const progress: number[] = [];
    await expect(crypto.hash(0, new Blob([data]), MIN_CHUNK_SIZE, (n) => progress.push(n))).resolves.toBe(
      hex(data),
    );
    await expect(crypto.hash(0, new Blob([data]), MIN_CHUNK_SIZE)).resolves.toBe(hex(data));
    expect(progress).toEqual([1000]);
    const size = await crypto.prepare(0, new Blob([data]), SALT, MIN_CHUNK_SIZE);
    const stream = await crypto.range(0, 0, size);
    await expect(decryptBytes({ key: K, index: 0 }, stream)).resolves.toEqual(data);
    const controller = new AbortController();
    controller.abort();
    await expect(
      crypto.hash(0, new Blob([data]), MIN_CHUNK_SIZE, undefined, controller.signal),
    ).rejects.toSatisfy(isAbortError);
    crypto.dispose();
    await expect(crypto.hash(0, new Blob([data]), MIN_CHUNK_SIZE)).rejects.toThrow('disposed');
    await expect(crypto.prepare(0, new Blob([data]), SALT, MIN_CHUNK_SIZE)).rejects.toThrow('disposed');
    await expect(crypto.range(0, 0, 1)).rejects.toThrow('disposed');
  });
});

describe('Worker UploadCrypto', () => {
  it('hashes with progress and returns the ranges as transferred buffers', async () => {
    const { crypto, transfers } = await workerCrypto();
    const data = bytes(HASH_SLICE_SIZE + 3, 9);
    const progress: number[] = [];
    await expect(crypto.hash(0, new Blob([data]), MIN_CHUNK_SIZE, (n) => progress.push(n))).resolves.toBe(
      hex(data),
    );
    expect(progress).toEqual([HASH_SLICE_SIZE, HASH_SLICE_SIZE + 3]);
    const small = bytes(200_000, 4);
    await crypto.hash(1, new Blob([small]), MIN_CHUNK_SIZE);
    const size = await crypto.prepare(1, new Blob([small]), SALT, MIN_CHUNK_SIZE);
    expect(size).toBe(ciphertextSize(small.length, MIN_CHUNK_SIZE));
    const ref = await prepareFileEncryption(K, 1, new Blob([small]), {
      chunkSize: MIN_CHUNK_SIZE,
      salt: SALT,
    });
    const part = await crypto.range(1, 10, 100_000);
    expect(part).toEqual(await ref.range(10, 100_000));
    expect(transfers.at(-1)?.[0]).toBe(part.buffer);
    await expect(crypto.hash(0, new Blob([small]), MIN_CHUNK_SIZE)).resolves.toBe(hex(small));
  });

  it('rebuilds the errors of the Worker', async () => {
    const { crypto } = await workerCrypto();
    await crypto.hash(0, new Blob([]), MIN_CHUNK_SIZE);
    await expect(crypto.prepare(0, new Blob([]), new Uint8Array(3), MIN_CHUNK_SIZE)).rejects.toMatchObject({
      code: 'bad-header',
    });
    await expect(crypto.range(4, 0, 1)).rejects.toThrow('file 4 not prepared');
  });

  it('refuses requests before init', async () => {
    const { worker } = bridgedWorker();
    const crypto = new WorkerUploadCrypto(worker);
    await expect(crypto.range(0, 0, 1)).rejects.toThrow('not initialised');
  });

  it('aborts a hash in progress, or at once when already aborted', async () => {
    const { crypto, posted } = await workerCrypto();
    const controller = new AbortController();
    const pending = crypto.hash(
      0,
      new Blob([bytes(3 * HASH_SLICE_SIZE)]),
      MIN_CHUNK_SIZE,
      () => controller.abort(),
      controller.signal,
    );
    await expect(pending).rejects.toSatisfy(isAbortError);
    const hashId = posted.find((r) => r.op === 'hash')?.id;
    expect(posted).toContainEqual(expect.objectContaining({ op: 'abort', target: hashId }));
    await expect(
      crypto.hash(0, new Blob([]), MIN_CHUNK_SIZE, undefined, controller.signal),
    ).rejects.toSatisfy(isAbortError);
  });

  it('fails every pending and later request when the Worker fails or is disposed', async () => {
    const { crypto, worker } = await workerCrypto();
    const pending = crypto.range(0, 0, 1);
    worker.onerror?.(new Event('error'));
    await expect(pending).rejects.toThrow('worker failed');
    await expect(crypto.range(0, 0, 1)).rejects.toThrow('worker failed');
    crypto.dispose();
    expect(worker.terminated).toBe(true);
    const other = await workerCrypto();
    other.crypto.dispose();
    await expect(other.crypto.range(0, 0, 1)).rejects.toThrow('disposed');
  });

  it('ignores answers to unknown requests', async () => {
    const { crypto, worker } = await workerCrypto();
    worker.onmessage?.({ data: { id: 999, kind: 'ok' } });
    worker.onmessage?.({ data: { id: 999, kind: 'progress', bytes: 1 } });
    await expect(crypto.hash(0, new Blob([]), MIN_CHUNK_SIZE)).resolves.toBe(hex(new Uint8Array(0)));
  });
});

describe('openUploadCrypto', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('uses the Worker when it answers', async () => {
    const { worker } = bridgedWorker();
    const crypto = await openUploadCrypto(await importTransferKey(K), { createWorker: () => worker });
    expect(crypto).toBeInstanceOf(WorkerUploadCrypto);
    await expect(crypto.hash(0, new Blob(['abc']), MIN_CHUNK_SIZE)).resolves.toBe(
      hex(new TextEncoder().encode('abc')),
    );
  });

  it('falls back to the page without Worker support (Node has no global Worker)', async () => {
    const crypto = await openUploadCrypto(await importTransferKey(K));
    expect(crypto).not.toBeInstanceOf(WorkerUploadCrypto);
    await expect(crypto.hash(0, new Blob(['abc']), MIN_CHUNK_SIZE)).resolves.toBe(
      hex(new TextEncoder().encode('abc')),
    );
  });

  it('falls back when the Worker fails to start or does not answer in time', async () => {
    const key = await importTransferKey(K);
    const failing = bridgedWorker().worker;
    failing.postMessage = () => setTimeout(() => failing.onerror?.(new Event('error')), 0);
    const a = await openUploadCrypto(key, { createWorker: () => failing });
    expect(a).not.toBeInstanceOf(WorkerUploadCrypto);
    expect((failing as { terminated?: boolean }).terminated).toBe(true);

    const silent = bridgedWorker().worker;
    silent.postMessage = () => {};
    vi.useFakeTimers();
    const opening = openUploadCrypto(key, { createWorker: () => silent });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await opening).not.toBeInstanceOf(WorkerUploadCrypto);
  });
});

describe('upload.worker.ts', () => {
  it('serves the requests posted to the Worker global scope', async () => {
    const posted: CryptoResponse[] = [];
    const scope: WorkerScope = { onmessage: null, postMessage: (m) => posted.push(m) };
    vi.stubGlobal('self', scope);
    try {
      await import('./upload.worker');
      expect(scope.onmessage).toBeTypeOf('function');
      scope.onmessage?.({ data: { id: 1, op: 'init', key: K } });
      await vi.waitFor(() => expect(posted).toEqual([{ id: 1, kind: 'ok' }]));
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
