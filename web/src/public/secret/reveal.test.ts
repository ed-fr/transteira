import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ApiProblem, NetworkError, type ApiClient, type Problem } from '../../shared/api/client';
import { safeFileName } from '../../shared/e2e/archive-names';
import { sealMetadata } from '../../shared/e2e/sealed';
import {
  deriveSecretKey,
  encodeProof,
  newPassphraseDescriptor,
  parseProof,
  sealSecret,
  secretKeyProof,
  secretProof,
  secretVerifier,
  type PassphraseDescriptor,
} from '../../shared/e2e/secret';
import { generateTransferKey, prepareFileEncryption } from '../../shared/e2e/tte2';
import { sha256Hex } from '../../shared/e2e/tte2-helpers.test-helper';
import {
  GRANT_HEADER,
  MAX_SECRET_FILE_BYTES,
  readCapped,
  classifyFailure,
  descriptorValid,
  downloadFile,
  grantExpired,
  loadStatus,
  passphraseProblem,
  revealSecret,
  type RevealDeps,
  type RevealedFile,
  type SecretRevealed,
  type SecretStatus,
} from './reveal';

const TOKEN = 'tts_' + 'a'.repeat(43);
const GRANT = 'ttg_' + 'b'.repeat(43);
const GRANT_END = '2026-11-09T09:10:00Z';
const PASSPHRASE = 'correct horse';

function problem(status: number, body?: Partial<Problem>): ApiProblem {
  return new ApiProblem(status, body === undefined ? undefined : ({ status, ...body } as Problem));
}

/** A secret built as the creating client does. */
interface Fixture {
  key: Uint8Array;
  status: SecretStatus;
  revealed: SecretRevealed;
  keyVerifier: string;
  verifier: string;
  plain: Uint8Array;
  ciphertext: Uint8Array;
}

interface FixtureOptions {
  descriptor?: PassphraseDescriptor | null;
  text?: string;
  file?: { name: string; plain: Uint8Array; count?: number; sha256?: string; size?: number } | null;
}

async function fixture(options: FixtureOptions = {}): Promise<Fixture> {
  const key = generateTransferKey();
  const descriptor = options.descriptor ?? null;
  const rootKey = await deriveSecretKey(key, descriptor === null ? '' : PASSPHRASE, descriptor);
  const status: SecretStatus = { state: 'active', expiresAt: '2026-11-10T09:00:00Z', file: null };
  if (descriptor !== null) status.passphrase = descriptor as SecretStatus['passphrase'];
  const revealed: SecretRevealed = { encryptedText: await sealSecret(rootKey, options.text ?? 'hunter2') };
  let plain: Uint8Array = new Uint8Array(0);
  let ciphertext = new Uint8Array(0);
  if (options.file) {
    plain = options.file.plain;
    const enc = await prepareFileEncryption(rootKey, 0, new Blob([new Uint8Array(plain)]));
    ciphertext = await enc.range(0, enc.size);
    status.file = { size: enc.size };
    revealed.encryptedMetadata = await sealMetadata(rootKey, 0, {
      index: 0,
      count: options.file.count ?? 1,
      name: options.file.name,
      path: '',
      type: 'text/plain',
      size: options.file.size ?? plain.length,
      sha256: options.file.sha256 ?? (await sha256Hex(plain)),
    });
    revealed.fileGrant = GRANT;
    revealed.fileGrantExpiresAt = GRANT_END;
  }
  return {
    key,
    status,
    revealed,
    keyVerifier: encodeProof(await secretVerifier(await secretKeyProof(key))),
    verifier: encodeProof(await secretVerifier(await secretProof(rootKey))),
    plain,
    ciphertext,
  };
}

/** A fake server checking the proofs as revealSecret does (key proof first, uncounted). */
function server(
  fx: Fixture,
  override?: () => SecretRevealed,
): RevealDeps & {
  post: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
  fetchMock: ReturnType<typeof vi.fn>;
} {
  const get = vi.fn(async () => ({ status: 200, data: fx.status, headers: new Headers() }));
  const post = vi.fn(async (_path: string, opts: { body: { keyProof: string; proof: string } }) => {
    const keyVerifier = encodeProof(await secretVerifier(parseProof(opts.body.keyProof)));
    if (keyVerifier !== fx.keyVerifier) throw problem(403, { code: 'secret-proof-invalid' });
    const verifier = encodeProof(await secretVerifier(parseProof(opts.body.proof)));
    if (verifier !== fx.verifier) throw problem(403, { code: 'secret-proof-invalid', attemptsRemaining: 4 });
    return { status: 200, data: override?.() ?? fx.revealed, headers: new Headers() };
  });
  const fetchMock = vi.fn(async () => new Response(new Uint8Array(fx.ciphertext), { status: 200 }));
  return {
    api: { get, post } as unknown as Pick<ApiClient, 'get' | 'post'>,
    fetch: fetchMock as unknown as typeof fetch,
    get,
    post,
    fetchMock,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('classifyFailure', () => {
  it.each([
    [new NetworkError(new Error('offline')), { kind: 'network' }],
    [new Error('boom'), { kind: 'error' }],
    [problem(404, { code: 'not-found' }), { kind: 'not-found' }],
    [problem(410, { code: 'secret-gone', reason: 'read' }), { kind: 'gone', reason: 'read' }],
    [problem(410, { code: 'secret-gone', reason: 'expired' }), { kind: 'gone', reason: 'expired' }],
    [problem(410, { code: 'secret-gone', reason: 'deleted' }), { kind: 'gone', reason: 'deleted' }],
    [problem(410, { code: 'secret-gone', reason: 'locked' }), { kind: 'gone', reason: 'locked' }],
    [problem(410, { code: 'secret-gone', reason: 'later' as never }), { kind: 'gone', reason: 'unknown' }],
    [problem(410), { kind: 'gone', reason: 'unknown' }],
    [problem(403, { code: 'secret-proof-invalid' }), { kind: 'wrong-key' }],
    [
      problem(403, { code: 'secret-proof-invalid', attemptsRemaining: 2 }),
      { kind: 'wrong-passphrase', attemptsRemaining: 2 },
    ],
    [problem(403, { code: 'forbidden' }), { kind: 'error' }],
    [
      problem(429, { code: 'rate-limited', retryAfterSeconds: 30 }),
      { kind: 'rate-limited', retryAfterSeconds: 30 },
    ],
    [problem(503, { code: 'maintenance' }), { kind: 'maintenance' }],
    [problem(503, { code: 'tenant-in-setup' }), { kind: 'in-setup' }],
    [problem(503), { kind: 'error' }],
    [problem(500), { kind: 'error' }],
  ])('maps %o', (err, expected) => {
    expect(classifyFailure(err)).toEqual(expected);
  });
});

describe('loadStatus', () => {
  it('returns the status of an active secret', async () => {
    const fx = await fixture();
    const deps = server(fx);
    expect(await loadStatus(deps, TOKEN)).toEqual({ kind: 'active', status: fx.status });
    expect(deps.get).toHaveBeenCalledWith('/secret-links/{secretToken}', { path: { secretToken: TOKEN } });
  });

  it('classifies a failure', async () => {
    const deps = server(await fixture());
    deps.get.mockRejectedValueOnce(problem(410, { code: 'secret-gone', reason: 'read' }));
    expect(await loadStatus(deps, TOKEN)).toEqual({
      kind: 'failure',
      failure: { kind: 'gone', reason: 'read' },
    });
  });
});

describe('passphraseProblem and descriptorValid', () => {
  it('checks the passphrase rules', () => {
    expect(passphraseProblem('')).toEqual({ kind: 'passphrase-required' });
    expect(passphraseProblem('a\ud800b')).toEqual({ kind: 'passphrase-invalid' });
    expect(passphraseProblem('a'.repeat(1025))).toEqual({ kind: 'passphrase-invalid' });
    expect(passphraseProblem('a'.repeat(1024))).toBeUndefined();
    expect(passphraseProblem(' spaces kept ')).toBeUndefined();
  });

  it('accepts only the parameters of the format', () => {
    const d = newPassphraseDescriptor();
    expect(descriptorValid(d)).toBe(true);
    expect(descriptorValid({ ...d, kdf: 'argon2id' })).toBe(false);
    expect(descriptorValid({ ...d, iterations: 1000 })).toBe(false);
    expect(descriptorValid({ ...d, salt: 'short' })).toBe(false);
  });
});

describe('revealSecret', () => {
  let withPassphrase: Fixture;

  beforeAll(async () => {
    // PBKDF2 with 600 000 iterations: built once.
    withPassphrase = await fixture({ descriptor: newPassphraseDescriptor(), text: 'with passphrase' });
  });

  it('reveals a text secret without passphrase', async () => {
    const fx = await fixture({ text: 'top secret' });
    const deps = server(fx);
    // A passphrase typed for a secret without one is ignored.
    const out = await revealSecret(deps, TOKEN, fx.key, 'ignored', fx.status);
    expect(out.kind).toBe('revealed');
    if (out.kind !== 'revealed') return;
    expect(out.secret.text).toBe('top secret');
    expect(out.secret.file).toEqual({ kind: 'none' });
    expect(deps.post).toHaveBeenCalledWith('/secret-links/{secretToken}/reveal', {
      path: { secretToken: TOKEN },
      body: {
        keyProof: expect.stringMatching(/^[0-9a-f]{64}$/),
        proof: expect.stringMatching(/^[0-9a-f]{64}$/),
      },
    });
  });

  it('reveals a passphrase secret with the right passphrase', async () => {
    const out = await revealSecret(
      server(withPassphrase),
      TOKEN,
      withPassphrase.key,
      PASSPHRASE,
      withPassphrase.status,
    );
    expect(out.kind === 'revealed' && out.secret.text).toBe('with passphrase');
  });

  it('reports a wrong passphrase with the attempts left', async () => {
    const out = await revealSecret(
      server(withPassphrase),
      TOKEN,
      withPassphrase.key,
      'wrong',
      withPassphrase.status,
    );
    expect(out).toEqual({ kind: 'failure', failure: { kind: 'wrong-passphrase', attemptsRemaining: 4 } });
  });

  it('reports a wrong key as an incorrect link', async () => {
    const fx = await fixture();
    const out = await revealSecret(server(fx), TOKEN, generateTransferKey(), '', fx.status);
    expect(out).toEqual({ kind: 'failure', failure: { kind: 'wrong-key' } });
  });

  it('sends nothing without the passphrase, with an invalid one or with a foreign descriptor', async () => {
    const deps = server(withPassphrase);
    const { key, status } = withPassphrase;
    expect(await revealSecret(deps, TOKEN, key, '', status)).toEqual({
      kind: 'failure',
      failure: { kind: 'passphrase-required' },
    });
    expect(await revealSecret(deps, TOKEN, key, '\udc00', status)).toEqual({
      kind: 'failure',
      failure: { kind: 'passphrase-invalid' },
    });
    const cheap = {
      ...status,
      passphrase: { ...status.passphrase!, iterations: 1 },
    } as unknown as SecretStatus;
    expect(await revealSecret(deps, TOKEN, key, PASSPHRASE, cheap)).toEqual({
      kind: 'failure',
      failure: { kind: 'tampered' },
    });
    expect(deps.post).not.toHaveBeenCalled();
  });

  it('sends nothing without WebCrypto', async () => {
    const fx = await fixture();
    const deps = server(fx);
    const out = await revealSecret({ ...deps, cryptoAvailable: () => false }, TOKEN, fx.key, '', fx.status);
    expect(out).toEqual({ kind: 'failure', failure: { kind: 'unsupported' } });
    expect(deps.post).not.toHaveBeenCalled();
  });

  it('detects WebCrypto by default', async () => {
    const fx = await fixture();
    vi.stubGlobal('crypto', undefined);
    const out = await revealSecret(server(fx), TOKEN, fx.key, '', fx.status);
    expect(out).toEqual({ kind: 'failure', failure: { kind: 'unsupported' } });
  });

  it('maps a local format error to tampered and a WebCrypto failure to unsupported', async () => {
    const fx = await fixture();
    const deps = server(fx);
    expect(await revealSecret(deps, TOKEN, new Uint8Array(5), '', fx.status)).toEqual({
      kind: 'failure',
      failure: { kind: 'tampered' },
    });
    vi.spyOn(globalThis.crypto.subtle, 'deriveBits').mockRejectedValueOnce(
      new DOMException('no', 'NotSupportedError'),
    );
    expect(await revealSecret(deps, TOKEN, fx.key, '', fx.status)).toEqual({
      kind: 'failure',
      failure: { kind: 'unsupported' },
    });
    expect(deps.post).not.toHaveBeenCalled();
  });

  it('classifies a refused reveal', async () => {
    const fx = await fixture();
    const deps = server(fx);
    deps.post.mockRejectedValueOnce(problem(410, { code: 'secret-gone', reason: 'locked' }));
    expect(await revealSecret(deps, TOKEN, fx.key, '', fx.status)).toEqual({
      kind: 'failure',
      failure: { kind: 'gone', reason: 'locked' },
    });
  });

  it('refuses a sealed text that does not open', async () => {
    const fx = await fixture();
    const other = await fixture({ text: 'other' });
    const out = await revealSecret(
      server(fx, () => other.revealed),
      TOKEN,
      fx.key,
      '',
      fx.status,
    );
    expect(out).toEqual({ kind: 'failure', failure: { kind: 'tampered' } });
  });

  describe('with a file', () => {
    it('opens the metadata and sanitizes the name', async () => {
      const fx = await fixture({ text: '', file: { name: 'report?.pdf', plain: new Uint8Array([1, 2, 3]) } });
      const out = await revealSecret(server(fx), TOKEN, fx.key, '', fx.status);
      expect(out.kind).toBe('revealed');
      if (out.kind !== 'revealed') return;
      expect(out.secret.text).toBe('');
      expect(out.secret.file).toEqual({
        kind: 'ready',
        name: safeFileName('report?.pdf'),
        size: 3,
        sha256: await sha256Hex(fx.plain),
        grant: GRANT,
        grantExpiresAt: GRANT_END,
      });
      expect(safeFileName('report?.pdf')).not.toBe('report?.pdf');
    });

    it('marks a missing, partial, foreign or multi-file metadata as tampered', async () => {
      const fx = await fixture({ file: { name: 'a.txt', plain: new Uint8Array([1]) } });
      const cases: SecretRevealed[] = [
        { encryptedText: fx.revealed.encryptedText },
        { ...fx.revealed, fileGrant: undefined } as SecretRevealed,
        { ...fx.revealed, encryptedMetadata: 'AQ' + 'A'.repeat(60) },
      ];
      const multi = await fixture({ file: { name: 'a.txt', plain: new Uint8Array([1]), count: 2 } });
      for (const revealed of cases) {
        const out = await revealSecret(
          server(fx, () => revealed),
          TOKEN,
          fx.key,
          '',
          fx.status,
        );
        expect(out.kind === 'revealed' && out.secret.file).toEqual({ kind: 'tampered' });
      }
      const out = await revealSecret(server(multi), TOKEN, multi.key, '', multi.status);
      expect(out.kind === 'revealed' && out.secret.file).toEqual({ kind: 'tampered' });
    });
  });
});

describe('grantExpired', () => {
  it('compares the end of the grant with now', () => {
    const end = Date.parse(GRANT_END);
    expect(grantExpired({ grantExpiresAt: GRANT_END }, end - 1)).toBe(false);
    expect(grantExpired({ grantExpiresAt: GRANT_END }, end)).toBe(true);
    expect(grantExpired({ grantExpiresAt: 'not a date' }, 0)).toBe(true);
  });
});

describe('downloadFile', () => {
  async function revealedFile(
    file: FixtureOptions['file'],
  ): Promise<{ fx: Fixture; deps: ReturnType<typeof server>; root: CryptoKey; f: RevealedFile }> {
    const fx = await fixture({ file });
    const deps = server(fx);
    const out = await revealSecret(deps, TOKEN, fx.key, '', fx.status);
    if (out.kind !== 'revealed' || out.secret.file.kind !== 'ready') throw new Error('not revealed');
    return { fx, deps, root: out.secret.rootKey, f: out.secret.file };
  }

  const plain = new TextEncoder().encode('file content');

  it('downloads, decrypts and checks the file once with its grant', async () => {
    const { deps, root, f } = await revealedFile({ name: 'notes.txt', plain });
    const out = await downloadFile(deps, TOKEN, root, f);
    expect(out.kind).toBe('ok');
    if (out.kind !== 'ok') return;
    expect(out.name).toBe('notes.txt');
    expect(new Uint8Array(await out.blob.arrayBuffer())).toEqual(plain);
    expect(out.blob.type).toBe('application/octet-stream');
    expect(deps.fetchMock).toHaveBeenCalledWith(`/api/v1/secret-links/${TOKEN}/file`, {
      method: 'GET',
      headers: { [GRANT_HEADER]: GRANT },
      credentials: 'same-origin',
      cache: 'no-store',
    });
  });

  it('uses the configured API base', async () => {
    const { deps, root, f } = await revealedFile({ name: 'notes.txt', plain });
    await downloadFile({ ...deps, baseUrl: '/base' }, TOKEN, root, f);
    expect(deps.fetchMock.mock.calls[0]?.[0]).toBe(`/base/secret-links/${TOKEN}/file`);
  });

  it.each([
    [new Response(null, { status: 404 }), 'unavailable'],
    [new Response(null, { status: 429 }), 'rate-limited'],
    [Response.json({ code: 'maintenance' }, { status: 503 }), 'maintenance'],
    [Response.json({ code: 'tenant-in-setup' }, { status: 503 }), 'in-setup'],
    [new Response('null', { status: 503 }), 'in-setup'],
    [new Response('not json', { status: 503 }), 'in-setup'],
    [new Response(null, { status: 500 }), 'error'],
  ])('maps an error answer %#', async (response, failure) => {
    const { deps, root, f } = await revealedFile({ name: 'notes.txt', plain });
    deps.fetchMock.mockResolvedValueOnce(response);
    expect(await downloadFile(deps, TOKEN, root, f)).toEqual({ kind: 'failure', failure });
  });

  it('maps a network error', async () => {
    const { deps, root, f } = await revealedFile({ name: 'notes.txt', plain });
    deps.fetchMock.mockRejectedValueOnce(new TypeError('offline'));
    expect(await downloadFile(deps, TOKEN, root, f)).toEqual({ kind: 'failure', failure: 'network' });
  });

  it('refuses a ciphertext larger than the limit', async () => {
    const { deps, root, f } = await revealedFile({ name: 'notes.txt', plain });
    deps.fetchMock.mockResolvedValueOnce(new Response(new Uint8Array(MAX_SECRET_FILE_BYTES + 1)));
    expect(await downloadFile(deps, TOKEN, root, f)).toEqual({ kind: 'failure', failure: 'corrupt' });
  });

  it('refuses a declared length above the limit without reading the body', async () => {
    const { deps, root, f } = await revealedFile({ name: 'notes.txt', plain });
    const pull = vi.fn();
    const body = new ReadableStream<Uint8Array>({ pull }, { highWaterMark: 0 });
    deps.fetchMock.mockResolvedValueOnce(
      new Response(body, { headers: { 'Content-Length': String(MAX_SECRET_FILE_BYTES + 1) } }),
    );
    expect(await downloadFile(deps, TOKEN, root, f)).toEqual({ kind: 'failure', failure: 'corrupt' });
    expect(pull).not.toHaveBeenCalled();
  });

  it('refuses a file whose fingerprint or size differs from the metadata', async () => {
    const wrongSha = await revealedFile({ name: 'a.txt', plain, sha256: 'c'.repeat(64) });
    expect(await downloadFile(wrongSha.deps, TOKEN, wrongSha.root, wrongSha.f)).toEqual({
      kind: 'failure',
      failure: 'corrupt',
    });
    const wrongSize = await revealedFile({ name: 'a.txt', plain, size: plain.length + 1 });
    expect(await downloadFile(wrongSize.deps, TOKEN, wrongSize.root, wrongSize.f)).toEqual({
      kind: 'failure',
      failure: 'corrupt',
    });
  });

  it('refuses an altered ciphertext and reports a WebCrypto failure', async () => {
    const { fx, deps, root, f } = await revealedFile({ name: 'a.txt', plain });
    const altered = new Uint8Array(fx.ciphertext);
    altered[altered.length - 1]! ^= 1;
    deps.fetchMock.mockResolvedValueOnce(new Response(altered));
    expect(await downloadFile(deps, TOKEN, root, f)).toEqual({ kind: 'failure', failure: 'corrupt' });
    vi.spyOn(globalThis.crypto.subtle, 'deriveKey').mockRejectedValueOnce(new Error('engine failure'));
    expect(await downloadFile(deps, TOKEN, root, f)).toEqual({ kind: 'failure', failure: 'error' });
  });
});

describe('readCapped', () => {
  function chunked(...chunks: number[]): { response: Response; cancel: ReturnType<typeof vi.fn> } {
    const cancel = vi.fn();
    let i = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const n = chunks[i++];
        if (n === undefined) controller.close();
        else controller.enqueue(new Uint8Array(n).fill(i));
      },
      cancel,
    });
    return { response: new Response(body), cancel };
  }

  it('joins the chunks of a body within the cap', async () => {
    const { response } = chunked(2, 3);
    expect(await readCapped(response, 5)).toEqual(new Uint8Array([1, 1, 2, 2, 2]));
  });

  it('stops reading as soon as the body goes beyond the cap', async () => {
    const { response, cancel } = chunked(3, 3, 3);
    expect(await readCapped(response, 5)).toBeUndefined();
    expect(cancel).toHaveBeenCalled();
  });

  it('refuses a declared length above the cap, and reads an empty body', async () => {
    expect(await readCapped(new Response(null, { headers: { 'Content-Length': '6' } }), 5)).toBeUndefined();
    expect(await readCapped(new Response(null), 5)).toEqual(new Uint8Array(0));
  });
});
