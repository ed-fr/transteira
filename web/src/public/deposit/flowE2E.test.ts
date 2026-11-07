import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApiClient } from '../../shared/api/client';
import { decryptBytes } from '../../shared/e2e/decrypt';
import { openMessage, openMetadata } from '../../shared/e2e/sealed';
import { DEFAULT_CHUNK_SIZE, ciphertextSize, parseKey } from '../../shared/e2e/tte2';
import { createInThreadUploadCrypto, type UploadCrypto } from '../../shared/e2e/upload-crypto';
import { createUploadEngine, type UploadEngine } from '../../shared/upload/engine';
import { FakeServer } from '../../shared/upload/fake-transport.test-helper';
import type { FinalizeOutcome, SenderTransfer } from '../../shared/upload/finalize';
import type { ResumeRecord, ResumeStore } from '../../shared/upload/resume-store';
import {
  DepositFlow,
  encryptedSize,
  scanStatusKey,
  scanWarningKey,
  type CryptoFactory,
  type DepositFile,
  type DepositSession,
  type DropLinkContext,
  type FinalizeFn,
  type PublicTenant,
  type TransferCreate,
} from './flow.svelte';

// End-to-end encrypted deposits (V2 step 8): policy, preparation, sealed body, upload through the
// real engine on a fake tus server (the bytes received decrypt to the original files), resume after
// a reload with the key and the salts of the record.

type Handler = (body: unknown) => { status: number; body?: unknown };
type Route = { status: number; body?: unknown } | Handler;

const rules = {
  requireRecipientVerification: false,
  requirePassword: false,
  allowedExpiryDays: [1, 7, 30] as (1 | 7 | 30)[],
  internalRecipientsOnly: false,
  forceDeleteAfterFirstDownload: false,
  maxDownloads: null,
};

const features = {
  remoteInternalDeposit: false,
  transferReply: false,
  recipientVerification: false,
  maxDownloads: false,
  folders: true,
  recipientRestrictions: false,
  antivirus: 'enabled' as const,
  linkOnly: true,
};

function tenantWith(extra: Partial<PublicTenant> = {}, e2ePolicy?: 'forbidden' | 'allowed' | 'required') {
  const tenant: PublicTenant = {
    name: 'Entity A',
    language: 'en',
    availableLanguages: ['en', 'fr'],
    branding: {
      primaryColor: '#123456',
      accentColor: '#654321',
      hasLogo: false,
      hasBackground: false,
      backgroundUrl: '/api/v1/tenant/assets/background',
    },
    limits: { maxTransferBytes: 10_000_000, expiryDays: [1, 7, 30] },
    maintenance: false,
    legalDocuments: [],
    features: e2ePolicy === undefined ? features : { ...features, e2ePolicy },
    ...extra,
  };
  return tenant;
}

const session = (
  kind: DepositSession['kind'] = 'internal',
  maxTransferBytes = 10_000_000,
): DepositSession => ({
  email: 'alice@entity-a.example.com',
  kind,
  csrfToken: 'csrf_1',
  expiresAt: '2026-10-23T20:00:00Z',
  limits: { maxTransferBytes, expiryDays: [1, 7, 30] },
  canInvite: false,
});

/** The createTransfer answer for a body: one tus upload per declared file. */
function created(body: TransferCreate, extra: Partial<SenderTransfer> = {}): SenderTransfer {
  return {
    id: 'trf_1',
    status: 'uploading',
    senderEmail: 'alice@entity-a.example.com',
    recipients: body.recipients ?? [],
    expiryDays: body.expiryDays,
    passwordProtected: false,
    deleteAfterFirstDownload: false,
    totalBytes: body.files.reduce((sum, f) => sum + f.size, 0),
    createdAt: '2026-10-23T16:00:00Z',
    endToEndEncrypted: body.endToEndEncrypted === true,
    files: body.files.map((f, i) => ({
      id: `fil_${i}`,
      name: f.name,
      size: f.size,
      scanStatus: 'pending',
      uploadUrl: `/api/v1/uploads/u${i}`,
      uploadOffset: 0,
    })),
    ...extra,
  };
}

function memoryStore(initial?: ResumeRecord): ResumeStore & { value: ResumeRecord | undefined } {
  const store = {
    value: initial,
    save(record: ResumeRecord) {
      store.value = structuredClone(record);
    },
    load() {
      return store.value;
    },
    clear() {
      store.value = undefined;
    },
  };
  return store;
}

const hex = (data: Uint8Array): string => createHash('sha256').update(data).digest('hex');

function bytes(n: number, seed = 1): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed) & 0xff;
  return out;
}

function depositFile(data: Uint8Array<ArrayBuffer>, name: string, path?: string, type = ''): DepositFile {
  const f = new File([data], name, { type, lastModified: 1 }) as DepositFile;
  if (path !== undefined) f.path = path;
  return f;
}

interface SetupOptions {
  tenant?: PublicTenant;
  store?: ReturnType<typeof memoryStore>;
  finalize?: FinalizeFn;
  openCrypto?: CryptoFactory;
  dropLink?: DropLinkContext;
  server?: FakeServer;
}

type Routes = Record<string, Route | Route[]>;

/**
 * Builds a flow on a fake API. routes may be a function of create, the handler answering
 * POST /transfers like the server (used by default when the routes have none).
 */
function setup(routesOrBuild: Routes | ((create: Handler) => Routes), options: SetupOptions = {}) {
  let routes: Routes = {};
  const calls: { method: string; path: string; body: unknown; headers: Headers }[] = [];
  const server = options.server ?? new FakeServer();
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'https://transfer.entity-a.example.com');
    const method = init?.method ?? 'GET';
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ method, path, body, headers: new Headers(init?.headers) });
    const entry = routes[`${method} ${path}`];
    if (entry === undefined) throw new Error(`unexpected request ${method} ${path}`);
    const route = Array.isArray(entry) ? ((entry.length > 1 ? entry.shift() : entry[0]) as Route) : entry;
    const reply = typeof route === 'function' ? route(body) : route;
    return new Response(reply.body === undefined ? null : JSON.stringify(reply.body), {
      status: reply.status,
      headers: { 'Content-Type': reply.status >= 400 ? 'application/problem+json' : 'application/json' },
    });
  };
  const api = createApiClient({
    fetch: fetch as typeof globalThis.fetch,
    language: () => 'en',
    csrfToken: () => undefined,
    onCsrfToken: () => undefined,
  });
  const store = options.store ?? memoryStore();
  const announce = vi.fn();
  const engines: UploadEngine[] = [];
  let keys = 0;
  const finalize = vi.fn<FinalizeFn>(
    options.finalize ??
      (async (): Promise<FinalizeOutcome> => {
        const t = lastCreated;
        if (t === undefined) throw new Error('no transfer');
        return {
          kind: 'available',
          transfer: {
            ...t,
            status: 'available',
            files: t.files.map((f) => ({ ...f, scanStatus: 'not_scanned_e2e' as const })),
          },
        };
      }),
  );
  let lastCreated: SenderTransfer | undefined;
  const flow = new DepositFlow(
    options.tenant ?? tenantWith({}, 'allowed'),
    undefined,
    {
      api,
      tr: {
        t: (k: string, p?: Record<string, string | number>) => (p ? `${k} ${JSON.stringify(p)}` : k),
        has: () => true,
      },
      clearCsrf: vi.fn(),
      resumeStore: store,
      createEngine: (specs, cancelTransfer) => {
        const engine = createUploadEngine(specs, {
          transport: server,
          cancelTransfer,
          onOnline: () => () => {},
        });
        engines.push(engine);
        return engine;
      },
      finalize,
      poll: finalize,
      confirm: () => true,
      sleep: async () => {},
      announce,
      language: () => 'en',
      newKey: () => `key-${++keys}`,
      ...(options.openCrypto === undefined ? {} : { openCrypto: options.openCrypto }),
    },
    undefined,
    options.dropLink,
  );
  /** Answers POST /transfers like the server, registering the uploads on the fake tus server. */
  const create: Handler = (body) => {
    const b = body as TransferCreate;
    lastCreated = created(b);
    b.files.forEach((f, i) => {
      if (!server.uploads.has(`/api/v1/uploads/u${i}`)) server.add(`/api/v1/uploads/u${i}`, f.size);
    });
    return { status: 201, body: lastCreated };
  };
  routes = typeof routesOrBuild === 'function' ? routesOrBuild(create) : routesOrBuild;
  routes['POST /transfers'] ??= create;
  return { flow, calls, server, store, announce, engines, finalize, create };
}

/** Waits until the flow reaches a step (real timers: the encryption runs in this thread). */
async function until(flow: DepositFlow, step: DepositFlow['step']): Promise<void> {
  await vi.waitFor(() => expect(flow.step).toBe(step), { timeout: 5000, interval: 5 });
}

/** Counts the calls of the in-page crypto service. */
function countingCrypto() {
  const counts = { hash: 0, prepare: 0, range: 0, opened: 0, disposed: 0 };
  const factory: CryptoFactory = async (key) => {
    counts.opened++;
    const inner = createInThreadUploadCrypto(key);
    const wrapped: UploadCrypto = {
      hash: (...a) => (counts.hash++, inner.hash(...a)),
      prepare: (...a) => (counts.prepare++, inner.prepare(...a)),
      range: (...a) => (counts.range++, inner.range(...a)),
      dispose: () => (counts.disposed++, inner.dispose()),
    };
    return wrapped;
  };
  return { counts, factory };
}

async function decryptUploads(server: FakeServer, key: string, count: number) {
  const k = parseKey(key);
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    out.push(await decryptBytes({ key: k, index: i }, server.bytes(`/api/v1/uploads/u${i}`)));
  }
  return out;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('end-to-end encryption policy', () => {
  const levels = (policies: ('forbidden' | 'allowed' | 'required' | undefined)[]) =>
    policies.map((p, i) => ({
      key: `l${i}`,
      label: `Level ${i}`,
      isDefault: i === 0,
      rules,
      ...(p === undefined ? {} : { e2ePolicy: p }),
    }));

  it('follows the tenant policy without levels, forbidden when absent', async () => {
    const absent = setup({}, { tenant: tenantWith() }).flow;
    expect(absent.e2ePolicy).toBe('forbidden');
    expect(absent.e2eOffered).toBe(false);
    const allowed = setup({}, { tenant: tenantWith({}, 'allowed') }).flow;
    expect([allowed.e2eOffered, allowed.e2eRequired, allowed.e2eEffective]).toEqual([true, false, false]);
    allowed.form.endToEnd = true;
    expect(allowed.e2eEffective).toBe(true);
    const required = setup({}, { tenant: tenantWith({}, 'required') }).flow;
    expect([required.e2eOffered, required.e2eRequired, required.e2eEffective]).toEqual([true, true, true]);
    const noFeatures = setup({}, { tenant: { ...tenantWith(), features: undefined } }).flow;
    expect(noFeatures.e2ePolicy).toBe('forbidden');
  });

  it('follows the effective policy of the chosen level and resets the choice when forbidden', () => {
    const { flow } = setup(
      {},
      {
        tenant: tenantWith(
          { confidentialityLevels: levels(['allowed', 'forbidden', 'required', undefined]) },
          'allowed',
        ),
      },
    );
    expect(flow.e2ePolicy).toBe('allowed');
    flow.form.endToEnd = true;
    flow.setLevel('l2');
    expect(flow.e2eRequired).toBe(true);
    flow.setLevel('l1');
    expect(flow.e2eOffered).toBe(false);
    expect(flow.form.endToEnd).toBe(false);
    flow.setLevel('l3');
    expect(flow.e2ePolicy).toBe('forbidden');
  });

  it('is never offered through a drop link', () => {
    const { flow } = setup(
      {},
      {
        tenant: tenantWith({}, 'required'),
        dropLink: { token: 'ttd_x', label: 'Invoices', validityDays: 7 },
      },
    );
    expect(flow.e2eOffered).toBe(false);
  });

  it('maps the not_scanned_e2e status to neutral texts', () => {
    expect(scanStatusKey({ has: () => true }, 'not_scanned_e2e')).toBe('deposit.e2e.scanStatus');
    expect(scanWarningKey('not_scanned_e2e')).toBe('deposit.e2e.notScanned');
  });

  it('applies the size limit to the encrypted sizes', async () => {
    const plain = 1000;
    const { flow, calls } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session('internal', plain + 10) } },
      { tenant: tenantWith({}, 'required') },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(plain), 'a.bin')]);
    expect(flow.totalBytes).toBe(encryptedSize(plain));
    await flow.submitTransfer();
    expect(flow.formErrors['files']).toEqual({ key: 'deposit.form.files.tooLarge' });
    expect(calls.filter((c) => c.method === 'POST')).toEqual([]);
  });
});

describe('end-to-end encrypted deposit', () => {
  it('prepares, seals the body, uploads ciphertext that decrypts, then shows the key once', async () => {
    const a = bytes(70_000, 3);
    const b = bytes(0);
    const { flow, calls, server, store, announce, engines } = setup({
      'GET /deposit-sessions/current': { status: 200, body: session() },
    });
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.form.message = 'Hello 👋';
    flow.form.endToEnd = true;
    flow.addFiles([depositFile(a, 'plan.pdf', 'site/a', 'application/pdf'), depositFile(b, 'empty.txt')]);
    const submitting = flow.submitTransfer();
    expect(flow.step).toBe('preparing');
    expect(flow.preparation).toMatchObject({ hashedBytes: 0, totalBytes: 70_000 });
    await submitting;
    expect(flow.e2eActive).toBe(true);
    const post = calls.find((c) => c.method === 'POST' && c.path === '/transfers');
    const body = post?.body as TransferCreate;
    expect(body).toMatchObject({ endToEndEncrypted: true, recipients: ['bob@example.com'] });
    expect(body).not.toHaveProperty('message');
    expect(body.files.map((f) => [f.name, f.size, 'path' in f, 'mediaType' in f])).toEqual([
      ['file-1.tte2', ciphertextSize(70_000, DEFAULT_CHUNK_SIZE), false, false],
      ['file-2.tte2', ciphertextSize(0, DEFAULT_CHUNK_SIZE), false, false],
    ]);
    const record = store.value;
    expect(record?.e2e?.salts).toHaveLength(2);
    expect(record?.e2e?.chunkSize).toBe(DEFAULT_CHUNK_SIZE);
    const key = parseKey(record?.e2e?.key ?? '');
    await expect(openMetadata(key, 0, body.files[0]?.encryptedMetadata ?? '')).resolves.toEqual({
      index: 0,
      count: 2,
      name: 'plan.pdf',
      path: 'site/a',
      type: 'application/pdf',
      size: 70_000,
      sha256: hex(a),
    });
    await expect(openMetadata(key, 1, body.files[1]?.encryptedMetadata ?? '')).resolves.toMatchObject({
      name: 'empty.txt',
      path: '',
      type: '',
    });
    await expect(openMessage(key, body.encryptedMessage ?? '')).resolves.toBe('Hello 👋');
    await until(flow, 'done');
    expect(engines[0]?.getSnapshot().files.map((f) => f.name)).toEqual(['site/a/plan.pdf', 'empty.txt']);
    expect(await decryptUploads(server, record?.e2e?.key ?? '', 2)).toEqual([a, b]);
    expect(flow.e2eKey).toBe(record?.e2e?.key);
    expect(flow.e2eActive).toBe(false);
    expect(flow.e2eFiles).toEqual([
      { name: 'plan.pdf', path: 'site/a', sha256: hex(a) },
      { name: 'empty.txt', path: '', sha256: hex(b) },
    ]);
    expect(store.value).toBeUndefined();
    expect(announce).toHaveBeenCalledWith('deposit.e2e.preparing.done');
    flow.newTransfer();
    expect(flow.e2eKey).toBeUndefined();
    expect(flow.e2eFiles).toBeUndefined();
  });

  it('retries a transient failure with the same sealed body and key, without hashing again', async () => {
    const { counts, factory } = countingCrypto();
    const { flow, calls } = setup(
      (create) => ({
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'POST /transfers': [{ status: 503, body: { code: 'internal-error', status: 503 } }, create],
      }),
      { tenant: tenantWith({}, 'required'), openCrypto: factory },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.form.message = 'secret';
    flow.addFiles([depositFile(bytes(100), 'a.bin')]);
    await flow.submitTransfer();
    expect(flow.step).toBe('form');
    expect(flow.stepError).toBeDefined();
    await flow.submitTransfer();
    const posts = calls.filter((c) => c.method === 'POST' && c.path === '/transfers');
    expect(posts).toHaveLength(2);
    expect(posts[1]?.body).toEqual(posts[0]?.body);
    expect(posts[1]?.headers.get('Idempotency-Key')).toBe(posts[0]?.headers.get('Idempotency-Key'));
    expect(counts.hash).toBe(1);
    await until(flow, 'done');
    expect(counts.opened).toBe(1);
    expect(counts.disposed).toBe(1);
  });

  it('seals again with a new key when the form changed after a failure', async () => {
    const { counts, factory } = countingCrypto();
    const { flow, calls } = setup(
      (create) => ({
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'POST /transfers': [{ status: 503, body: { code: 'internal-error', status: 503 } }, create],
      }),
      { tenant: tenantWith({}, 'required'), openCrypto: factory },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(100), 'a.bin')]);
    await flow.submitTransfer();
    flow.form.message = 'added';
    await flow.submitTransfer();
    const posts = calls.filter((c) => c.method === 'POST' && c.path === '/transfers');
    const [first, second] = posts.map((p) => p.body as TransferCreate);
    expect(second?.files[0]?.encryptedMetadata).not.toBe(first?.files[0]?.encryptedMetadata);
    expect(second?.encryptedMessage).toBeDefined();
    expect(posts[1]?.headers.get('Idempotency-Key')).not.toBe(posts[0]?.headers.get('Idempotency-Key'));
    expect(counts.hash).toBe(2);
    // The Worker of the abandoned submission is released.
    expect(counts.disposed).toBeGreaterThanOrEqual(1);
    await until(flow, 'done');
  });

  it('seals again for other files with the same fingerprints, and handles empty files', async () => {
    const { counts, factory } = countingCrypto();
    const { flow, calls } = setup(
      (create) => ({
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'POST /transfers': [{ status: 503, body: { code: 'internal-error', status: 503 } }, create],
      }),
      { tenant: tenantWith({}, 'required'), openCrypto: factory },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(0), 'empty.txt')]);
    const submitting = flow.submitTransfer();
    expect(flow.preparation).toEqual({ kind: 'create', hashedBytes: 0, totalBytes: 0, percent: 100 });
    await submitting;
    flow.removeFile(0);
    flow.addFiles([depositFile(bytes(0), 'empty.txt')]);
    await flow.submitTransfer();
    const posts = calls.filter((c) => c.method === 'POST' && c.path === '/transfers');
    expect(posts).toHaveLength(2);
    expect(posts[1]?.body).not.toEqual(posts[0]?.body);
    // Same plaintext form: the Idempotency-Key is kept (no request was created with it).
    expect(posts[1]?.headers.get('Idempotency-Key')).toBe(posts[0]?.headers.get('Idempotency-Key'));
    expect(counts.hash).toBe(2);
    await until(flow, 'done');
  });

  it('shows the server refusals next to the option', async () => {
    const { flow } = setup({
      'GET /deposit-sessions/current': { status: 200, body: session() },
      'POST /transfers': [
        { status: 400, body: { code: 'e2e-required', status: 400 } },
        { status: 403, body: { code: 'e2e-forbidden', status: 403 } },
      ],
    });
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ endToEnd: { key: 'deposit.e2e.required' } });
    flow.form.endToEnd = true;
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ endToEnd: { key: 'deposit.e2e.forbidden' } });
    expect(flow.formRefusals).toBe(2);
  });

  it('cancels the preparation and goes back to the form', async () => {
    let release: (() => void) | undefined;
    const factory: CryptoFactory = async (key) => {
      const inner = createInThreadUploadCrypto(key);
      return {
        ...inner,
        hash: (_index, _file, _chunkSize, onProgress, signal) =>
          new Promise<string>((resolve, reject) => {
            onProgress?.(5);
            release = () =>
              signal?.aborted ? reject(new DOMException('x', 'AbortError')) : resolve('0'.repeat(64));
          }),
      };
    };
    const { flow, calls } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      { tenant: tenantWith({}, 'required'), openCrypto: factory },
    );
    await flow.start();
    flow.cancelPreparing();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    const submitting = flow.submitTransfer();
    await vi.waitFor(() => expect(release).toBeDefined());
    expect(flow.preparation).toMatchObject({ hashedBytes: 5, percent: 50 });
    flow.cancelPreparing();
    expect(flow.step).toBe('form');
    expect(flow.notice).toEqual({ key: 'deposit.e2e.preparing.cancelled' });
    // A new submission starts before the cancelled preparation settles: it stays busy.
    const firstRelease = release;
    release = undefined;
    const again = flow.submitTransfer();
    await vi.waitFor(() => expect(release).toBeDefined());
    firstRelease?.();
    await submitting;
    expect(flow.busy).toBe(true);
    flow.cancelPreparing();
    // TypeScript narrows release to undefined after the assignment above; the hash set it again.
    (release as (() => void) | undefined)?.();
    await again;
    expect(flow.step).toBe('form');
    expect(flow.busy).toBe(false);
    expect(flow.stepError).toBeUndefined();
    expect(calls.filter((c) => c.method === 'POST')).toEqual([]);
  });

  it('stops when the page is left or a new transfer is started during the preparation', async () => {
    let started = 0;
    const factory: CryptoFactory = async (key) => ({
      ...createInThreadUploadCrypto(key),
      hash: async (_index, _file, _chunkSize, _progress, signal) => {
        started++;
        await new Promise((resolve) => setTimeout(resolve, 300));
        if (signal?.aborted) throw new DOMException('x', 'AbortError');
        return '0'.repeat(64);
      },
    });
    for (const leave of ['dispose', 'newTransfer'] as const) {
      const { flow, calls } = setup(
        { 'GET /deposit-sessions/current': { status: 200, body: session() } },
        { tenant: tenantWith({}, 'required'), openCrypto: factory },
      );
      await flow.start();
      flow.form.recipientsText = 'bob@example.com';
      flow.addFiles([depositFile(bytes(10), 'a.bin')]);
      const submitting = flow.submitTransfer();
      await vi.waitFor(() => expect(started).toBeGreaterThan(0), { interval: 5 });
      started = 0;
      flow[leave]();
      await submitting;
      expect(calls.filter((c) => c.method === 'POST')).toEqual([]);
    }
  });

  it('reports a file that cannot be read during the preparation', async () => {
    const failing: CryptoFactory = async () => {
      throw new Error('worker');
    };
    const { flow } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      { tenant: tenantWith({}, 'required'), openCrypto: failing },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    expect(flow.step).toBe('form');
    expect(flow.stepError).toEqual({ message: { key: 'deposit.e2e.prepareFailed' } });
    expect(flow.preparation).toBeUndefined();
  });

  it('refuses to encrypt without WebCrypto', async () => {
    const { flow } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      { tenant: tenantWith({}, 'required') },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    vi.stubGlobal('crypto', {});
    await flow.submitTransfer();
    vi.unstubAllGlobals();
    expect(flow.stepError).toEqual({ message: { key: 'deposit.e2e.unsupported' } });
    expect(flow.busy).toBe(false);
  });

  it('shows the full link of a link-only transfer, key included', async () => {
    const { flow, calls } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      {
        tenant: tenantWith({}, 'allowed'),
        finalize: async () => ({
          kind: 'available',
          transfer: {
            ...created({ expiryDays: 7, files: [] }),
            status: 'available',
            linkOnly: true,
            downloadUrl: 'https://t.example.com/d/dl_x',
          },
        }),
      },
    );
    await flow.start();
    flow.setLinkOnly(true);
    flow.form.endToEnd = true;
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    const body = calls.find((c) => c.method === 'POST' && c.path === '/transfers')?.body as TransferCreate;
    expect(body).toMatchObject({ linkOnly: true, endToEndEncrypted: true });
    expect(body).not.toHaveProperty('recipients');
    await until(flow, 'done');
    expect(flow.linkOnlyUrl).toBe('https://t.example.com/d/dl_x');
    expect(flow.e2eKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('shows no key when the transfer is refused', async () => {
    const { flow } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      {
        tenant: tenantWith({}, 'required'),
        finalize: async () => ({
          kind: 'rejected',
          transfer: { ...created({ expiryDays: 7, files: [] }), status: 'rejected' },
        }),
      },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    await until(flow, 'done');
    expect(flow.outcome).toBe('rejected');
    expect(flow.e2eKey).toBeUndefined();
  });

  it('fails the upload when the encrypted size differs from the declared one', async () => {
    const { flow, engines } = setup(
      (create) => ({
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'POST /transfers': (body) => {
          const b = body as TransferCreate;
          const r = create({ ...b, files: b.files.map((f) => ({ ...f, size: f.size + 1 })) });
          return r;
        },
      }),
      { tenant: tenantWith({}, 'required') },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    await vi.waitFor(() => expect(engines[0]?.getSnapshot().phase).toBe('failed'));
    expect(engines[0]?.getSnapshot().error?.code).toBe('file-unreadable');
  });

  it('forgets the encryption state when the upload is cancelled', async () => {
    const { counts, factory } = countingCrypto();
    const server = new FakeServer();
    const { flow } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'DELETE /transfers/trf_1': { status: 204 },
      },
      { tenant: tenantWith({}, 'required'), openCrypto: factory, server },
    );
    server.patchFaults.push({ kind: 'stall', keep: 0 });
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    await vi.waitFor(() => expect(counts.range).toBe(1));
    await flow.cancelUpload();
    expect(flow.step).toBe('form');
    expect(flow.e2eActive).toBe(false);
    expect(flow.e2eFiles).toBeUndefined();
    expect(counts.disposed).toBe(1);
  });
});

describe('end-to-end encrypted resume after a reload', () => {
  async function interrupted() {
    const small = bytes(300, 2);
    const a = bytes(150_000, 5);
    const server = new FakeServer();
    const store = memoryStore();
    const first = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      { tenant: tenantWith({}, 'required'), server, store },
    );
    // The first file is sent, the second PATCH stores 10 000 bytes, then the connection is cut:
    // the page is then left.
    server.patchFaults.push({ kind: 'ok' }, { kind: 'cut', keep: 10_000 });
    await first.flow.start();
    first.flow.form.recipientsText = 'bob@example.com';
    first.flow.addFiles([depositFile(small, 'small.txt'), depositFile(a, 'big.bin', 'dir')]);
    await first.flow.submitTransfer();
    await vi.waitFor(() => expect(first.engines[0]?.getSnapshot().phase).toBe('retrying'));
    const record = store.value as ResumeRecord;
    first.flow.dispose();
    expect(server.uploads.get('/api/v1/uploads/u1')?.offset).toBe(10_000);
    return { small, a, server, store, record };
  }

  function uploading(extra: Partial<SenderTransfer> = {}): SenderTransfer {
    const body: TransferCreate = {
      expiryDays: 7,
      endToEndEncrypted: true,
      files: [
        { name: 'file-1.tte2', size: ciphertextSize(300, DEFAULT_CHUNK_SIZE) },
        { name: 'file-2.tte2', size: ciphertextSize(150_000, DEFAULT_CHUNK_SIZE) },
      ],
    };
    const t = created(body);
    // The first file is complete on the server (its offset is recorded at the end of its upload).
    t.files = t.files.map((f, i) => (i === 0 ? { ...f, uploadOffset: f.size } : f));
    return { ...t, ...extra };
  }

  it('regenerates the same bytes with the stored key and salts', async () => {
    const { small, a, server, store, record } = await interrupted();
    expect(record.e2e).toBeDefined();
    const second = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading() },
      },
      {
        tenant: tenantWith({}, 'required'),
        server,
        store,
        finalize: async () => ({
          kind: 'available',
          transfer: { ...uploading(), status: 'available' },
        }),
      },
    );
    await second.flow.start();
    expect(second.flow.step).toBe('resume');
    expect(second.flow.e2eActive).toBe(true);
    expect(second.flow.e2eFiles).toEqual([
      { name: 'small.txt', path: '', sha256: hex(small) },
      { name: 'big.bin', path: 'dir', sha256: hex(a) },
    ]);
    // The first file is complete on the server: only the second one is selected again.
    second.flow.addResumeFiles([depositFile(a, 'big.bin', 'dir')]);
    await second.flow.continueResume();
    await until(second.flow, 'done');
    expect(await decryptUploads(server, record.e2e?.key ?? '', 2)).toEqual([small, a]);
    expect(second.flow.e2eKey).toBe(record.e2e?.key);
  });

  it('refuses to resume with a reselected file whose content changed, without sending anything', async () => {
    const { a, server, store } = await interrupted();
    const { counts, factory } = countingCrypto();
    const second = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading() },
        'DELETE /transfers/trf_1': { status: 204 },
      },
      { tenant: tenantWith({}, 'required'), server, store, openCrypto: factory },
    );
    await second.flow.start();
    expect(second.flow.step).toBe('resume');
    const modified = new Uint8Array(a);
    modified[100_000]! ^= 1;
    // Same folder, name, size and date: the fingerprint matches, the content does not.
    second.flow.addResumeFiles([depositFile(modified, 'big.bin', 'dir')]);
    expect(second.flow.resumeMissing).toEqual([]);
    await second.flow.continueResume();
    expect(second.flow.step).toBe('form');
    expect(second.flow.stepError).toEqual({ message: { key: 'deposit.e2e.resumeChanged' } });
    expect(second.announce).toHaveBeenCalledWith('deposit.e2e.resumeChanged', 'assertive');
    expect(store.value).toBeUndefined();
    expect(second.flow.e2eActive).toBe(false);
    expect(second.flow.transfer).toBeUndefined();
    expect(second.engines).toEqual([]);
    expect(counts).toMatchObject({ hash: 1, prepare: 0, range: 0 });
    expect(second.calls.some((c) => c.method === 'DELETE' && c.path === '/transfers/trf_1')).toBe(true);
    expect(server.uploads.get('/api/v1/uploads/u1')?.offset).toBe(10_000);
  });

  it('checks the reselected files with progress, and goes back to the resume step when cancelled or unreadable', async () => {
    const { a, store } = await interrupted();
    let release: ((fail: boolean) => void) | undefined;
    const factory: CryptoFactory = async (key) => ({
      ...createInThreadUploadCrypto(key),
      hash: (_index, _file, _chunkSize, onProgress, signal) =>
        new Promise<string>((resolve, reject) => {
          onProgress?.(75_000);
          release = (fail) =>
            signal?.aborted
              ? reject(new DOMException('x', 'AbortError'))
              : fail
                ? reject(new Error('unreadable'))
                : resolve('0'.repeat(64));
        }),
    });
    const { flow } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading() },
      },
      { tenant: tenantWith({}, 'required'), store, openCrypto: factory },
    );
    await flow.start();
    flow.addResumeFiles([depositFile(a, 'big.bin', 'dir')]);
    const checking = flow.continueResume();
    await vi.waitFor(() => expect(release).toBeDefined());
    expect(flow.step).toBe('preparing');
    expect(flow.busy).toBe(true);
    expect(flow.preparation).toEqual({
      kind: 'resume',
      hashedBytes: 75_000,
      totalBytes: 150_000,
      percent: 50,
    });
    // Ignored while the check runs.
    await flow.continueResume();
    flow.cancelPreparing();
    expect(flow.step).toBe('resume');
    expect(flow.notice).toEqual({ key: 'deposit.e2e.preparing.resumeCancelled' });
    release?.(false);
    await checking;
    expect(flow.step).toBe('resume');
    expect(flow.busy).toBe(false);
    expect(store.value).toBeDefined();

    release = undefined;
    const failing = flow.continueResume();
    await vi.waitFor(() => expect(release).toBeDefined());
    (release as ((fail: boolean) => void) | undefined)?.(true);
    await failing;
    expect(flow.step).toBe('resume');
    expect(flow.stepError).toEqual({ message: { key: 'deposit.e2e.prepareFailed' } });
    expect(flow.preparation).toBeUndefined();
    expect(flow.busy).toBe(false);
    expect(store.value).toBeDefined();
  });

  it('stays on the resume step when a check cancelled too late still succeeds', async () => {
    const { a, store } = await interrupted();
    let release: (() => void) | undefined;
    const factory: CryptoFactory = async (key) => {
      const inner = createInThreadUploadCrypto(key);
      return {
        ...inner,
        // A Worker answer already on its way when the abort is posted: the hash still resolves.
        hash: async (index, file, chunkSize) => {
          const hash = await inner.hash(index, file, chunkSize);
          await new Promise<void>((resolve) => (release = resolve));
          return hash;
        },
      };
    };
    const { flow, engines } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading() },
      },
      { tenant: tenantWith({}, 'required'), store, openCrypto: factory },
    );
    await flow.start();
    flow.addResumeFiles([depositFile(a, 'big.bin', 'dir')]);
    const checking = flow.continueResume();
    await vi.waitFor(() => expect(release).toBeDefined());
    flow.cancelPreparing();
    release?.();
    await checking;
    expect(flow.step).toBe('resume');
    expect(engines).toEqual([]);
    expect(store.value).toBeDefined();
  });

  it('shows the key of a transfer completed before the reload', async () => {
    const { small, a, store, record } = await interrupted();
    const { flow } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading({ status: 'available' }) },
      },
      { tenant: tenantWith({}, 'required'), store },
    );
    await flow.start();
    expect(flow.step).toBe('done');
    expect(flow.e2eKey).toBe(record.e2e?.key);
    expect(flow.e2eFiles).toEqual([
      { name: 'small.txt', path: '', sha256: hex(small) },
      { name: 'big.bin', path: 'dir', sha256: hex(a) },
    ]);
    expect(store.value).toBeUndefined();
  });

  it('drops a record that does not match the transfer', async () => {
    const { store } = await interrupted();
    const { flow } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading({ endToEndEncrypted: false }) },
      },
      { tenant: tenantWith({}, 'required'), store },
    );
    await flow.start();
    expect(flow.step).toBe('form');
    expect(store.value).toBeUndefined();
    expect(flow.e2eActive).toBe(false);
  });

  it('forgets the state of an expired transfer and of a discarded resume', async () => {
    const { store, record } = await interrupted();
    const expired = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading({ status: 'expired' }) },
      },
      { tenant: tenantWith({}, 'required'), store: memoryStore(record) },
    );
    await expired.flow.start();
    expect(expired.flow.step).toBe('form');
    expect(expired.flow.e2eActive).toBe(false);
    expect(expired.flow.e2eFiles).toBeUndefined();

    const discarded = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 200, body: uploading() },
        'DELETE /transfers/trf_1': { status: 204 },
      },
      { tenant: tenantWith({}, 'required'), store },
    );
    await discarded.flow.start();
    expect(discarded.flow.step).toBe('resume');
    await discarded.flow.discardResume();
    expect(discarded.flow.e2eActive).toBe(false);
    expect(discarded.flow.e2eFiles).toBeUndefined();
  });
});

/** A file whose content can change after it was selected (same name, size and date). */
class MutableFile extends File {
  current: Uint8Array<ArrayBuffer>;
  constructor(data: Uint8Array<ArrayBuffer>, name: string) {
    super([data], name, { lastModified: 1 });
    this.current = new Uint8Array(data);
  }
  override slice(start?: number, end?: number): Blob {
    return new Blob([this.current.slice(start, end)]);
  }
}

describe('end-to-end encryption nonce reuse guard', () => {
  it('stops the upload with file-changed, without sending the chunk, when a file changes after its hash', async () => {
    const { counts, factory } = countingCrypto();
    const server = new FakeServer();
    const file = new MutableFile(bytes(3000, 4), 'a.bin');
    const wrapped: CryptoFactory = async (key) => {
      const inner = await factory(key);
      return {
        ...inner,
        prepare: (index, blob, salt, chunkSize) => {
          // The file is modified on disk between the hash pass and the first encrypted range.
          file.current[10]! ^= 0xff;
          return inner.prepare(index, blob, salt, chunkSize);
        },
      };
    };
    const { flow, engines } = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: session() } },
      { tenant: tenantWith({}, 'required'), openCrypto: wrapped, server },
    );
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([file as DepositFile]);
    await flow.submitTransfer();
    await vi.waitFor(() => expect(engines[0]?.getSnapshot().phase).toBe('failed'));
    expect(engines[0]?.getSnapshot().error?.code).toBe('file-changed');
    expect(counts.range).toBe(1);
    expect(server.calls.filter((c) => c.startsWith('PATCH'))).toEqual([]);
    expect(server.uploads.get('/api/v1/uploads/u0')?.offset).toBe(0);
  });

  it('stops the engine before releasing the encryption when the session is established again', async () => {
    const { counts, factory } = countingCrypto();
    const server = new FakeServer();
    const store = memoryStore();
    const { flow, engines } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: session() },
        'GET /transfers/trf_1': { status: 503, body: { type: 'about:blank', title: 'x', status: 503 } },
      },
      { tenant: tenantWith({}, 'required'), openCrypto: factory, server, store },
    );
    server.patchFaults.push({ kind: 'stall', keep: 0 });
    await flow.start();
    flow.form.recipientsText = 'bob@example.com';
    flow.addFiles([depositFile(bytes(10), 'a.bin')]);
    await flow.submitTransfer();
    await vi.waitFor(() => expect(counts.range).toBe(1));
    await flow.start();
    expect(engines[0]?.isActive()).toBe(false);
    expect(flow.e2eActive).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(counts.opened).toBe(1);
    expect(counts.disposed).toBe(1);
  });
});
