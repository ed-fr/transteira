import { describe, expect, it, vi } from 'vitest';
import { createApiClient } from '../../shared/api/client';
import type {
  UploadAnnouncement,
  UploadEngine,
  UploadFileSpec,
  UploadSnapshot,
} from '../../shared/upload/engine';
import { UploadError } from '../../shared/upload/engine';
import type { FinalizeOutcome, SenderTransfer } from '../../shared/upload/finalize';
import type { ResumeRecord, ResumeStore } from '../../shared/upload/resume-store';
import {
  announcementText,
  DepositFlow,
  finalizeErrorKey,
  scanStatusKey,
  scanWarningKey,
  type DepositSession,
  type FinalizeFn,
  type InvitationContext,
  type ReplyContext,
  type PublicTenant,
  type ScanStatus,
} from './flow.svelte';

// ---- Fakes ----------------------------------------------------------------------------------

interface Reply {
  status: number;
  body?: unknown;
}

interface Call {
  method: string;
  path: string;
  body: unknown;
  headers: Headers;
}

function problem(status: number, code: string, extra: Record<string, unknown> = {}): Reply {
  return { status, body: { type: 'about:blank', title: code, status, code, ...extra } };
}

/** Fake fetch answering "METHOD /path" routes (a list is consumed in order, the last one sticks). */
function fakeApi(routes: Record<string, Reply | Reply[] | Error>) {
  const calls: Call[] = [];
  const csrf: string[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'https://transfer.entity-a.example.com');
    const method = init?.method ?? 'GET';
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const body = typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined;
    calls.push({ method, path, body, headers: new Headers(init?.headers) });
    const route = routes[`${method} ${path}`];
    if (route === undefined) {
      throw new Error(`unexpected request ${method} ${path}`);
    }
    if (route instanceof Error) {
      throw route;
    }
    const reply = Array.isArray(route)
      ? route.length > 1
        ? (route.shift() as Reply)
        : (route[0] as Reply)
      : route;
    const type = reply.status >= 400 ? 'application/problem+json' : 'application/json';
    return new Response(reply.body === undefined ? null : JSON.stringify(reply.body), {
      status: reply.status,
      headers: { 'Content-Type': type },
    });
  };
  const api = createApiClient({
    fetch: fetch as typeof globalThis.fetch,
    language: () => 'en',
    csrfToken: () => undefined,
    onCsrfToken: (token) => csrf.push(token),
  });
  return { api, calls, csrf, routes };
}

interface FakeEngine extends UploadEngine {
  specs: UploadFileSpec[];
  cancelTransfer: () => Promise<void>;
  finish(result: 'completed' | 'cancelled'): void;
  fail(err: unknown): void;
  emit(snapshot: Partial<UploadSnapshot>): void;
  say(a: UploadAnnouncement): void;
  active: boolean;
  stop: ReturnType<typeof vi.fn<() => void>>;
}

function fakeEngine(specs: UploadFileSpec[], cancelTransfer: () => Promise<void>): FakeEngine {
  let settle: { resolve: (r: 'completed' | 'cancelled') => void; reject: (e: unknown) => void } | undefined;
  const promise = new Promise<'completed' | 'cancelled'>((resolve, reject) => {
    settle = { resolve, reject };
  });
  let snapshot: UploadSnapshot = {
    phase: 'idle',
    files: specs.map((s) => ({ name: s.name, size: s.size ?? 0, uploadedBytes: 0, done: false })),
    currentIndex: 0,
    uploadedBytes: 0,
    totalBytes: specs.reduce((sum, s) => sum + (s.size ?? 0), 0),
    percent: 0,
    failures: 0,
  };
  const runs = new Set<(s: UploadSnapshot) => void>();
  const announces = new Set<(a: UploadAnnouncement) => void>();
  const engine: FakeEngine = {
    specs,
    cancelTransfer,
    active: false,
    start: vi.fn(() => {
      engine.active = true;
      engine.emit({ phase: 'uploading' });
      return promise;
    }),
    pause: vi.fn(),
    resume: vi.fn(),
    stop: vi.fn(() => {
      engine.active = false;
    }),
    cancel: vi.fn(async () => {
      engine.active = false;
      settle?.resolve('cancelled');
      await cancelTransfer();
    }),
    getSnapshot: () => snapshot,
    subscribe(run) {
      runs.add(run);
      run(snapshot);
      return () => runs.delete(run);
    },
    onAnnounce(listener) {
      announces.add(listener);
      return () => announces.delete(listener);
    },
    isActive: () => engine.active,
    finish(result) {
      engine.active = false;
      settle?.resolve(result);
    },
    fail(err) {
      engine.active = false;
      settle?.reject(err);
    },
    emit(partial) {
      snapshot = { ...snapshot, ...partial };
      for (const run of runs) run(snapshot);
    },
    say(a) {
      for (const l of announces) l(a);
    },
  };
  return engine;
}

function memoryStore(initial?: ResumeRecord): ResumeStore & { value: ResumeRecord | undefined } {
  const store = {
    value: initial,
    save(record: ResumeRecord) {
      store.value = record;
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

const tr = {
  t: (key: string, params?: Record<string, string | number>) =>
    params === undefined ? key : `${key} ${JSON.stringify(params)}`,
  has: (key: string) => !key.endsWith('.unknown-code'),
};

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
  limits: { maxTransferBytes: 1000, expiryDays: [1, 7, 30] },
  maintenance: false,
  legalDocuments: [],
};

const internalSession: DepositSession = {
  email: 'alice@entity-a.example.com',
  kind: 'internal',
  csrfToken: 'csrf_1',
  expiresAt: '2026-10-23T20:00:00Z',
  limits: { maxTransferBytes: 1000, expiryDays: [1, 7, 30] },
  canInvite: true,
};

const externalSession: DepositSession = {
  email: 'bob@partner.example.org',
  kind: 'external',
  csrfToken: 'csrf_2',
  expiresAt: '2026-10-23T20:00:00Z',
  limits: { maxTransferBytes: 1000, expiryDays: [1, 7] },
  canInvite: false,
  invitation: { invitedBy: 'alice@entity-a.example.com', expiresAt: '2027-10-01T08:00:00Z' },
};

const invitation: InvitationContext = {
  token: 'inv_0123456789012345678901', // gitleaks:allow (fake invitation token)
  email: 'bob@partner.example.org',
  invitedBy: 'alice@entity-a.example.com',
};

const replySession: DepositSession = {
  email: 'carol@customer.example.net',
  kind: 'reply',
  csrfToken: 'csrf_3',
  expiresAt: '2026-10-23T20:00:00Z',
  limits: { maxTransferBytes: 1000, expiryDays: [1, 7] },
  canInvite: false,
  reply: { recipient: 'alice@entity-a.example.com', transferExpiresAt: '2026-10-25T08:00:00Z' },
};

const replyContext: ReplyContext = {
  token: 'dl_0123456789012345678901', // gitleaks:allow (fake download token)
  recipient: 'alice@entity-a.example.com',
  transferExpiresAt: '2026-10-25T08:00:00Z',
};

const challenge = {
  challengeId: 'vch_1',
  email: 'alice@entity-a.example.com',
  expiresAt: '2026-10-23T16:15:00Z',
  attemptsRemaining: 2,
};

function transfer(status: SenderTransfer['status'], extra: Partial<SenderTransfer> = {}): SenderTransfer {
  return {
    id: 'trf_1',
    status,
    senderEmail: 'alice@entity-a.example.com',
    recipients: ['carol@customer.example.net'],
    expiryDays: 7,
    passwordProtected: false,
    deleteAfterFirstDownload: false,
    totalBytes: 3,
    createdAt: '2026-10-23T16:00:00Z',
    files: [
      {
        id: 'fil_1',
        name: 'a.txt',
        size: 3,
        scanStatus: 'pending',
        uploadUrl: '/api/v1/uploads/upl_1',
        uploadOffset: 0,
      },
    ],
    ...extra,
  };
}

const file = (name = 'a.txt', content = 'abc') =>
  new File([content], name, { type: 'text/plain', lastModified: 1 });

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function setup(
  routes: Record<string, Reply | Reply[] | Error>,
  options: {
    tenant?: PublicTenant;
    invitation?: InvitationContext;
    reply?: ReplyContext;
    store?: ReturnType<typeof memoryStore>;
    finalize?: FinalizeFn;
    poll?: FinalizeFn;
    confirm?: (message: string) => boolean;
  } = {},
) {
  const fake = fakeApi(routes);
  const engines: FakeEngine[] = [];
  const store = options.store ?? memoryStore();
  const announce = vi.fn();
  const clearCsrf = vi.fn();
  let keys = 0;
  const finalize = vi.fn<FinalizeFn>(
    options.finalize ?? (async () => ({ kind: 'available', transfer: transfer('available') })),
  );
  const poll = vi.fn<FinalizeFn>(
    options.poll ?? (async () => ({ kind: 'available', transfer: transfer('available') })),
  );
  const confirm = vi.fn(options.confirm ?? (() => true));
  const sleeps: number[] = [];
  const flow = new DepositFlow(
    options.tenant ?? tenant,
    options.invitation,
    {
      api: fake.api,
      tr,
      clearCsrf,
      resumeStore: store,
      createEngine: (specs, cancelTransfer) => {
        const engine = fakeEngine(specs, cancelTransfer);
        engines.push(engine);
        return engine;
      },
      finalize,
      poll,
      confirm,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      announce,
      language: () => 'fr',
      newKey: () => `key-${++keys}`,
      now: () => 1_000_000,
    },
    options.reply,
  );
  return { flow, ...fake, engines, store, announce, clearCsrf, finalize, poll, confirm, sleeps };
}

async function readyForm(routes: Record<string, Reply | Reply[] | Error> = {}, options = {}) {
  const ctx = setup(
    { 'GET /deposit-sessions/current': { status: 200, body: internalSession }, ...routes },
    options,
  );
  await ctx.flow.start();
  return ctx;
}

// ---- Pure helpers -----------------------------------------------------------------------------

describe('helpers', () => {
  it('words the engine announcements', () => {
    expect(announcementText(tr, { kind: 'progress', percent: 40 })).toBe(
      'upload.announce.progress {"percent":40}',
    );
    expect(announcementText(tr, { kind: 'file-done', index: 0, name: 'a' })).toBe(
      'upload.announce.fileDone {"name":"a"}',
    );
    expect(announcementText(tr, { kind: 'paused', reason: 'user' })).toBe('upload.announce.pausedUser');
    expect(announcementText(tr, { kind: 'paused', reason: 'failures' })).toBe(
      'upload.announce.pausedFailures',
    );
    expect(announcementText(tr, { kind: 'error', code: 'forbidden' })).toBe('upload.announce.error');
    expect(announcementText(tr, { kind: 'completed' })).toBe('upload.announce.completed');
    expect(announcementText(tr, { kind: 'cancelled' })).toBe('upload.announce.cancelled');
  });

  it('maps finalization failures and scan statuses to keys', () => {
    expect(finalizeErrorKey('checksum-mismatch')).toBe('upload.finalize.error.checksum-mismatch');
    expect(finalizeErrorKey('network')).toBe('upload.finalize.error.network');
    expect(finalizeErrorKey('internal-error')).toBe('upload.finalize.error.other');
    expect(scanStatusKey(tr, 'clean')).toBe('deposit.scan.clean');
    // A status added to the API later gets a generic wording.
    expect(scanStatusKey(tr, 'unknown-code' as ScanStatus)).toBe('deposit.scan.other');
    expect(scanWarningKey('clean')).toBeUndefined();
    expect(scanWarningKey('infected')).toBe('deposit.done.warning.infected');
    expect(scanWarningKey('not_scanned_too_large')).toBe('deposit.done.warning.notScanned');
    expect(scanWarningKey('not_scanned_encrypted')).toBe('deposit.done.warning.notScanned');
    expect(scanWarningKey('scan_error')).toBe('deposit.done.warning.scanError');
  });
});

// ---- Bootstrap ----------------------------------------------------------------------------------

describe('bootstrap', () => {
  it('shows the maintenance step without calling the API', async () => {
    const { flow, calls } = setup(
      {},
      {
        tenant: {
          ...tenant,
          maintenance: true,
          maintenanceMessage: 'Retour à 18 h',
          maintenanceMessageLanguage: 'fr',
        },
      },
    );
    await flow.start();
    expect(flow.step).toBe('maintenance');
    expect(flow.maintenanceMessage).toBe('Retour à 18 h');
    expect(flow.maintenanceMessageLanguage).toBe('fr');
    expect(calls).toEqual([]);
  });

  it('shows the maintenance step without message nor language', async () => {
    const { flow } = setup({}, { tenant: { ...tenant, maintenance: true, maintenanceMessage: '' } });
    await flow.start();
    expect(flow.step).toBe('maintenance');
    expect(flow.maintenanceMessage).toBeUndefined();
    expect(flow.maintenanceMessageLanguage).toBeUndefined();
  });

  it('opens the form for a current session, with the default expiry and limits', async () => {
    const { flow, csrf } = await readyForm();
    expect(flow.step).toBe('form');
    expect(flow.session?.email).toBe('alice@entity-a.example.com');
    expect(flow.form.expiryDays).toBe(7);
    expect(flow.canInvite).toBe(true);
    expect(flow.isExternal).toBe(false);
    expect(flow.limits.maxTransferBytes).toBe(1000);
    expect(csrf).toEqual(['csrf_1']);
  });

  it('asks for the email when there is no session', async () => {
    const { flow } = setup({ 'GET /deposit-sessions/current': problem(401, 'unauthenticated') });
    await flow.start();
    expect(flow.step).toBe('email');
    expect(flow.limits).toEqual(tenant.limits);
    expect(flow.canInvite).toBe(false);
  });

  it('shows an error step with retry on other failures', async () => {
    const { flow, routes } = setup({ 'GET /deposit-sessions/current': problem(500, 'internal-error') });
    await flow.start();
    expect(flow.step).toBe('error');
    expect(flow.errorText).toBe('errors.internal-error');
    routes['GET /deposit-sessions/current'] = new TypeError('offline');
    await flow.start();
    expect(flow.errorText).toBe('errors.network');
  });

  it('describes an external session', async () => {
    const { flow } = setup({ 'GET /deposit-sessions/current': { status: 200, body: externalSession } });
    await flow.start();
    expect(flow.isExternal).toBe(true);
    expect(flow.invitedBy).toBe('alice@entity-a.example.com');
    expect(flow.canInvite).toBe(false);
  });
});

// ---- Identification ---------------------------------------------------------------------------------

describe('identification', () => {
  async function emailStep(routes: Record<string, Reply | Reply[] | Error>) {
    const ctx = setup({ 'GET /deposit-sessions/current': problem(401, 'unauthenticated'), ...routes });
    await ctx.flow.start();
    return ctx;
  }

  it('validates the address before sending it', async () => {
    const { flow, calls } = await emailStep({});
    await flow.submitEmail();
    expect(flow.fieldError).toEqual({ key: 'fieldErrors.required' });
    flow.email = 'not-an-address';
    await flow.submitEmail();
    expect(flow.fieldError).toEqual({ key: 'fieldErrors.invalid-email' });
    expect(calls).toHaveLength(1);
  });

  it('goes through the code step to the form', async () => {
    const { flow, calls } = await emailStep({
      'POST /deposit-sessions': { status: 202, body: challenge },
      'POST /verification-challenges/vch_1/confirm': [
        problem(422, 'verification-code-invalid', { attemptsRemaining: 1 }),
        { status: 201, body: internalSession },
      ],
    });
    flow.email = ' alice@entity-a.example.com ';
    await flow.submitEmail();
    expect(flow.step).toBe('code');
    expect(calls[1]?.body).toEqual({ email: 'alice@entity-a.example.com' });

    flow.code = '12';
    await flow.submitCode();
    expect(flow.fieldError).toEqual({ key: 'deposit.code.format' });
    flow.code = '';
    await flow.submitCode();
    expect(flow.fieldError).toEqual({ key: 'fieldErrors.required' });

    flow.code = '111 111';
    await flow.submitCode();
    expect(calls[2]?.body).toEqual({ code: '111111' });
    expect(flow.fieldError).toEqual({ key: 'deposit.code.wrong' });
    expect(flow.attemptsRemaining).toBe(1);
    expect(flow.code).toBe('');

    flow.code = '482913';
    await flow.submitCode();
    expect(flow.step).toBe('form');
    expect(flow.attemptsRemaining).toBeUndefined();
  });

  it('opens the session at once for a recognised internal address', async () => {
    const { flow } = await emailStep({ 'POST /deposit-sessions': { status: 201, body: internalSession } });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.step).toBe('form');
  });

  it('returns to the email step when the code is exhausted', async () => {
    const { flow } = await emailStep({
      'POST /deposit-sessions': { status: 202, body: challenge },
      'POST /verification-challenges/vch_1/confirm': problem(410, 'verification-exhausted'),
    });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    flow.code = '000000';
    await flow.submitCode();
    expect(flow.step).toBe('email');
    expect(flow.errorText).toBe('deposit.code.exhausted');
    expect(flow.challenge).toBeUndefined();
  });

  it('resends a code and lets the user change the address', async () => {
    const { flow, calls } = await emailStep({ 'POST /deposit-sessions': { status: 202, body: challenge } });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    await flow.resendCode();
    expect(flow.notice).toEqual({ key: 'deposit.code.resent' });
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(2);
    flow.changeEmail();
    expect(flow.step).toBe('email');
    expect(flow.notice).toBeUndefined();
  });

  it('explains a refused deposit', async () => {
    const { flow } = await emailStep({ 'POST /deposit-sessions': problem(403, 'deposit-not-allowed') });
    flow.email = 'eve@elsewhere.example';
    await flow.submitEmail();
    expect(flow.step).toBe('email');
    expect(flow.errorText).toBe('deposit.email.notAllowed');
  });

  it('counts down after a rate limit', async () => {
    const { flow } = await emailStep({
      'POST /deposit-sessions': problem(429, 'rate-limited', { retryAfterSeconds: 90 }),
    });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.retryAt).toBe(1_000_000 + 90_000);
    expect(flow.secondsBeforeRetry()).toBe(90);
    expect(flow.secondsBeforeRetry(1_000_000 + 89_500)).toBe(1);
    expect(flow.secondsBeforeRetry(2_000_000)).toBe(0);
    expect(flow.errorText).toBe('errors.rate-limited');
  });

  it('switches to maintenance on a 503 maintenance problem', async () => {
    const { flow, calls } = await emailStep({
      'POST /deposit-sessions': problem(503, 'maintenance', { detail: 'Upgrade in progress' }),
    });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.step).toBe('maintenance');
    expect(flow.maintenanceMessage).toBe('Upgrade in progress');
    // GET /tenant is not routed: the language stays unknown.
    await vi.waitFor(() => {
      expect(calls.some((c) => c.path === '/tenant')).toBe(true);
    });
    await Promise.resolve();
    expect(flow.maintenanceMessageLanguage).toBeUndefined();
  });

  it('reads the language of a 503 maintenance message from GET /tenant', async () => {
    const maintenanceTenant = (message: string) => ({
      status: 200,
      body: { ...tenant, maintenance: true, maintenanceMessage: message, maintenanceMessageLanguage: 'fr' },
    });
    const { flow, calls } = await emailStep({
      'POST /deposit-sessions': problem(503, 'maintenance', { detail: 'Retour à 18 h' }),
      'GET /tenant': [maintenanceTenant('Retour à 18 h'), maintenanceTenant('Changed meanwhile')],
    });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.maintenanceMessage).toBe('Retour à 18 h');
    await vi.waitFor(() => {
      expect(flow.maintenanceMessageLanguage).toBe('fr');
    });
    expect(calls.filter((c) => c.path === '/tenant')).toHaveLength(1);

    // A message that no longer matches the tenant description gets no language.
    await flow.submitEmail();
    await vi.waitFor(() => {
      expect(calls.filter((c) => c.path === '/tenant')).toHaveLength(2);
    });
    await Promise.resolve();
    expect(flow.maintenanceMessageLanguage).toBeUndefined();
  });

  it('takes the language of a 503 maintenance message from the known tenant description', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': problem(401, 'unauthenticated'),
        'POST /deposit-sessions': problem(503, 'maintenance', { detail: 'Back at 6' }),
      },
      { tenant: { ...tenant, maintenanceMessage: 'Back at 6', maintenanceMessageLanguage: 'en' } },
    );
    await flow.start();
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.step).toBe('maintenance');
    expect(flow.maintenanceMessageLanguage).toBe('en');
    expect(calls.some((c) => c.path === '/tenant')).toBe(false);
  });

  it('gives no language to a 503 maintenance problem without detail', async () => {
    const { flow, calls } = await emailStep({ 'POST /deposit-sessions': problem(503, 'maintenance') });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.step).toBe('maintenance');
    expect(flow.maintenanceMessage).toBeUndefined();
    expect(flow.maintenanceMessageLanguage).toBeUndefined();
    expect(calls.some((c) => c.path === '/tenant')).toBe(false);
  });

  it('maps validation and unknown errors', async () => {
    const { flow, routes } = await emailStep({ 'POST /deposit-sessions': problem(400, 'validation-failed') });
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    expect(flow.fieldError).toEqual({ key: 'fieldErrors.invalid-email' });
    routes['POST /deposit-sessions'] = problem(500, 'mail-unavailable');
    await flow.submitEmail();
    expect(flow.errorText).toBe('errors.mail-unavailable');
  });
});

describe('invitation', () => {
  it('sends the code at once with the invitation token', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': problem(401, 'unauthenticated'),
        'POST /deposit-sessions': { status: 202, body: { ...challenge, email: invitation.email } },
      },
      { invitation },
    );
    expect(flow.email).toBe(invitation.email);
    expect(flow.isExternal).toBe(true);
    await flow.start();
    expect(flow.step).toBe('code');
    expect(calls[1]?.body).toEqual({ email: invitation.email, invitationToken: invitation.token });
  });

  it('reuses a session of the same invitation, not another one', async () => {
    const same = setup(
      { 'GET /deposit-sessions/current': { status: 200, body: externalSession } },
      { invitation },
    );
    await same.flow.start();
    expect(same.flow.step).toBe('form');

    const other = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: internalSession },
        'POST /deposit-sessions': { status: 202, body: challenge },
      },
      { invitation },
    );
    await other.flow.start();
    expect(other.flow.step).toBe('code');
  });

  it('stops when the invitation is gone', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': problem(401, 'unauthenticated'),
        'POST /deposit-sessions': problem(410, 'invitation-gone'),
      },
      { invitation },
    );
    await flow.start();
    expect(flow.step).toBe('email');
    expect(flow.invitationGone).toBe(true);
    expect(flow.errorText).toBe('deposit.email.invitationGone');
    await flow.submitEmail();
    expect(calls).toHaveLength(2);
  });
});

describe('reply', () => {
  it('opens the form with the sender as only recipient and never asks for recipients', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: replySession },
        'POST /transfers': { status: 201, body: transfer('uploading') },
      },
      { reply: replyContext },
    );
    expect(flow.isReply).toBe(true);
    expect(flow.replyRecipient).toBe('alice@entity-a.example.com');
    await flow.start();
    expect(flow.step).toBe('form');
    expect(flow.canInvite).toBe(false);
    flow.addFiles([file()]);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({});
    expect(calls[1]?.body).not.toHaveProperty('recipients');
  });

  it('describes a reply session without a context', async () => {
    const { flow } = setup({ 'GET /deposit-sessions/current': { status: 200, body: replySession } });
    await flow.start();
    expect(flow.isReply).toBe(true);
    expect(flow.replyRecipient).toBe('alice@entity-a.example.com');
  });

  it.each([
    ['no session', problem(401, 'unauthenticated')],
    ['another kind of session', { status: 200, body: internalSession }],
  ])('flags the reply as ended with %s', async (_name, current) => {
    const { flow, calls } = setup({ 'GET /deposit-sessions/current': current }, { reply: replyContext });
    await flow.start();
    expect(flow.replyEnded).toBe(true);
    expect(flow.step).toBe('loading');
    expect(calls).toHaveLength(1);
  });

  it('flags the reply as ended when the session ends or expires', async () => {
    const ended = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: replySession },
        'DELETE /deposit-sessions/current': { status: 204 },
      },
      { reply: replyContext },
    );
    await ended.flow.start();
    await ended.flow.endSession();
    expect(ended.flow.replyEnded).toBe(true);

    const expired = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: replySession },
        'POST /transfers': problem(401, 'unauthenticated'),
      },
      { reply: replyContext },
    );
    await expired.flow.start();
    expired.flow.addFiles([file()]);
    await expired.flow.submitTransfer();
    expect(expired.flow.replyEnded).toBe(true);
  });
});

// ---- Form and upload ------------------------------------------------------------------------------

describe('transfer', () => {
  it('refuses an invalid form without calling the API', async () => {
    const { flow, calls } = await readyForm();
    flow.form.recipientsText = 'nope';
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({
      'recipients.0': { key: 'fieldErrors.invalid-email' },
      files: { key: 'deposit.form.files.none' },
    });
    expect(flow.formRefusals).toBe(1);
    expect(calls).toHaveLength(1);
  });

  it('manages the file selection', async () => {
    const { flow } = await readyForm();
    flow.addFiles([file('a.txt'), file('b.txt', 'hello')]);
    flow.addFiles([file('a.txt')]);
    expect(flow.form.files.map((f) => f.name)).toEqual(['a.txt', 'b.txt']);
    expect(flow.totalBytes).toBe(8);
    flow.formErrors = { files: { key: 'x' }, 'files.1.name': { key: 'y' }, message: { key: 'z' } };
    flow.removeFile(0);
    expect(flow.form.files.map((f) => f.name)).toEqual(['b.txt']);
    expect(flow.formErrors).toEqual({ message: { key: 'z' } });
  });

  it('declares the folder of picked files and keeps same-named files of other folders', async () => {
    const { flow, calls } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
    });
    const a = file('a.txt');
    const b = file('a.txt');
    flow.addPicked([
      { file: a, path: 'docs/sub', hidden: false },
      { file: b, path: '', hidden: true },
    ]);
    expect(flow.form.files).toHaveLength(2);
    expect(flow.fileRoom).toBe(998);
    expect(flow.foldersEnabled).toBe(false);
    flow.form.recipientsText = 'carol@customer.example.net';
    await flow.submitTransfer();
    const files = (calls[1]?.body as { files: unknown[] }).files;
    expect(files).toEqual([
      { name: 'a.txt', size: 3, path: 'docs/sub', mediaType: 'text/plain' },
      { name: 'a.txt', size: 3, mediaType: 'text/plain' },
    ]);
  });

  it('creates the transfer, uploads, finalizes and shows the recap', async () => {
    const { flow, calls, engines, store, finalize, announce } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
    });
    flow.form.recipientsText = 'carol@customer.example.net\nCarol@customer.example.net';
    flow.form.message = 'Hello';
    flow.form.password = 'secret';
    flow.addFiles([file()]);
    await flow.submitTransfer();

    const post = calls[1];
    expect(post?.headers.get('Idempotency-Key')).toBe('key-1');
    expect(post?.body).toEqual({
      expiryDays: 7,
      deleteAfterFirstDownload: false,
      files: [{ name: 'a.txt', size: 3, mediaType: 'text/plain' }],
      recipients: ['carol@customer.example.net'],
      message: 'Hello',
      password: 'secret',
      language: 'fr',
    });
    expect(flow.form.password).toBe('');
    expect(store.value).toEqual({
      transferId: 'trf_1',
      files: [{ name: 'a.txt', size: 3, lastModified: 1, path: '' }],
    });
    expect(flow.step).toBe('upload');
    const engine = engines[0] as FakeEngine;
    expect(engine.specs).toHaveLength(1);
    expect(engine.specs[0]?.uploadUrl).toBe('/api/v1/uploads/upl_1');
    expect(flow.upload?.phase).toBe('uploading');
    expect(flow.isUploading()).toBe(true);

    engine.say({ kind: 'progress', percent: 10 });
    engine.say({ kind: 'error', code: 'forbidden' });
    expect(announce).toHaveBeenCalledWith('upload.announce.progress {"percent":10}', 'polite');
    expect(announce).toHaveBeenCalledWith('upload.announce.error', 'assertive');

    flow.pause();
    flow.resume();
    expect(engine.pause).toHaveBeenCalled();
    expect(engine.resume).toHaveBeenCalled();

    engine.finish('completed');
    await flush();
    expect(finalize).toHaveBeenCalledWith(
      'trf_1',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(flow.step).toBe('done');
    expect(flow.outcome).toBe('available');
    expect(store.value).toBeUndefined();
    expect(announce).toHaveBeenCalledWith('upload.finalize.available');

    flow.newTransfer();
    expect(flow.step).toBe('form');
    expect(flow.form.files).toEqual([]);
    expect(flow.transfer).toBeUndefined();
  });

  it('omits recipients and empty options for an external depositor', async () => {
    const { flow, calls } = setup({
      'GET /deposit-sessions/current': { status: 200, body: externalSession },
      'POST /transfers': { status: 201, body: transfer('uploading') },
    });
    await flow.start();
    flow.addFiles([new File(['x'], 'raw.bin', { lastModified: 2 })]);
    flow.form.message = '   ';
    await flow.submitTransfer();
    expect(calls[1]?.body).toEqual({
      expiryDays: 7,
      deleteAfterFirstDownload: false,
      files: [{ name: 'raw.bin', size: 1 }],
      language: 'fr',
    });
  });

  it('maps server validation errors and renews the idempotency key', async () => {
    const { flow, calls, routes } = await readyForm({
      'POST /transfers': problem(400, 'validation-failed', {
        errors: [{ field: '/recipients/0', code: 'invalid-email' }],
      }),
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ 'recipients.0': { key: 'fieldErrors.invalid-email' } });
    expect(flow.formRefusals).toBe(1);

    routes['POST /transfers'] = new TypeError('offline');
    await flow.submitTransfer();
    expect(flow.errorText).toBe('errors.network');
    routes['POST /transfers'] = problem(502, 'internal-error');
    await flow.submitTransfer();
    const keys = calls.filter((c) => c.method === 'POST').map((c) => c.headers.get('Idempotency-Key'));
    // New key after the definitive refusal, then the same key on transient failures.
    expect(keys).toEqual(['key-1', 'key-2', 'key-2']);
  });

  it('renews the idempotency key when the form changed after a transient failure', async () => {
    const { flow, calls, routes, engines } = await readyForm({ 'POST /transfers': new TypeError('offline') });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    await flow.submitTransfer();
    flow.form.message = 'Edited';
    await flow.submitTransfer();
    routes['POST /transfers'] = { status: 201, body: transfer('uploading') };
    await flow.submitTransfer();
    const keys = calls.filter((c) => c.method === 'POST').map((c) => c.headers.get('Idempotency-Key'));
    expect(keys).toEqual(['key-1', 'key-1', 'key-2', 'key-2']);
    expect(flow.step).toBe('upload');
    // The fresh createTransfer answer gives exact offsets.
    expect(engines[0]?.specs[0]?.offset).toBe(0);
  });

  it('handles size, refusal, quota and session errors', async () => {
    const { flow, routes, clearCsrf } = await readyForm({
      'POST /transfers': problem(413, 'transfer-too-large', { maxTransferBytes: 1000 }),
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ files: { key: 'deposit.form.files.tooLarge' } });

    routes['POST /transfers'] = problem(403, 'deposit-not-allowed');
    await flow.submitTransfer();
    expect(flow.errorText).toBe('deposit.email.notAllowed');

    routes['POST /transfers'] = problem(507, 'quota-exceeded');
    await flow.submitTransfer();
    expect(flow.errorText).toBe('errors.quota-exceeded');

    routes['POST /transfers'] = problem(429, 'rate-limited', { retryAfterSeconds: 5 });
    await flow.submitTransfer();
    expect(flow.secondsBeforeRetry()).toBe(5);

    routes['POST /transfers'] = problem(401, 'unauthenticated');
    await flow.submitTransfer();
    expect(flow.step).toBe('email');
    expect(flow.session).toBeUndefined();
    expect(flow.notice).toEqual({ key: 'deposit.session.expired' });
    expect(clearCsrf).toHaveBeenCalled();
  });

  it('cancels the upload after confirmation and returns to the form', async () => {
    const { flow, engines, calls, store } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': { status: 204 },
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    await flow.cancelUpload();
    expect(engines[0]?.cancel).toHaveBeenCalled();
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: '/transfers/trf_1' });
    expect(store.value).toBeUndefined();
    expect(flow.step).toBe('form');
    expect(flow.notice).toEqual({ key: 'deposit.upload.cancelled' });
    expect(flow.form.files).toHaveLength(1);
    await flush();
    expect(flow.step).toBe('form');
  });

  it('retries the cancellation while the server still holds the upload lock', async () => {
    const { flow, calls, sleeps, store } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': [
        problem(409, 'state-conflict'),
        problem(409, 'state-conflict'),
        problem(409, 'state-conflict'),
        { status: 204 },
      ],
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    const cancelling = flow.cancelUpload();
    expect(flow.notice).toEqual({ key: 'deposit.upload.cancelling' });
    await flow.cancelUpload(); // ignored while busy
    await cancelling;
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(4);
    expect(sleeps).toEqual([1000, 2000, 4000]);
    expect(flow.step).toBe('form');
    expect(flow.notice).toEqual({ key: 'deposit.upload.cancelled' });
    expect(flow.stepError).toBeUndefined();
    expect(store.value).toBeUndefined();
  });

  it('reports a cancellation that still fails after 90 s', async () => {
    const { flow, calls, sleeps } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': problem(409, 'state-conflict'),
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    await flow.cancelUpload();
    expect(sleeps).toEqual([1000, 2000, 4000, 8000, 10000, 10000, 10000, 10000, 10000, 10000, 10000, 10000]);
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(13);
    expect(flow.step).toBe('form');
    expect(flow.notice).toBeUndefined();
    expect(flow.errorText).toBe('deposit.upload.cancelFailed');
  });

  it('does not retry a cancellation refused for another reason, and accepts a transfer already gone', async () => {
    const refused = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': problem(500, 'internal-error'),
    });
    refused.flow.form.recipientsText = 'carol@customer.example.net';
    refused.flow.addFiles([file()]);
    await refused.flow.submitTransfer();
    await refused.flow.cancelUpload();
    expect(refused.sleeps).toEqual([]);
    expect(refused.flow.errorText).toBe('deposit.upload.cancelFailed');

    const gone = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': problem(404, 'not-found'),
    });
    gone.flow.form.recipientsText = 'carol@customer.example.net';
    gone.flow.addFiles([file()]);
    await gone.flow.submitTransfer();
    await gone.flow.cancelUpload();
    expect(gone.flow.notice).toEqual({ key: 'deposit.upload.cancelled' });
  });

  it('stops the cancellation retries when the page is left', async () => {
    const { flow, calls, engines } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': problem(409, 'state-conflict'),
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    const cancelling = flow.cancelUpload();
    flow.dispose();
    await cancelling;
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(1);
    expect(engines[0]?.stop).toHaveBeenCalled();
    expect(flow.step).toBe('upload');
  });

  it('asks before leaving during an upload and stops the engine without abandoning the transfer', async () => {
    const answers = [false, true];
    const { flow, engines, confirm, calls } = await readyForm(
      { 'POST /transfers': { status: 201, body: transfer('uploading') } },
      { confirm: () => answers.shift() ?? true },
    );
    expect(flow.confirmLeave()).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    expect(flow.confirmLeave()).toBe(false);
    expect(confirm).toHaveBeenCalledWith('deposit.upload.leaveConfirm');
    expect(flow.confirmLeave()).toBe(true);
    flow.dispose();
    expect(engines[0]?.stop).toHaveBeenCalled();
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
  });

  it('stops the engine when a new transfer is started or the session expires', async () => {
    const { flow, engines, routes } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    flow.newTransfer();
    expect(engines[0]?.stop).toHaveBeenCalled();
    expect(flow.isUploading()).toBe(false);

    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    routes['POST /transfers'] = { status: 201, body: transfer('uploading') };
    await flow.submitTransfer();
    engines[1]?.fail(new UploadError('unauthenticated', 401));
    await flush();
    expect(engines[1]?.stop).toHaveBeenCalled();
  });

  it('parses the recipients and reports other code errors', async () => {
    const { flow } = setup({
      'GET /deposit-sessions/current': problem(401, 'unauthenticated'),
      'POST /deposit-sessions': { status: 202, body: challenge },
      'POST /verification-challenges/vch_1/confirm': problem(500, 'internal-error'),
    });
    flow.form.recipientsText = 'a@entity-a.example.com, b@entity-a.example.com';
    expect(flow.recipients).toEqual(['a@entity-a.example.com', 'b@entity-a.example.com']);
    await flow.start();
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    flow.code = '123456';
    await flow.submitCode();
    expect(flow.step).toBe('code');
    expect(flow.errorText).toBe('errors.internal-error');
  });

  it('accepts a pasted code with spaces', async () => {
    const { flow, calls } = setup({
      'GET /deposit-sessions/current': problem(401, 'unauthenticated'),
      'POST /deposit-sessions': { status: 202, body: challenge },
      'POST /verification-challenges/vch_1/confirm': { status: 201, body: internalSession },
    });
    await flow.start();
    flow.email = 'alice@entity-a.example.com';
    await flow.submitEmail();
    flow.code = ' 123 456 ';
    await flow.submitCode();
    expect(calls.at(-1)?.body).toEqual({ code: '123456' });
    expect(flow.step).toBe('form');
  });

  it('returns to identification when the upload loses the session', async () => {
    const { flow, engines, store } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    engines[0]?.fail(new UploadError('unauthenticated', 401));
    await flush();
    expect(flow.step).toBe('email');
    expect(flow.notice).toEqual({ key: 'deposit.session.expired' });
    // The resume record is kept: after the new identification the upload can resume.
    expect(store.value?.transferId).toBe('trf_1');
  });

  it('stays on the upload step after another fatal error and abandons the transfer', async () => {
    const { flow, engines, calls } = await readyForm({
      'POST /transfers': { status: 201, body: transfer('uploading') },
      'DELETE /transfers/trf_1': { status: 204 },
    });
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([file()]);
    await flow.submitTransfer();
    engines[0]?.fail(new UploadError('upload-gone', 410));
    await flush();
    expect(flow.step).toBe('upload');
    await flow.abandonTransfer();
    expect(flow.step).toBe('form');
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: '/transfers/trf_1' });
  });
});

// ---- Finalization ------------------------------------------------------------------------------------

describe('finalization', () => {
  async function uploaded(outcomes: FinalizeOutcome[], routes: Record<string, Reply | Reply[] | Error> = {}) {
    const queue = [...outcomes];
    const ctx = await readyForm(
      { 'POST /transfers': { status: 201, body: transfer('uploading') }, ...routes },
      {
        finalize: async (_id: string, options: { onUpdate?: (t: SenderTransfer) => void }) => {
          options.onUpdate?.(transfer('scanning'));
          return queue.shift() ?? { kind: 'stopped' };
        },
      },
    );
    ctx.flow.form.recipientsText = 'carol@customer.example.net';
    ctx.flow.addFiles([file()]);
    await ctx.flow.submitTransfer();
    ctx.engines[0]?.finish('completed');
    await flush();
    return ctx;
  }

  it('resumes the upload when files are incomplete', async () => {
    const { flow, engines } = await uploaded([{ kind: 'upload-incomplete', files: ['fil_1'] }], {
      'GET /transfers/trf_1': { status: 200, body: transfer('uploading') },
    });
    expect(flow.notice).toEqual({ key: 'upload.finalize.incomplete' });
    expect(engines).toHaveLength(2);
    expect(engines[1]?.specs[0]?.file).toBeInstanceOf(File);
    expect(flow.step).toBe('upload');
  });

  it('reports a failure to reload the incomplete transfer', async () => {
    const { flow } = await uploaded([{ kind: 'upload-incomplete', files: ['fil_1'] }], {
      'GET /transfers/trf_1': new TypeError('offline'),
    });
    expect(flow.finalizeError).toEqual({ key: 'upload.finalize.error.network' });
    expect(flow.finalizeRetryable).toBe(true);
  });

  it('handles a lost session or a refusal while reloading the incomplete transfer', async () => {
    const lost = await uploaded([{ kind: 'upload-incomplete', files: ['fil_1'] }], {
      'GET /transfers/trf_1': problem(401, 'unauthenticated'),
    });
    expect(lost.flow.step).toBe('email');

    const refused = await uploaded([{ kind: 'upload-incomplete', files: ['fil_1'] }], {
      'GET /transfers/trf_1': problem(404, 'not-found'),
    });
    expect(refused.flow.finalizeError).toEqual({ key: 'upload.finalize.error.other' });
    expect(refused.flow.finalizeRetryable).toBe(false);
  });

  it('lists blocked files and abandons the transfer', async () => {
    const { flow, calls, store } = await uploaded([{ kind: 'blocked', files: ['a.txt'] }], {
      'DELETE /transfers/trf_1': { status: 409, body: undefined },
    });
    expect(flow.step).toBe('finalizing');
    expect(flow.blockedFiles).toEqual(['a.txt']);
    expect(store.value).toBeUndefined();
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: '/transfers/trf_1' });
  });

  it('offers to retry a transient failure, not a definitive one', async () => {
    const { flow, store } = await uploaded([
      { kind: 'failed', code: 'network' },
      { kind: 'failed', code: 'checksum-mismatch', status: 409 },
    ]);
    expect(flow.finalizeError).toEqual({ key: 'upload.finalize.error.network' });
    expect(flow.finalizeRetryable).toBe(true);
    expect(store.value).toBeDefined();
    await flow.retryFinalize();
    expect(flow.finalizeError).toEqual({ key: 'upload.finalize.error.checksum-mismatch' });
    expect(flow.finalizeRetryable).toBe(false);
    expect(store.value).toBeUndefined();
  });

  it('handles maintenance, lost session and rejection', async () => {
    const maintenance = await uploaded([{ kind: 'failed', code: 'maintenance', status: 503 }]);
    expect(maintenance.flow.finalizeError).toEqual({ key: 'errors.maintenance' });
    expect(maintenance.flow.finalizeRetryable).toBe(true);

    const lost = await uploaded([{ kind: 'failed', code: 'unauthenticated', status: 401 }]);
    expect(lost.flow.step).toBe('email');

    const rejected = await uploaded([{ kind: 'rejected', transfer: transfer('rejected') }]);
    expect(rejected.flow.step).toBe('done');
    expect(rejected.flow.outcome).toBe('rejected');
  });

  it('ignores a stopped finalization and stops polling on dispose', async () => {
    const { flow } = await uploaded([{ kind: 'stopped' }]);
    expect(flow.step).toBe('finalizing');
    expect(flow.transfer?.status).toBe('scanning');
    flow.dispose();
  });
});

// ---- Resume and session end ----------------------------------------------------------------------------

describe('resume after reload', () => {
  const record: ResumeRecord = {
    transferId: 'trf_1',
    files: [
      { name: 'done.txt', size: 2, lastModified: 1 },
      { name: 'a.txt', size: 3, lastModified: 1 },
    ],
  };
  const interrupted = transfer('uploading', {
    files: [
      {
        id: 'fil_0',
        name: 'done.txt',
        size: 2,
        scanStatus: 'pending',
        uploadUrl: '/api/v1/uploads/u0',
        uploadOffset: 2,
      },
      {
        id: 'fil_1',
        name: 'a.txt',
        size: 3,
        scanStatus: 'pending',
        uploadUrl: '/api/v1/uploads/u1',
        uploadOffset: 1,
      },
    ],
  });

  it('asks for the files again and continues the upload', async () => {
    const { flow, engines } = await readyForm(
      { 'GET /transfers/trf_1': { status: 200, body: interrupted } },
      { store: memoryStore(record) },
    );
    expect(flow.step).toBe('resume');
    expect(flow.resumeMissing.map((f) => f.name)).toEqual(['a.txt']);
    flow.continueResume();
    expect(engines).toHaveLength(0);
    flow.addResumeFiles([file('other.txt')]);
    flow.addResumeFiles([file('a.txt')]);
    expect(flow.resumeMissing).toEqual([]);
    flow.continueResume();
    expect(flow.step).toBe('upload');
    // The offsets of GET /transfers may be stale: the engine asks the server (HEAD).
    expect(engines[0]?.specs.map((s) => [s.name, s.offset, s.file !== undefined])).toEqual([
      ['done.txt', undefined, false],
      ['a.txt', undefined, true],
    ]);
  });

  it('abandons the interrupted transfer on request', async () => {
    const { flow, store, calls } = await readyForm(
      {
        'GET /transfers/trf_1': { status: 200, body: interrupted },
        'DELETE /transfers/trf_1': { status: 204 },
      },
      { store: memoryStore(record) },
    );
    await flow.discardResume();
    expect(flow.step).toBe('form');
    expect(store.value).toBeUndefined();
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: '/transfers/trf_1' });
  });

  it('forgets a record whose transfer is no longer uploading or is unknown', async () => {
    const finished = await readyForm(
      { 'GET /transfers/trf_1': { status: 200, body: transfer('expired') } },
      { store: memoryStore(record) },
    );
    expect(finished.flow.step).toBe('form');
    expect(finished.store.value).toBeUndefined();

    const unknown = await readyForm(
      { 'GET /transfers/trf_1': problem(404, 'not-found') },
      { store: memoryStore(record) },
    );
    expect(unknown.store.value).toBeUndefined();

    const offline = await readyForm(
      { 'GET /transfers/trf_1': new TypeError('offline') },
      { store: memoryStore(record) },
    );
    expect(offline.flow.step).toBe('form');
    expect(offline.store.value).toBeDefined();
  });

  it('waits for the analysis of a transfer reloaded while scanning, without finalizing it', async () => {
    const { flow, poll, finalize, store } = await readyForm(
      { 'GET /transfers/trf_1': { status: 200, body: transfer('scanning') } },
      { store: memoryStore(record) },
    );
    await flush();
    expect(poll).toHaveBeenCalledWith('trf_1', expect.objectContaining({ signal: expect.any(AbortSignal) }));
    expect(finalize).not.toHaveBeenCalled();
    expect(flow.step).toBe('done');
    expect(flow.outcome).toBe('available');
    expect(store.value).toBeUndefined();
  });

  it('shows the recap of a transfer already decided', async () => {
    const { flow, store, poll } = await readyForm(
      { 'GET /transfers/trf_1': { status: 200, body: transfer('rejected') } },
      { store: memoryStore(record) },
    );
    expect(flow.step).toBe('done');
    expect(flow.outcome).toBe('rejected');
    expect(flow.transfer?.status).toBe('rejected');
    expect(store.value).toBeUndefined();
    expect(poll).not.toHaveBeenCalled();
  });

  it('reports a failed cancellation of the interrupted transfer', async () => {
    const { flow, sleeps } = await readyForm(
      {
        'GET /transfers/trf_1': { status: 200, body: interrupted },
        'DELETE /transfers/trf_1': [problem(409, 'state-conflict'), problem(401, 'unauthenticated')],
      },
      { store: memoryStore(record) },
    );
    await flow.discardResume();
    expect(sleeps).toEqual([1000]);
    expect(flow.errorText).toBe('deposit.upload.cancelFailed');
  });

  it('has nothing missing without a record', async () => {
    const { flow } = await readyForm();
    expect(flow.resumeMissing).toEqual([]);
  });
});

describe('end of session', () => {
  it('ends the session even when the server already forgot it', async () => {
    const { flow, calls, clearCsrf } = await readyForm({
      'DELETE /deposit-sessions/current': problem(401, 'unauthenticated'),
    });
    await flow.endSession();
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: '/deposit-sessions/current' });
    expect(clearCsrf).toHaveBeenCalled();
    expect(flow.session).toBeUndefined();
    expect(flow.step).toBe('email');
    expect(flow.notice).toEqual({ key: 'deposit.session.ended' });
    flow.newTransfer();
    expect(flow.step).toBe('email');
  });
});
