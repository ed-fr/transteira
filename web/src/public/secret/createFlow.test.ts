// State machine of the secret creation (createFlow.svelte.ts) against a fake API: link and e-mail
// deliveries, file upload, retries with the same bytes, error mapping and the deposit session.
import { describe, expect, it, vi } from 'vitest';
import { createApiClient, NetworkError } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import { deriveSecretKey, openSecret } from '../../shared/e2e/secret';
import { parseKey } from '../../shared/e2e/tte2';
import type { SecretFeatures } from './create';
import { SecretCreateFlow, type SecretFlowDeps, type SecretHost } from './createFlow.svelte';

type PublicTenant = components['schemas']['PublicTenant'];

// ---- Fakes ----------------------------------------------------------------------------------

interface Reply {
  status: number;
  body?: unknown;
}

interface Call {
  method: string;
  path: string;
  body: unknown;
  bytes: Uint8Array | undefined;
  headers: Headers;
}

function problem(status: number, code: string, extra: Record<string, unknown> = {}): Reply {
  return { status, body: { type: 'about:blank', title: code, status, code, ...extra } };
}

/** Fake fetch answering "METHOD /path" routes (a list is consumed in order, the last one sticks). */
function fakeApi(routes: Record<string, Reply | (Reply | Error)[] | Error>) {
  const calls: Call[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'https://transfer.entity-a.example.com');
    const method = init?.method ?? 'GET';
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const raw = init?.body;
    const body = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : undefined;
    const bytes = raw instanceof Blob ? new Uint8Array(await raw.arrayBuffer()) : undefined;
    calls.push({ method, path, body, bytes, headers: new Headers(init?.headers) });
    const route = routes[`${method} ${path}`];
    if (route === undefined) throw new Error(`unexpected request ${method} ${path}`);
    const reply = Array.isArray(route) ? (route.length > 1 ? route.shift() : route[0]) : route;
    if (reply instanceof Error) throw reply;
    const r = reply as Reply;
    const type = r.status >= 400 ? 'application/problem+json' : 'application/json';
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), {
      status: r.status,
      headers: { 'Content-Type': type },
    });
  };
  const api = createApiClient({
    fetch: fetch as typeof globalThis.fetch,
    language: () => 'en',
    csrfToken: () => 'csrf-1',
  });
  return { api, calls };
}

const features: SecretFeatures = {
  enabled: true,
  durations: ['1h', '1d', '7d'],
  defaultDuration: '1d',
  fileAllowed: true,
  fileMaxBytes: 1024 * 1024,
  emailAllowed: true,
};

function tenantWith(secrets: SecretFeatures | undefined): PublicTenant {
  return { name: 'Entity A', features: secrets === undefined ? {} : { secrets } } as unknown as PublicTenant;
}

interface Setup {
  secrets?: SecretFeatures | undefined;
  external?: boolean;
  dropLink?: boolean;
  reply?: boolean;
  sessionError?: (err: unknown) => boolean;
  now?: () => number;
  seal?: SecretFlowDeps['seal'];
}

const TOKEN = 'tts_UEb8n51xYj4xMXBFL52EtiILriXUayRi9TbqLuPp29L'; // gitleaks:allow (fake secret token from the API example)
const ID = 'sec_01JABCS1T2V3W4X5Y6Z7A8B9C0';
const EXPIRES = '2026-11-10T09:00:00Z';

function setup(routes: Record<string, Reply | (Reply | Error)[] | Error>, s: Setup = {}) {
  const { api, calls } = fakeApi(routes);
  const sessionError = vi.fn(s.sessionError ?? (() => false));
  const endListeners: (() => void)[] = [];
  const host: SecretHost = {
    tenant: tenantWith('secrets' in s ? s.secrets : features),
    isExternal: s.external === true,
    invitedBy: s.external === true ? 'bob@entity-a.example.com' : undefined,
    isDropLink: s.dropLink === true,
    isReply: s.reply === true,
    sessionError,
    onSessionEnd: (listener) => {
      endListeners.push(listener);
      return () => undefined;
    },
  };
  /** The depositor presses "End session". */
  const endSession = () => endListeners.forEach((l) => l());
  const announce = vi.fn();
  const tr = {
    t: (key: string, params?: Record<string, string | number>) =>
      params === undefined ? key : `${key} ${JSON.stringify(params)}`,
    has: (key: string) => key.startsWith('fieldErrors.') || key.startsWith('errors.'),
  };
  const deps: SecretFlowDeps = {
    api,
    tr,
    announce,
    origin: () => 'https://transfer.entity-a.example.com',
    ...(s.now === undefined ? {} : { now: s.now }),
    ...(s.seal === undefined ? {} : { seal: s.seal }),
  };
  const flow = new SecretCreateFlow(host, deps);
  return { flow, calls, sessionError, announce, host, endSession };
}

const created = (state: 'active' | 'pending' = 'active'): Reply => ({
  status: 201,
  body:
    state === 'active'
      ? { id: ID, token: TOKEN, state, expiresAt: EXPIRES }
      : { id: ID, token: TOKEN, state },
});

const secretAnswer = (delivery: 'link' | 'email', expiresAt = EXPIRES): Reply => ({
  status: 200,
  body: {
    id: ID,
    state: 'active',
    delivery,
    readReceipt: false,
    hasFile: true,
    createdAt: EXPIRES,
    expiresAt,
  },
});

function file(content: string, name = 'note.txt'): File {
  return new File([content], name, { type: 'text/plain' });
}

/** Key of the fragment of a link. */
function keyOf(link: string): Uint8Array {
  return parseKey(link.split('#k=')[1] as string);
}

// ---- Tests ----------------------------------------------------------------------------------

describe('derived values', () => {
  it('offers the tab to deposit sessions only, and to externals only with e-mail', () => {
    expect(setup({}).flow.offered).toBe(true);
    expect(setup({}, { dropLink: true }).flow.offered).toBe(false);
    expect(setup({}, { reply: true }).flow.offered).toBe(false);
    expect(setup({}, { external: true }).flow.offered).toBe(true);
    expect(setup({}, { external: true, secrets: { ...features, emailAllowed: false } }).flow.offered).toBe(
      false,
    );
    const none = setup({}, { secrets: undefined }).flow;
    expect(none.offered).toBe(false);
    expect(none.features.enabled).toBe(false);
  });

  it('describes the delivery for an internal creator', () => {
    const { flow } = setup({});
    expect(flow.emailOnly).toBe(false);
    expect(flow.deliveryChoice).toBe(true);
    expect(flow.delivery).toBe('link');
    expect(flow.imposedRecipient).toBeUndefined();
    flow.form.delivery = 'email';
    expect(flow.delivery).toBe('email');
    expect(flow.passphraseRequired).toBe(false);
  });

  it('forces the e-mail to the inviter for an external creator', () => {
    const { flow } = setup({}, { external: true, secrets: { ...features, emailRequiresPassphrase: true } });
    expect(flow.emailOnly).toBe(true);
    expect(flow.deliveryChoice).toBe(false);
    expect(flow.delivery).toBe('email');
    expect(flow.imposedRecipient).toBe('bob@entity-a.example.com');
    expect(flow.passphraseRequired).toBe(true);
  });

  it('uses the link when e-mail is not allowed', () => {
    const { flow } = setup({}, { secrets: { ...features, emailAllowed: false } });
    flow.form.delivery = 'email';
    expect(flow.deliveryChoice).toBe(false);
    expect(flow.delivery).toBe('link');
  });

  it('counts the text and gives the largest file', () => {
    const { flow } = setup({});
    flow.form.text = 'a😀';
    expect(flow.textLength).toBe(2);
    expect(flow.maxFileBytes).toBeGreaterThan(1024 * 1024 - 100);
    expect(flow.maxFileBytes).toBeLessThan(1024 * 1024);
    expect(flow.busy).toBe(false);
    expect(flow.errorText).toBeUndefined();
    flow.stepError = { message: { key: 'secretCreate.error.sealFailed' } };
    expect(flow.errorText).toBe('secretCreate.error.sealFailed');
    flow.stepError = { cause: new NetworkError(new Error('x')) };
    expect(flow.errorText).toBe('errors.network');
  });
});

describe('form actions', () => {
  it('keeps one file and clears its errors', () => {
    const { flow } = setup({});
    flow.errors = { file: { key: 'a' }, text: { key: 'b' }, recipient: { key: 'c' } };
    flow.setFile([]);
    expect(flow.form.file).toBeUndefined();
    const a = file('a');
    flow.setFile([a, file('b')]);
    expect(flow.form.file).toBe(a);
    expect(flow.errors).toEqual({ recipient: { key: 'c' } });
    flow.errors = { file: { key: 'a' } };
    flow.removeFile();
    expect(flow.form.file).toBeUndefined();
    expect(flow.errors).toEqual({});
    flow.removeFile();
    expect(flow.errors).toEqual({});
  });

  it('ignores file changes while working', () => {
    const { flow } = setup({});
    const a = file('a');
    flow.setFile([a]);
    flow.step = 'working';
    flow.setFile([file('b')]);
    flow.removeFile();
    expect(flow.form.file).toBe(a);
  });
});

describe('submit', () => {
  it('refuses an invalid form without any request', async () => {
    const { flow, calls } = setup({});
    await flow.submit();
    expect(calls).toEqual([]);
    expect(flow.errors.text?.key).toBe('secretCreate.text.required');
    expect(flow.invalidFields).toEqual(['text']);
    expect(flow.refusals).toBe(1);
    expect(flow.step).toBe('form');
  });

  it('creates a link secret and shows its link once', async () => {
    const { flow, calls, announce } = setup({ 'POST /secrets': created() });
    flow.form.text = 'hunter2';
    flow.form.readReceipt = true;
    await flow.submit();
    expect(calls).toHaveLength(1);
    const body = calls[0]?.body as components['schemas']['SecretCreate'];
    expect(body.delivery).toBe('link');
    expect(body.readReceipt).toBe(true);
    expect(body.recipient).toBeUndefined();
    expect(calls[0]?.headers.get('X-CSRF-Token')).toBe('csrf-1');
    expect(flow.step).toBe('done');
    expect(flow.phase).toBeUndefined();
    expect(flow.link).toMatch(
      new RegExp(`^https://transfer\\.entity-a\\.example\\.com/s/${TOKEN}#k=[A-Za-z0-9_-]{43}$`),
    );
    expect(flow.sentTo).toBeUndefined();
    expect(flow.expiresAt).toBe(EXPIRES);
    expect(flow.doneWithFile).toBe(false);
    // The key of the link opens the sealed text; the key itself never reached the server.
    const key = keyOf(flow.link as string);
    expect(await openSecret(await deriveSecretKey(key, '', null), body.encryptedText)).toBe('hunter2');
    expect(JSON.stringify(calls[0]?.body)).not.toContain((flow.link as string).split('#k=')[1]);
    // The plaintext left the state.
    expect(flow.form.text).toBe('');
    expect(flow.form.readReceipt).toBe(false);
    expect(announce).toHaveBeenCalledWith('secretCreate.done.announce');
    // Only once: a second submission is ignored on the done step.
    await flow.submit();
    expect(calls).toHaveLength(1);
  });

  it('uploads the file of a link secret as raw bytes', async () => {
    const later = '2026-11-10T10:00:00Z';
    const { flow, calls } = setup({
      'POST /secrets': created('pending'),
      [`PUT /secrets/${ID}/file`]: secretAnswer('link', later),
    });
    flow.setFile([file('attached')]);
    await flow.submit();
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['POST /secrets', `PUT /secrets/${ID}/file`]);
    const declared = (calls[0]?.body as components['schemas']['SecretCreate']).file;
    expect(calls[1]?.headers.get('Content-Type')).toBe('application/octet-stream');
    expect(calls[1]?.headers.get('X-CSRF-Token')).toBe('csrf-1');
    expect(calls[1]?.bytes).toHaveLength(declared?.size as number);
    expect(flow.step).toBe('done');
    expect(flow.expiresAt).toBe(later);
    expect(flow.doneWithFile).toBe(true);
    expect(flow.form.file).toBeUndefined();
  });

  it('keeps the creation expiry when the upload answer has none', async () => {
    const { flow } = setup({
      'POST /secrets': created('active'),
      [`PUT /secrets/${ID}/file`]: { status: 200, body: { id: ID, state: 'active' } },
    });
    flow.setFile([file('x')]);
    await flow.submit();
    expect(flow.expiresAt).toBe(EXPIRES);
  });

  it('mails an e-mail secret with both halves of the link', async () => {
    const { flow, calls } = setup({
      'POST /secrets': created('pending'),
      [`PUT /secrets/${ID}/file`]: secretAnswer('email', undefined as unknown as string),
      [`POST /secrets/${ID}/send`]: secretAnswer('email'),
    });
    flow.form.text = 'hunter2';
    flow.form.delivery = 'email';
    flow.form.recipient = ' carol@example.net ';
    flow.setFile([file('x')]);
    await flow.submit();
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /secrets',
      `PUT /secrets/${ID}/file`,
      `POST /secrets/${ID}/send`,
    ]);
    const body = calls[0]?.body as components['schemas']['SecretCreate'];
    expect(body.recipient).toBe('carol@example.net');
    const send = calls[2]?.body as components['schemas']['SecretSend'];
    expect(send.secretToken).toBe(TOKEN);
    const key = parseKey(send.fragmentKey);
    expect(await openSecret(await deriveSecretKey(key, '', null), body.encryptedText)).toBe('hunter2');
    expect(flow.step).toBe('done');
    expect(flow.link).toBeUndefined();
    expect(flow.sentTo).toBe('carol@example.net');
    expect(flow.expiresAt).toBe(EXPIRES);
  });

  it('keeps the previous expiry when the send answer has none', async () => {
    const { flow } = setup({
      'POST /secrets': created('pending'),
      [`POST /secrets/${ID}/send`]: { status: 200, body: { id: ID, state: 'active' } },
    });
    flow.form.text = 'x';
    flow.form.delivery = 'email';
    flow.form.recipient = 'carol@example.net';
    await flow.submit();
    expect(flow.step).toBe('done');
    expect(flow.expiresAt).toBeUndefined();
  });

  it('mails the secret of an external to the inviter', async () => {
    const { flow, calls } = setup(
      { 'POST /secrets': created('pending'), [`POST /secrets/${ID}/send`]: secretAnswer('email') },
      { external: true },
    );
    flow.form.text = 'x';
    flow.form.recipient = 'someone@else.example';
    await flow.submit();
    expect((calls[0]?.body as components['schemas']['SecretCreate']).recipient).toBe(
      'bob@entity-a.example.com',
    );
    expect(flow.sentTo).toBe('bob@entity-a.example.com');
  });

  it('shows a sealing failure on the form', async () => {
    const { flow, calls } = setup(
      {},
      {
        seal: {
          crypto: () => ({
            hash: () => Promise.reject(new Error('unreadable')),
            prepare: () => Promise.reject(new Error('unused')),
            range: () => Promise.reject(new Error('unused')),
            dispose: () => undefined,
          }),
        },
      },
    );
    flow.setFile([file('x')]);
    await flow.submit();
    expect(calls).toEqual([]);
    expect(flow.step).toBe('form');
    expect(flow.errorText).toBe('secretCreate.error.sealFailed');
    expect(flow.refusals).toBe(1);
  });
});

describe('retries after the creation', () => {
  async function failedUpload(first: Reply | Error, then: Reply | Error) {
    const s = setup({
      'POST /secrets': created('pending'),
      [`PUT /secrets/${ID}/file`]: [first, then],
    });
    s.flow.setFile([file('attached')]);
    await s.flow.submit();
    return s;
  }

  it('retries a failed upload with the same bytes', async () => {
    const { flow, calls } = await failedUpload(new TypeError('offline'), secretAnswer('link'));
    expect(flow.step).toBe('retry');
    expect(flow.errorText).toBe('errors.network');
    expect(flow.refusals).toBe(1);
    await flow.retry();
    expect(calls.map((c) => c.method)).toEqual(['POST', 'PUT', 'PUT']);
    expect(calls[2]?.bytes).toEqual(calls[1]?.bytes);
    expect(flow.step).toBe('done');
    expect(flow.link).toContain(TOKEN);
  });

  it('takes a conflict on a retried upload as stored', async () => {
    const { flow } = await failedUpload(problem(500, 'internal'), problem(409, 'state-conflict'));
    await flow.retry();
    expect(flow.step).toBe('done');
  });

  it('reports a conflict on the first upload', async () => {
    const { flow } = await failedUpload(problem(409, 'state-conflict'), secretAnswer('link'));
    expect(flow.step).toBe('retry');
    expect(flow.errorText).toBe('errors.state-conflict');
  });

  it('starts over when the incomplete secret is gone', async () => {
    const { flow } = await failedUpload(problem(404, 'not-found'), secretAnswer('link'));
    expect(flow.step).toBe('form');
    expect(flow.errorText).toBe('secretCreate.error.pendingGone');
    // The form is kept for a new attempt (which draws a new key).
    expect(flow.form.file).toBeDefined();
    await flow.retry();
    expect(flow.step).toBe('form');
  });

  it('retries a failed mail, and takes a conflict on a retried send as sent', async () => {
    const { flow, calls } = setup({
      'POST /secrets': created('pending'),
      [`POST /secrets/${ID}/send`]: [problem(503, 'mail-unavailable'), problem(409, 'state-conflict')],
    });
    flow.form.text = 'x';
    flow.form.delivery = 'email';
    flow.form.recipient = 'carol@example.net';
    await flow.submit();
    expect(flow.step).toBe('retry');
    expect(flow.errorText).toBe('errors.mail-unavailable');
    await flow.retry();
    expect(calls.map((c) => c.path)).toEqual(['/secrets', `/secrets/${ID}/send`, `/secrets/${ID}/send`]);
    expect(calls[2]?.body).toEqual(calls[1]?.body);
    expect(flow.step).toBe('done');
    expect(flow.sentTo).toBe('carol@example.net');
  });

  it('waits for the rate limit before a retry', async () => {
    let now = 1_000;
    const { flow, calls } = setup(
      {
        'POST /secrets': created('pending'),
        [`PUT /secrets/${ID}/file`]: [
          problem(429, 'rate-limited', { retryAfterSeconds: 5 }),
          secretAnswer('link'),
        ],
      },
      { now: () => now },
    );
    flow.setFile([file('x')]);
    await flow.submit();
    expect(flow.step).toBe('retry');
    expect(flow.secondsBeforeRetry()).toBe(5);
    await flow.retry();
    expect(calls).toHaveLength(2);
    now += 5_000;
    expect(flow.secondsBeforeRetry()).toBe(0);
    await flow.retry();
    expect(flow.step).toBe('done');
    expect(flow.retryAt).toBeUndefined();
  });

  it('hands an expired session to the deposit flow and keeps the incomplete secret', async () => {
    const { flow, sessionError } = setup(
      {
        'POST /secrets': created('pending'),
        [`PUT /secrets/${ID}/file`]: [problem(401, 'unauthenticated'), secretAnswer('link')],
      },
      { sessionError: (err) => (err as { code?: string }).code === 'unauthenticated' },
    );
    flow.setFile([file('x')]);
    await flow.submit();
    expect(sessionError).toHaveBeenCalled();
    expect(flow.step).toBe('retry');
    expect(flow.stepError).toBeUndefined();
    await flow.retry();
    expect(flow.step).toBe('done');
  });

  it('wipes the key of an abandoned secret, and of a refused creation', async () => {
    const key = new Uint8Array(32).fill(7);
    const s = setup(
      { 'POST /secrets': created('pending'), [`PUT /secrets/${ID}/file`]: problem(500, 'internal') },
      { seal: { newKey: () => key } },
    );
    s.flow.setFile([file('x')]);
    await s.flow.submit();
    expect(s.flow.step).toBe('retry');
    expect(key.some((b) => b !== 0)).toBe(true);
    s.flow.abandon();
    expect(key.every((b) => b === 0)).toBe(true);

    const other = new Uint8Array(32).fill(9);
    const refused = setup({ 'POST /secrets': problem(500, 'internal') }, { seal: { newKey: () => other } });
    refused.flow.form.text = 'x';
    await refused.flow.submit();
    expect(refused.flow.step).toBe('form');
    expect(other.every((b) => b === 0)).toBe(true);
  });

  it('abandons the incomplete secret', async () => {
    const { flow } = await failedUpload(problem(500, 'internal'), secretAnswer('link'));
    flow.abandon();
    expect(flow.step).toBe('form');
    expect(flow.stepError).toBeUndefined();
    expect(flow.form.file).toBeDefined();
    await flow.retry();
    expect(flow.step).toBe('form');
    flow.abandon();
    expect(flow.step).toBe('form');
  });
});

describe('creation refused', () => {
  async function refused(reply: Reply | Error, s: Setup = {}, edit?: (flow: SecretCreateFlow) => void) {
    const setupResult = setup({ 'POST /secrets': reply }, s);
    const { flow } = setupResult;
    flow.form.text = 'x';
    edit?.(flow);
    await flow.submit();
    expect(flow.step).toBe('form');
    expect(flow.phase).toBeUndefined();
    return setupResult;
  }

  const email = (flow: SecretCreateFlow) => {
    flow.form.delivery = 'email';
    flow.form.recipient = 'carol@example.net';
    flow.form.passphrase = 'p';
  };

  it('maps validation errors to the fields, or shows the general message', async () => {
    const mapped = await refused(
      problem(400, 'validation-failed', { errors: [{ field: '/expiresIn', code: 'required' }] }),
    );
    expect(mapped.flow.errors).toEqual({ expiresIn: { key: 'fieldErrors.required' } });
    expect(mapped.flow.stepError).toBeUndefined();
    expect(mapped.flow.refusals).toBe(1);
    const general = await refused(
      problem(400, 'validation-failed', { errors: [{ field: '/verifier', code: 'x' }] }),
    );
    expect(general.flow.errors).toEqual({});
    expect(general.flow.errorText).toBe('errors.validation-failed');
  });

  it('drops the errors of fields an external does not see', async () => {
    const { flow } = await refused(
      problem(400, 'validation-failed', {
        errors: [
          { field: '/delivery', code: 'not-allowed' },
          { field: '/recipient', code: 'required' },
        ],
      }),
      { external: true },
    );
    expect(flow.errors).toEqual({});
    expect(flow.errorText).toBe('errors.validation-failed');
  });

  it('drops a delivery error when the delivery is not offered, but keeps the recipient', async () => {
    const { flow } = await refused(
      problem(400, 'validation-failed', {
        errors: [
          { field: '/delivery', code: 'not-allowed' },
          { field: '/recipient', code: 'required' },
        ],
      }),
      { secrets: { ...features, emailAllowed: false } },
    );
    expect(flow.errors).toEqual({ recipient: { key: 'fieldErrors.required' } });
  });

  it('shows a refused recipient domain on the recipient', async () => {
    const withField = await refused(
      problem(403, 'recipient-domain-refused', { errors: [{ field: '/recipient', code: 'domain-denied' }] }),
      {},
      email,
    );
    expect(withField.flow.errors).toEqual({ recipient: { key: 'secretCreate.recipient.domainRefused' } });
    const without = await refused(problem(403, 'recipient-domain-refused'), {}, email);
    expect(without.flow.errors).toEqual({ recipient: { key: 'secretCreate.recipient.domainRefused' } });
    const ext = await refused(problem(403, 'recipient-domain-refused'), { external: true });
    expect(ext.flow.errors).toEqual({});
    expect(ext.flow.errorText).toBe('errors.recipient-domain-refused');
  });

  it('maps the rules of the tenant to their fields', async () => {
    expect((await refused(problem(403, 'secret-passphrase-required'))).flow.errors).toEqual({
      passphrase: { key: 'secretCreate.passphrase.requiredByEmail' },
    });
    expect((await refused(problem(403, 'secret-email-not-allowed'), {}, email)).flow.errors).toEqual({
      delivery: { key: 'secretCreate.delivery.emailNotAllowed' },
    });
    const ext = await refused(problem(403, 'secret-email-not-allowed'), { external: true });
    expect(ext.flow.errors).toEqual({});
    expect(ext.flow.errorText).toBe('errors.secret-email-not-allowed');
    expect((await refused(problem(403, 'secret-file-not-allowed'))).flow.errors).toEqual({
      file: { key: 'secretCreate.file.notAllowed' },
    });
    expect(
      (await refused(problem(413, 'secret-file-too-large', { maxTransferBytes: 58 }))).flow.errors,
    ).toEqual({
      file: { key: 'secretCreate.file.tooLarge', params: { max: 10 } },
    });
    const tooLarge = (await refused(problem(413, 'secret-file-too-large'))).flow;
    expect(tooLarge.errors.file?.params?.['max']).toBe(tooLarge.maxFileBytes);
    expect((await refused(problem(422, 'secret-duration-not-offered'))).flow.errors).toEqual({
      expiresIn: { key: 'fieldErrors.not-allowed' },
    });
  });

  it('shows the other problems as a general message', async () => {
    for (const code of [
      'secrets-disabled',
      'quota-exceeded',
      'deposit-not-allowed',
      'secret-format-invalid',
    ]) {
      const { flow } = await refused(problem(code === 'quota-exceeded' ? 507 : 403, code));
      expect(flow.errorText).toBe(`errors.${code}`);
      expect(flow.errors).toEqual({});
    }
  });

  it('waits after a rate limit or a 24-hour count, not after the open secrets limit', async () => {
    let now = 0;
    const limited = await refused(problem(429, 'rate-limited', { retryAfterSeconds: 3 }), { now: () => now });
    expect(limited.flow.secondsBeforeRetry()).toBe(3);
    expect(limited.flow.errorText).toBe('errors.rate-limited');
    limited.flow.form.text = 'again';
    await limited.flow.submit();
    expect(limited.calls).toHaveLength(1);
    now = 3_000;
    await limited.flow.submit();
    expect(limited.calls).toHaveLength(2);
    const daily = await refused(problem(429, 'secret-limit-reached', { retryAfterSeconds: 60 }), {
      now: () => 0,
    });
    expect(daily.flow.secondsBeforeRetry(30_000)).toBe(30);
    const open = await refused(problem(429, 'secret-limit-reached'));
    expect(open.flow.retryAt).toBeUndefined();
    expect(open.flow.secondsBeforeRetry()).toBe(0);
    expect(open.flow.errorText).toBe('errors.secret-limit-reached');
  });

  it('hands maintenance and an expired session to the deposit flow', async () => {
    const { flow, sessionError } = await refused(problem(503, 'maintenance'), { sessionError: () => true });
    expect(sessionError).toHaveBeenCalledOnce();
    expect(flow.stepError).toBeUndefined();
    expect(flow.refusals).toBe(0);
    expect(flow.form.text).toBe('x');
  });
});

describe('after the creation', () => {
  async function done() {
    const s = setup({ 'POST /secrets': created() });
    s.flow.form.text = 'x';
    await s.flow.submit();
    expect(s.flow.step).toBe('done');
    return s;
  }

  it('wipes the key once the link is built, and once the mail is sent', async () => {
    const key = new Uint8Array(32).fill(7);
    const link = setup({ 'POST /secrets': created() }, { seal: { newKey: () => key } });
    link.flow.form.text = 'x';
    await link.flow.submit();
    expect(link.flow.link).toContain('#k=BwcH');
    expect(key.every((b) => b === 0)).toBe(true);

    const mailKey = new Uint8Array(32).fill(7);
    const mail = setup(
      { 'POST /secrets': created('pending'), [`POST /secrets/${ID}/send`]: secretAnswer('email') },
      { seal: { newKey: () => mailKey } },
    );
    mail.flow.form.text = 'x';
    mail.flow.form.delivery = 'email';
    mail.flow.form.recipient = 'carol@example.net';
    mail.flow.form.passphrase = 'p';
    await mail.flow.submit();
    expect(mail.flow.step).toBe('done');
    expect((mail.calls[1]?.body as { fragmentKey: string }).fragmentKey).toMatch(/^BwcH/);
    expect(mailKey.every((b) => b === 0)).toBe(true);
  });

  it('forgets the link when the done screen is left, and only then', async () => {
    const { flow } = await done();
    flow.form.text = 'draft';
    flow.forgetResult();
    expect(flow.step).toBe('form');
    expect(flow.link).toBeUndefined();
    expect(flow.expiresAt).toBeUndefined();
    // Away from the done step, nothing changes.
    flow.forgetResult();
    expect(flow.step).toBe('form');
    expect(flow.form.text).toBe('draft');
  });

  it('forgets everything when the depositor ends the session', async () => {
    const s = setup({
      'POST /secrets': created('pending'),
      [`PUT /secrets/${ID}/file`]: problem(500, 'internal'),
    });
    s.flow.form.text = 'draft';
    s.flow.setFile([file('x')]);
    await s.flow.submit();
    expect(s.flow.step).toBe('retry');
    s.endSession();
    expect(s.flow.step).toBe('form');
    expect(s.flow.form.text).toBe('');
    expect(s.flow.form.file).toBeUndefined();
  });

  it('creates another secret', async () => {
    const { flow } = await done();
    flow.form.text = 'leftover';
    flow.createAnother();
    expect(flow.step).toBe('form');
    expect(flow.link).toBeUndefined();
    expect(flow.expiresAt).toBeUndefined();
    expect(flow.form.text).toBe('');
  });

  it('forgets the link when the session ends, and everything for another address', async () => {
    const { flow } = await done();
    flow.syncSession('alice@entity-a.example.com');
    flow.syncSession(undefined);
    expect(flow.step).toBe('form');
    expect(flow.link).toBeUndefined();
    flow.form.text = 'draft';
    flow.syncSession(undefined);
    flow.syncSession('ALICE@entity-a.example.com');
    expect(flow.form.text).toBe('draft');
    flow.errors = { text: { key: 'x' } };
    flow.syncSession('mallory@entity-a.example.com');
    expect(flow.form.text).toBe('');
    expect(flow.errors).toEqual({});
  });

  it('drops an incomplete secret on reset', async () => {
    const s = setup({
      'POST /secrets': created('pending'),
      [`PUT /secrets/${ID}/file`]: problem(500, 'internal'),
    });
    s.flow.setFile([file('x')]);
    await s.flow.submit();
    expect(s.flow.step).toBe('retry');
    s.flow.reset();
    expect(s.flow.step).toBe('form');
    expect(s.flow.form.file).toBeUndefined();
    await s.flow.retry();
    expect(s.calls).toHaveLength(2);
  });
});
