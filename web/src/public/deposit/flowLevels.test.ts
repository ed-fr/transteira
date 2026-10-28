import { describe, expect, it } from 'vitest';
import { createApiClient } from '../../shared/api/client';
import { DepositFlow, type DepositSession, type PublicTenant } from './flow.svelte';

// A minimal fake of the API: a deposit session is open and POST /transfers answers with reply.
interface Reply {
  status: number;
  body?: unknown;
}

function problem(status: number, code: string, extra: Record<string, unknown> = {}): Reply {
  return { status, body: { type: 'about:blank', title: code, status, code, ...extra } };
}

const rules = {
  requireRecipientVerification: false,
  requirePassword: false,
  allowedExpiryDays: [1, 7, 30] as (1 | 7 | 30)[],
  internalRecipientsOnly: false,
  forceDeleteAfterFirstDownload: false,
  maxDownloads: null,
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
  features: {
    remoteInternalDeposit: false,
    transferReply: false,
    recipientVerification: false,
    maxDownloads: true,
    folders: false,
    recipientRestrictions: true,
    antivirus: 'enabled',
  },
  confidentialityLevels: [
    { key: 'internal', label: 'Internal', isDefault: false, rules },
    { key: 'public', label: 'Public', isDefault: true, rules },
    {
      key: 'confidential',
      label: 'Confidential',
      isDefault: false,
      rules: {
        ...rules,
        requirePassword: true,
        allowedExpiryDays: [1],
        forceDeleteAfterFirstDownload: true,
        maxDownloads: 3,
      },
    },
  ],
};

const session: DepositSession = {
  email: 'alice@entity-a.example.com',
  kind: 'internal',
  csrfToken: 'csrf_1',
  expiresAt: '2026-10-23T20:00:00Z',
  limits: { maxTransferBytes: 1000, expiryDays: [1, 7, 30] },
  canInvite: true,
};

function setup(reply: Reply) {
  const bodies: unknown[] = [];
  let current = reply;
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'https://transfer.entity-a.example.com');
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const method = init?.method ?? 'GET';
    let r: Reply;
    if (method === 'GET' && path === '/deposit-sessions/current') {
      r = { status: 200, body: session };
    } else if (method === 'POST' && path === '/transfers') {
      bodies.push(typeof init?.body === 'string' ? JSON.parse(init.body) : undefined);
      r = current;
    } else {
      throw new Error(`unexpected request ${method} ${path}`);
    }
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), {
      status: r.status,
      headers: { 'Content-Type': r.status >= 400 ? 'application/problem+json' : 'application/json' },
    });
  };
  const api = createApiClient({
    fetch: fetch as typeof globalThis.fetch,
    language: () => 'en',
    csrfToken: () => undefined,
    onCsrfToken: () => undefined,
  });
  const flow = new DepositFlow(tenant, undefined, {
    api,
    tr: { t: (key: string) => key, has: (key: string) => key.startsWith('errors.') },
    language: () => 'en',
    resumeStore: { load: () => undefined, save: () => undefined, clear: () => undefined },
    clearCsrf: () => undefined,
    announce: () => undefined,
    newKey: () => 'key',
    createEngine: () => {
      throw new Error('no upload expected');
    },
    finalize: () => Promise.reject(new Error('no finalize expected')),
    poll: () => Promise.reject(new Error('no poll expected')),
    confirm: () => true,
  });
  return {
    flow,
    bodies,
    set(next: Reply) {
      current = next;
    },
  };
}

describe('levels in the deposit flow', () => {
  it('preselects the default level and applies the rules of the chosen one', async () => {
    const { flow } = setup(problem(500, 'internal-error'));
    await flow.start();
    expect(flow.level?.key).toBe('public');
    expect(flow.expiryOptions).toEqual([1, 7, 30]);
    flow.setLevel('confidential');
    expect(flow.form.expiryDays).toBe(1);
    expect(flow.expiryOptions).toEqual([1]);
    expect(flow.deleteAfterFirstEffective).toBe(true);
    flow.setLevel('internal');
    expect(flow.deleteAfterFirstEffective).toBe(false);
    expect(flow.form.expiryDays).toBe(1);
  });

  it('refuses a missing password and a download limit above the cap', async () => {
    const { flow, bodies } = setup(problem(500, 'internal-error'));
    await flow.start();
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([new File(['x'], 'a.bin', { lastModified: 1 })]);
    flow.setLevel('confidential');
    flow.form.maxDownloadsText = '5';
    await flow.submitTransfer();
    expect(Object.keys(flow.formErrors).sort()).toEqual(['maxDownloads', 'password']);
    expect(bodies).toHaveLength(0);
  });

  it('sends the level and the limit, and maps the server rule errors', async () => {
    const { flow, bodies, set } = setup(
      problem(422, 'confidentiality-rule-violated', { errors: [{ field: '/password', code: 'required' }] }),
    );
    await flow.start();
    flow.form.recipientsText = 'carol@customer.example.net';
    flow.addFiles([new File(['x'], 'a.bin', { lastModified: 1 })]);
    flow.setLevel('confidential');
    flow.form.password = 'secret';
    flow.form.maxDownloadsText = '2';
    await flow.submitTransfer();
    expect(bodies[0]).toMatchObject({
      confidentialityLevel: 'confidential',
      maxDownloads: 2,
      password: 'secret',
      deleteAfterFirstDownload: true,
      expiryDays: 1,
    });
    expect(flow.formErrors).toEqual({ password: { key: 'deposit.form.rules.required' } });
    expect(flow.formRefusals).toBe(1);

    set(problem(403, 'recipient-domain-refused', { errors: [{ field: '/recipients/0', code: 'denied' }] }));
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ 'recipients.0': { key: 'deposit.form.recipients.domainRefused' } });

    set(problem(403, 'recipient-domain-refused'));
    await flow.submitTransfer();
    expect(flow.stepError).toBeDefined();
  });
});
