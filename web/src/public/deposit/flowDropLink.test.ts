import { describe, expect, it, vi } from 'vitest';
import { createApiClient } from '../../shared/api/client';
import type { UploadEngine } from '../../shared/upload/engine';
import type { SenderTransfer } from '../../shared/upload/finalize';
import {
  DepositFlow,
  type DepositSession,
  type DropLinkContext,
  type FinalizeFn,
  type PublicTenant,
} from './flow.svelte';
import { validateForm } from './form';

// Drop link deposits and link-only transfers (since 2.0), on a minimal fake of the API.
interface Reply {
  status: number;
  body?: unknown;
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
    recipientVerification: true,
    maxDownloads: false,
    folders: false,
    recipientRestrictions: false,
    antivirus: 'enabled',
    linkOnly: true,
  },
  confidentialityLevels: [
    { key: 'internal', label: 'Internal', isDefault: true, rules },
    { key: 'open', label: 'Open', isDefault: false, rules: { ...rules, linkOnlyAllowed: false } },
    {
      key: 'verified',
      label: 'Verified',
      isDefault: false,
      rules: { ...rules, requireRecipientVerification: true },
    },
  ],
};

const baseSession = {
  email: 'alice@entity-a.example.com',
  csrfToken: 'csrf_1',
  expiresAt: '2026-10-23T20:00:00Z',
  limits: { maxTransferBytes: 1000, expiryDays: [1, 7, 30] as (1 | 7 | 30)[] },
  canInvite: false,
};
const internalSession: DepositSession = { ...baseSession, kind: 'internal' };
const dropSession: DepositSession = {
  ...baseSession,
  email: 'bob@partner.example.org',
  kind: 'drop_link',
  dropLink: { label: 'Supplier invoices', validityDays: 30 },
};
const dropLink: DropLinkContext = {
  token: 'ttd_0123456789012345678901234567890', // gitleaks:allow (fake drop token)
  label: 'Supplier invoices',
  validityDays: 30,
};

function transfer(extra: Partial<SenderTransfer> = {}): SenderTransfer {
  return {
    id: 'trf_1',
    status: 'uploading',
    senderEmail: 'alice@entity-a.example.com',
    recipients: [],
    expiryDays: 7,
    passwordProtected: false,
    deleteAfterFirstDownload: false,
    totalBytes: 3,
    createdAt: '2026-10-23T16:00:00Z',
    files: [{ id: 'fil_1', name: 'a.txt', size: 3, scanStatus: 'pending', uploadUrl: '/u', uploadOffset: 0 }],
    ...extra,
  };
}

function setup(
  routes: Record<string, Reply>,
  options: { tenant?: PublicTenant; dropLink?: DropLinkContext; finalize?: FinalizeFn } = {},
) {
  const calls: { method: string; path: string; body: unknown }[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'https://transfer.entity-a.example.com');
    const method = init?.method ?? 'GET';
    const path = url.pathname.replace(/^\/api\/v1/, '');
    calls.push({ method, path, body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined });
    const reply = routes[`${method} ${path}`];
    if (reply === undefined) throw new Error(`unexpected request ${method} ${path}`);
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
  const engine = {
    start: vi.fn(() => new Promise<'completed'>(() => undefined)),
    pause: vi.fn(),
    resume: vi.fn(),
    stop: vi.fn(),
    cancel: vi.fn(),
    getSnapshot: vi.fn(),
    subscribe: () => () => undefined,
    onAnnounce: () => () => undefined,
    isActive: () => false,
  } as unknown as UploadEngine;
  const flow = new DepositFlow(
    options.tenant ?? tenant,
    undefined,
    {
      api,
      tr: { t: (k: string) => k, has: () => true },
      clearCsrf: vi.fn(),
      resumeStore: { save: vi.fn(), load: () => undefined, clear: vi.fn() },
      createEngine: () => engine,
      finalize: options.finalize ?? (async () => ({ kind: 'available', transfer: transfer() })),
      poll: async () => ({ kind: 'available', transfer: transfer() }),
      confirm: () => true,
      announce: vi.fn(),
      language: () => 'en',
      newKey: () => 'key',
    },
    undefined,
    options.dropLink,
  );
  return { flow, calls };
}

const file = () => new File(['abc'], 'a.txt', { type: 'text/plain', lastModified: 1 });

describe('drop link deposit', () => {
  it('asks for the address, sends the drop link token and does not read it from the page', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': { status: 401, body: { code: 'unauthenticated', status: 401 } },
        'POST /deposit-sessions': {
          status: 202,
          body: {
            challengeId: 'vch_1',
            email: 'bob@partner.example.org',
            expiresAt: 'x',
            attemptsRemaining: 2,
          },
        },
      },
      { dropLink },
    );
    expect(flow.isDropLink).toBe(true);
    await flow.start();
    expect(flow.step).toBe('email');
    flow.email = 'bob@partner.example.org';
    await flow.submitEmail();
    expect(flow.step).toBe('code');
    expect(calls[1]?.body).toEqual({ email: 'bob@partner.example.org', dropLinkToken: dropLink.token });
  });

  it('refuses a session that is not for a drop link', async () => {
    const { flow } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: internalSession },
      },
      { dropLink },
    );
    await flow.start();
    expect(flow.step).toBe('email');
  });

  it('stops when the link is no longer valid', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': { status: 401, body: { code: 'unauthenticated', status: 401 } },
        'POST /deposit-sessions': { status: 404, body: { code: 'drop-link-invalid', status: 404 } },
      },
      { dropLink },
    );
    await flow.start();
    flow.email = 'bob@partner.example.org';
    await flow.submitEmail();
    expect(flow.dropLinkGone).toBe(true);
    expect(flow.errorText).toBe('deposit.email.dropLinkGone');
    await flow.submitEmail();
    expect(calls).toHaveLength(2);
  });

  it('sends neither recipients nor level, and forces the validity of the link', async () => {
    const { flow, calls } = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: dropSession },
        'POST /transfers': { status: 201, body: transfer() },
      },
      { dropLink },
    );
    await flow.start();
    expect(flow.step).toBe('form');
    expect(flow.dropLinkLabel).toBe('Supplier invoices');
    expect(flow.expiryOptions).toEqual([30]);
    expect(flow.linkOnlyOffered).toBe(false);
    flow.addFiles([file()]);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({});
    const body = calls[1]?.body as Record<string, unknown>;
    expect(body).not.toHaveProperty('recipients');
    expect(body).not.toHaveProperty('confidentialityLevel');
    expect(body['expiryDays']).toBe(30);
  });

  it('shows the level of the link only', () => {
    const { flow } = setup({}, { dropLink: { ...dropLink, levelKey: 'open' } });
    expect(flow.levels.map((l) => l.key)).toEqual(['open']);
    expect(flow.level?.key).toBe('open');
  });
});

describe('link-only transfer', () => {
  const ready = async (options: Parameters<typeof setup>[1] = {}) => {
    const ctx = setup(
      {
        'GET /deposit-sessions/current': { status: 200, body: internalSession },
        'POST /transfers': { status: 201, body: transfer({ linkOnly: true }) },
      },
      options,
    );
    await ctx.flow.start();
    ctx.flow.addFiles([file()]);
    return ctx;
  };

  it('is offered to internal depositors when the tenant and the level allow it', async () => {
    const { flow } = await ready();
    expect(flow.linkOnlyOffered).toBe(true);
    flow.setLevel('open');
    expect(flow.linkOnlyOffered).toBe(false);
    expect(flow.linkOnlyEffective).toBe(false);
  });

  it('is not offered without the tenant feature', async () => {
    const { flow } = await ready({
      tenant: { ...tenant, features: { ...tenant.features!, linkOnly: false } },
    });
    expect(flow.linkOnlyOffered).toBe(false);
  });

  it('is not offered to an external depositor', async () => {
    const { flow } = setup({ 'GET /deposit-sessions/current': { status: 200, body: dropSession } });
    await flow.start();
    expect(flow.linkOnlyOffered).toBe(false);
  });

  it('clears the recipient verification and makes recipients optional', async () => {
    const { flow, calls } = await ready();
    flow.form.recipientVerification = true;
    flow.setLinkOnly(true);
    expect(flow.form.recipientVerification).toBe(false);
    expect(flow.recipientVerificationEffective).toBe(false);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({});
    const body = calls[1]?.body as Record<string, unknown>;
    expect(body['linkOnly']).toBe(true);
    expect(body).not.toHaveProperty('recipients');
    expect(body).not.toHaveProperty('recipientVerification');
  });

  it('is blocked by a level requiring recipient verification', async () => {
    const { flow } = await ready();
    flow.setLinkOnly(true);
    flow.setLevel('verified');
    expect(flow.linkOnlyBlockedByVerification).toBe(true);
    expect(flow.form.linkOnly).toBe(false);
    expect(flow.linkOnlyEffective).toBe(false);
  });

  it('keeps the link of the finalization answer apart from the transfer', async () => {
    const { flow } = await ready({
      finalize: async (_id, options) => {
        const first = transfer({
          status: 'scanning',
          linkOnly: true,
          downloadUrl: 'https://t.example.com/d/dl_x',
        });
        options.onUpdate?.(first);
        const later = transfer({ status: 'available', linkOnly: true });
        options.onUpdate?.(later);
        return { kind: 'available', transfer: later };
      },
    });
    flow.setLinkOnly(true);
    await flow.submitTransfer();
    // The engine promise never settles in this fake: finalize through the retry entry point.
    await flow.retryFinalize();
    expect(flow.linkOnlyUrl).toBe('https://t.example.com/d/dl_x');
    expect(flow.transfer?.downloadUrl).toBeUndefined();
    flow.newTransfer();
    expect(flow.linkOnlyUrl).toBeUndefined();
  });
});

describe('validateForm with optional recipients', () => {
  const values = {
    recipientsText: '',
    message: '',
    expiryDays: 7,
    password: '',
    deleteAfterFirstDownload: false,
    files: [{ name: 'a.txt', size: 1 }],
  };
  const limits = { maxTransferBytes: 100, expiryDays: [7] };

  it('requires recipients unless they are optional', () => {
    expect(validateForm(values, limits, true)).toHaveProperty('recipients');
    expect(validateForm(values, limits, true, true)).toEqual({});
  });

  it('still checks the addresses typed', () => {
    const errors = validateForm({ ...values, recipientsText: 'nope' }, limits, true, true);
    expect(errors).toHaveProperty(['recipients.0']);
  });
});
