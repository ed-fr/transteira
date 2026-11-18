import { describe, expect, it } from 'vitest';
import { createApiClient } from '../../shared/api/client';
import { DepositFlow, type DepositSession, type PublicTenant } from './flow.svelte';

// The recipient chips, the security switches and the derived values of the redesigned form
// (CLAUDE.md section 13.2). A deposit session is open; POST /transfers answers 500 (only the
// request body matters here).

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
  recipientVerification: true,
  maxDownloads: true,
  folders: false,
  recipientRestrictions: false,
  antivirus: 'enabled' as const,
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
  features,
  confidentialityLevels: [
    { key: 'public', label: 'Public', isDefault: true, rules },
    {
      key: 'confidential',
      label: 'Confidential',
      isDefault: false,
      rules: {
        ...rules,
        requirePassword: true,
        forceDeleteAfterFirstDownload: true,
        requireRecipientVerification: true,
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

async function setup(usedTenant: PublicTenant = tenant) {
  const bodies: Record<string, unknown>[] = [];
  const fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = new URL(String(input), 'https://transfer.entity-a.example.com').pathname.replace(
      /^\/api\/v1/,
      '',
    );
    const method = init?.method ?? 'GET';
    if (method === 'GET' && path === '/deposit-sessions/current') {
      return Response.json(session);
    }
    if (method === 'POST' && path === '/transfers') {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(
        JSON.stringify({ type: 'about:blank', title: 'x', status: 500, code: 'internal-error' }),
        { status: 500, headers: { 'Content-Type': 'application/problem+json' } },
      );
    }
    throw new Error(`unexpected request ${method} ${path}`);
  };
  const api = createApiClient({
    fetch: fetch as typeof globalThis.fetch,
    language: () => 'en',
    csrfToken: () => undefined,
    onCsrfToken: () => undefined,
  });
  const flow = new DepositFlow(usedTenant, undefined, {
    api,
    tr: { t: (key: string) => key, has: () => true },
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
  await flow.start();
  flow.addFiles([new File(['x'], 'a.bin', { lastModified: 1 })]);
  return { flow, bodies };
}

describe('recipient chips', () => {
  it('starts with no recipient and an empty draft', async () => {
    const { flow } = await setup();
    expect(flow.form.recipientDraft).toBe('');
    expect(flow.committedRecipients).toEqual([]);
  });

  it('keeps the draft out of the chips', async () => {
    const { flow } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.form.recipientDraft = 'b@x.example';
    expect(flow.committedRecipients).toEqual(['a@x.example']);
  });

  it('commits the draft, leaving out the addresses already there', async () => {
    const { flow } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.form.recipientDraft = 'B@x.example; A@x.example\nc@x.example';
    expect(flow.commitRecipientDraft()).toEqual({
      list: ['a@x.example', 'B@x.example', 'c@x.example'],
      added: ['B@x.example', 'c@x.example'],
      duplicates: ['A@x.example'],
    });
    expect(flow.form.recipientDraft).toBe('');
    expect(flow.committedRecipients).toEqual(['a@x.example', 'B@x.example', 'c@x.example']);
  });

  it('keeps the list as it is when nothing is added', async () => {
    const { flow } = await setup();
    flow.form.recipientsText = 'a@x.example\nb@x.example';
    flow.form.recipientDraft = 'A@x.example';
    expect(flow.commitRecipientDraft().added).toEqual([]);
    expect(flow.form.recipientsText).toBe('a@x.example\nb@x.example');
    expect(flow.form.recipientDraft).toBe('');
  });

  it('removes a chip and the errors of individual recipients', async () => {
    const { flow } = await setup();
    flow.form.recipientsText = 'a@x.example, nope, c@x.example';
    flow.formErrors = {
      'recipients.1': { key: 'fieldErrors.invalid-email' },
      recipients: { key: 'deposit.form.recipients.tooMany' },
      message: { key: 'fieldErrors.too-long' },
    };
    flow.removeRecipient(1);
    expect(flow.committedRecipients).toEqual(['a@x.example', 'c@x.example']);
    expect(flow.formErrors).toEqual({
      recipients: { key: 'deposit.form.recipients.tooMany' },
      message: { key: 'fieldErrors.too-long' },
    });
    const errors = flow.formErrors;
    flow.removeRecipient(5);
    flow.removeRecipient(-1);
    expect(flow.committedRecipients).toEqual(['a@x.example', 'c@x.example']);
    expect(flow.formErrors).toBe(errors);
    flow.removeRecipient(0);
    expect(flow.formErrors).toBe(errors);
  });

  it('commits the draft first when the form is submitted', async () => {
    const { flow, bodies } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.form.recipientDraft = 'b@x.example';
    await flow.submitTransfer();
    expect(flow.form.recipientDraft).toBe('');
    expect(bodies[0]?.['recipients']).toEqual(['a@x.example', 'b@x.example']);
  });

  it('validates the address of the draft like a chip', async () => {
    const { flow, bodies } = await setup();
    flow.form.recipientDraft = 'nope';
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ 'recipients.0': { key: 'fieldErrors.invalid-email' } });
    expect(flow.committedRecipients).toEqual(['nope']);
    expect(bodies).toHaveLength(0);
  });
});

describe('password switch', () => {
  it('is off by default, on when chosen, imposed or typed', async () => {
    const { flow } = await setup();
    expect(flow.passwordEnabled).toBe(false);
    flow.setPasswordOn(true);
    expect(flow.passwordEnabled).toBe(true);
    flow.setPasswordOn(false);
    flow.form.password = 'secret';
    expect(flow.passwordEnabled).toBe(true);
    flow.form.password = '';
    flow.setLevel('confidential');
    expect(flow.passwordRequired).toBe(true);
    expect(flow.passwordEnabled).toBe(true);
  });

  it('refuses an empty password while on, and clears it when turned off', async () => {
    const { flow, bodies } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.setPasswordOn(true);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ password: { key: 'deposit.form.password.empty' } });
    expect(bodies).toHaveLength(0);
    flow.form.password = 'secret';
    flow.setPasswordOn(false);
    expect(flow.form.password).toBe('');
    expect(flow.formErrors).toEqual({});
    await flow.submitTransfer();
    expect(bodies[0]).not.toHaveProperty('password');
  });

  it('cannot be turned off while the level requires a password', async () => {
    const { flow } = await setup();
    flow.setLevel('confidential');
    flow.form.password = 'secret';
    flow.formErrors = { password: { key: 'x' } };
    flow.setPasswordOn(false);
    expect(flow.form.password).toBe('secret');
    expect(flow.formErrors).toEqual({ password: { key: 'x' } });
    expect(flow.passwordEnabled).toBe(true);
  });

  it('sends the password as typed, switch or not', async () => {
    const { flow, bodies } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.form.password = 'secret';
    await flow.submitTransfer();
    expect(bodies[0]).toMatchObject({ password: 'secret' });
  });
});

describe('download limit switch', () => {
  it('is on when chosen, typed or capped by the level', async () => {
    const { flow } = await setup();
    expect(flow.maxDownloadsEnabled).toBe(false);
    expect(flow.levelDownloadsCap).toBeUndefined();
    flow.setMaxDownloadsOn(true);
    expect(flow.maxDownloadsEnabled).toBe(true);
    flow.setMaxDownloadsOn(false);
    flow.form.maxDownloadsText = '2';
    expect(flow.maxDownloadsEnabled).toBe(true);
    flow.form.maxDownloadsText = '';
    flow.setLevel('confidential');
    expect(flow.levelDownloadsCap).toBe(3);
    expect(flow.maxDownloadsEnabled).toBe(true);
  });

  it('is never on when the option is not offered', async () => {
    const { flow } = await setup({ ...tenant, features: { ...features, maxDownloads: false } });
    flow.setLevel('confidential');
    flow.setMaxDownloadsOn(true);
    expect(flow.levelDownloadsCap).toBeUndefined();
    expect(flow.maxDownloadsEnabled).toBe(false);
  });

  it('refuses an empty field while on, and clears it when turned off', async () => {
    const { flow, bodies } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.setMaxDownloadsOn(true);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({ maxDownloads: { key: 'deposit.form.maxDownloads.empty' } });
    flow.form.maxDownloadsText = '4';
    flow.setMaxDownloadsOn(false);
    expect(flow.form.maxDownloadsText).toBe('');
    expect(flow.formErrors).toEqual({});
    await flow.submitTransfer();
    expect(bodies[0]).not.toHaveProperty('maxDownloads');
  });

  it('accepts an empty field under the cap of the level (the server applies the cap)', async () => {
    const { flow, bodies } = await setup();
    flow.form.recipientsText = 'a@x.example';
    flow.setLevel('confidential');
    flow.form.password = 'secret';
    flow.setMaxDownloadsOn(true);
    await flow.submitTransfer();
    expect(flow.formErrors).toEqual({});
    expect(bodies[0]).not.toHaveProperty('maxDownloads');
    flow.form.maxDownloadsText = '2';
    flow.setMaxDownloadsOn(false);
    expect(flow.form.maxDownloadsText).toBe('2');
  });
});

describe('security block', () => {
  it('counts the options in effect', async () => {
    const { flow } = await setup();
    expect(flow.activeSecurityCount).toBe(0);
    flow.setPasswordOn(true);
    flow.form.recipientVerification = true;
    flow.form.deleteAfterFirstDownload = true;
    flow.setMaxDownloadsOn(true);
    expect(flow.activeSecurityCount).toBe(4);
  });

  it('counts the options imposed by the level', async () => {
    const { flow } = await setup();
    flow.setLevel('confidential');
    // Password, recipient verification, deletion after the first download, download cap.
    expect(flow.activeSecurityCount).toBe(4);
  });

  it('counts the end-to-end encryption', async () => {
    const { flow } = await setup({
      ...tenant,
      confidentialityLevels: [],
      features: { ...features, e2ePolicy: 'allowed' },
    });
    flow.form.endToEnd = true;
    expect(flow.activeSecurityCount).toBe(1);
  });
});

describe('antivirus mention', () => {
  it('is shown when the tenant analyses its files', async () => {
    const { flow } = await setup();
    expect(flow.antivirusMentioned).toBe(true);
  });

  it('is left out when the antivirus is disabled', async () => {
    const { flow } = await setup({ ...tenant, features: { ...features, antivirus: 'disabled' } });
    expect(flow.antivirusMentioned).toBe(false);
  });

  it('is left out for an end-to-end encrypted transfer', async () => {
    const { flow } = await setup({
      ...tenant,
      confidentialityLevels: [],
      features: { ...features, e2ePolicy: 'allowed' },
    });
    expect(flow.antivirusMentioned).toBe(true);
    flow.form.endToEnd = true;
    expect(flow.antivirusMentioned).toBe(false);
  });

  it('is left out when the tenant does not describe its features', async () => {
    const { features: _f, ...bare } = tenant;
    const { flow } = await setup(bare);
    expect(flow.antivirusMentioned).toBe(false);
  });
});
