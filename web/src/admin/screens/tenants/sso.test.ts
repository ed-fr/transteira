import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  canEditSso,
  emptySsoForm,
  isHttpsIssuer,
  mapSsoSaveError,
  parseSsoDomains,
  secretRequired,
  ssoDirty,
  ssoFormFrom,
  ssoStageKey,
  ssoTestErrorKey,
  ssoTestView,
  ssoUpdateBody,
  validateSso,
  type SsoFields,
  type TenantSso,
} from './sso';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const fields: SsoFields = {
  issuer: { id: 'issuer', label: 'Issuer' },
  clientId: { id: 'client', label: 'Client ID' },
  clientSecret: { id: 'secret', label: 'Secret' },
  emailDomains: { id: 'domains', label: 'Domains' },
};

const saved: TenantSso = {
  enabled: true,
  issuer: 'https://login.example.com/dir/v2.0',
  clientId: 'client-1',
  hasClientSecret: true,
  emailDomains: ['entity-a.example.com'],
  enforced: false,
  requireMfa: true,
  createdAt: '2026-11-04T09:00:00Z',
  updatedAt: '2026-11-04T09:00:00Z',
};

function view(partial: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'server message',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...partial,
  };
}

describe('forms', () => {
  it('starts disabled with multi-factor authentication required', () => {
    expect(emptySsoForm()).toMatchObject({ enabled: false, enforced: false, requireMfa: true });
    expect(ssoFormFrom(undefined)).toEqual(emptySsoForm());
  });

  it('fills the form from the saved configuration without the secret', () => {
    expect(ssoFormFrom(saved)).toEqual({
      enabled: true,
      issuer: saved.issuer,
      clientId: 'client-1',
      clientSecret: '',
      domainsText: 'entity-a.example.com',
      enforced: false,
      requireMfa: true,
    });
  });

  it('sends the secret only when one was typed', () => {
    const form = ssoFormFrom(saved);
    const domains = parseSsoDomains(form.domainsText);
    expect(ssoUpdateBody(form, domains)).not.toHaveProperty('clientSecret');
    expect(ssoUpdateBody({ ...form, clientSecret: 's3cret', issuer: ` ${form.issuer} ` }, domains)).toEqual({
      enabled: true,
      issuer: saved.issuer,
      clientId: 'client-1',
      clientSecret: 's3cret',
      emailDomains: ['entity-a.example.com'],
      enforced: false,
      requireMfa: true,
    });
  });
});

describe('secretRequired', () => {
  it('is required without configuration, without stored secret, or when issuer or client ID change', () => {
    const same = { issuer: saved.issuer, clientId: saved.clientId };
    expect(secretRequired(undefined, same)).toBe(true);
    expect(secretRequired({ ...saved, hasClientSecret: false }, same)).toBe(true);
    expect(secretRequired(saved, same)).toBe(false);
    expect(secretRequired(saved, { ...same, issuer: 'https://login.example.com/other/v2.0' })).toBe(true);
    expect(secretRequired(saved, { ...same, clientId: 'client-2' })).toBe(true);
  });
});

describe('validateSso', () => {
  const run = (form: Partial<ReturnType<typeof ssoFormFrom>>, current: TenantSso | undefined = saved) => {
    const full = { ...ssoFormFrom(current), ...form };
    return validateSso(full, parseSsoDomains(full.domainsText), current, fields, t).map((e) => [
      e.id,
      e.message,
    ]);
  };

  it('accepts the saved configuration as it is', () => {
    expect(run({})).toEqual([]);
  });

  it('requires an https issuer', () => {
    expect(run({ issuer: '', clientSecret: 'x' })).toEqual([['issuer', 'fieldErrors.required']]);
    expect(run({ issuer: 'http://login.example.com/x', clientSecret: 'x' })).toEqual([
      ['issuer', 'adminTenants.sso.errors.issuerHttps'],
    ]);
  });

  it('requires the client ID, the secret when it changes and 1 to 20 valid domains', () => {
    expect(run({ clientId: ' ' })[0]).toEqual(['client', 'fieldErrors.required']);
    expect(run({ clientId: 'client-2' })).toEqual([['secret', 'adminTenants.sso.errors.secretRequired']]);
    expect(run({ clientId: 'client-2', clientSecret: 'x' })).toEqual([]);
    expect(run({ domainsText: '' })).toEqual([['domains', 'adminTenants.sso.errors.domainsRequired']]);
    expect(run({ domainsText: 'not a domain' })[0]?.[0]).toBe('domains');
    const many = Array.from({ length: 21 }, (_, i) => `d${i}.example.com`).join('\n');
    expect(run({ domainsText: many })).toEqual([['domains', 'fieldErrors.too-many']]);
  });

  it('asks for the secret of a first configuration', () => {
    const first = run({ issuer: saved.issuer, clientId: 'c', domainsText: 'a.example.com' }, undefined);
    expect(first).toEqual([['secret', 'adminTenants.sso.errors.secretRequired']]);
  });
});

describe('ssoDirty', () => {
  it('detects changes, a typed secret and an invalid domain list', () => {
    const form = ssoFormFrom(saved);
    const domains = (f: typeof form) => parseSsoDomains(f.domainsText);
    expect(ssoDirty(saved, form, domains(form))).toBe(false);
    expect(ssoDirty(saved, { ...form, enforced: true }, domains(form))).toBe(true);
    expect(ssoDirty(saved, { ...form, clientSecret: 'x' }, domains(form))).toBe(true);
    const more = { ...form, domainsText: 'entity-a.example.com\nentity-b.example.com' };
    expect(ssoDirty(saved, more, domains(more))).toBe(true);
    const bad = { ...form, domainsText: 'nope' };
    expect(ssoDirty(saved, bad, domains(bad))).toBe(true);
    expect(ssoDirty(undefined, emptySsoForm(), domains(emptySsoForm()))).toBe(false);
  });
});

describe('isHttpsIssuer', () => {
  it('accepts https only', () => {
    expect(isHttpsIssuer('https://login.example.com/x')).toBe(true);
    expect(isHttpsIssuer('http://login.example.com/x')).toBe(false);
    expect(isHttpsIssuer('login.example.com')).toBe(false);
    expect(isHttpsIssuer('https://u:p@login.example.com')).toBe(false);
  });
});

describe('mapSsoSaveError', () => {
  it('maps a domain conflict to the domains and a refused issuer to the issuer', () => {
    expect(mapSsoSaveError(view({ code: 'sso-domain-conflict', status: 409 }), fields, t)).toEqual({
      errors: [{ id: 'domains', label: 'Domains', message: 'errors.sso-domain-conflict' }],
    });
    expect(mapSsoSaveError(view({ code: 'sso-issuer-not-allowed', status: 422 }), fields, t)).toEqual({
      errors: [{ id: 'issuer', label: 'Issuer', message: 'errors.sso-issuer-not-allowed' }],
    });
  });

  it('maps validation errors per field, the secret required again included', () => {
    const result = mapSsoSaveError(
      view({
        code: 'validation-failed',
        fields: {
          clientSecret: { code: 'required', message: 'This field is required.' },
          'emailDomains.2': { code: 'invalid-domain', message: 'bad domain' },
        },
      }),
      fields,
      t,
    );
    expect(result.errors).toEqual([
      { id: 'secret', label: 'Secret', message: 'adminTenants.sso.errors.secretRequired' },
      { id: 'domains', label: 'Domains', message: 'bad domain' },
    ]);
    expect(result.message).toBeUndefined();
  });

  it('adds a general message for an unknown field or another error', () => {
    const unknown = mapSsoSaveError(
      view({ code: 'validation-failed', fields: { nope: { code: 'invalid', message: 'x' } } }),
      fields,
      t,
    );
    expect(unknown).toEqual({ errors: [], message: 'server message' });
    expect(mapSsoSaveError(view({ code: 'forbidden', status: 403 }), fields, t)).toEqual({
      errors: [],
      message: 'server message',
    });
  });
});

describe('test result', () => {
  it('translates the closed enums and falls back to unknown for a new value', () => {
    expect(ssoStageKey('tls')).toBe('adminTenants.sso.test.stages.tls');
    expect(ssoStageKey('brand-new')).toBe('adminTenants.sso.test.stages.unknown');
    expect(ssoTestErrorKey('timeout')).toBe('adminTenants.sso.test.errors.timeout');
    expect(ssoTestErrorKey('<b>remote text</b>')).toBe('adminTenants.sso.test.errors.unknown');
  });

  it('builds a view with translated text only', () => {
    expect(ssoTestView({ success: true, durationMs: 182, stage: 'done' }, t)).toEqual({
      success: true,
      summary: 'adminTenants.sso.test.success {"ms":182}',
      stage: 'adminTenants.sso.test.stages.done',
      error: undefined,
    });
    const failed = ssoTestView({ success: false, durationMs: 41, stage: 'tls', error: 'tls_error' }, t);
    expect(failed.success).toBe(false);
    expect(failed.error).toBe('adminTenants.sso.test.errors.tls_error');
  });
});

describe('canEditSso', () => {
  it('lets the super admin only edit; the other roles read', () => {
    expect(canEditSso('super_admin')).toBe(true);
    expect(canEditSso('delegated_admin')).toBe(false);
    expect(canEditSso('auditor')).toBe(false);
    expect(canEditSso(undefined)).toBe(false);
  });
});
