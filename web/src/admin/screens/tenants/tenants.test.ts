import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import type { AdminMe } from '../../auth/machine';
import { MAX_TRANSFER_BYTES } from '../../forms/bytes';
import {
  TENANT_FIELDS,
  appendPage,
  canManageTenants,
  changesProfile,
  createBody,
  deletionResumes,
  editableFields,
  effectiveCeiling,
  emptyForm,
  formFromTenant,
  isDirty,
  languageLabel,
  listRedirect,
  normalizeFqdn,
  quotaUsage,
  statusView,
  limitFollowsCeiling,
  tenantFailure,
  tenantPatch,
  validateTenantForm,
  type Tenant,
  type TenantFieldRefs,
  type TenantForm,
} from './tenants';

const GiB = 2 ** 30;

const tenant: Tenant = {
  id: 'ten_A',
  name: 'Entity A',
  fqdn: 'transfer.entity-a.example.com',
  defaultLanguage: 'fr',
  maxTransferBytes: 10 * GiB,
  maxTransferCeiling: 15 * GiB,
  status: 'active',
  storageQuotaBytes: 1024 * GiB,
  storageUsedBytes: 256 * GiB,
  createdAt: '2026-09-01T08:00:00Z',
  updatedAt: '2026-10-01T08:00:00Z',
};

function me(role: AdminMe['role'], tenants: { id: string; name: string; fqdn: string }[]): AdminMe {
  return { role, tenants } as unknown as AdminMe;
}

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;
const fmt = (n: number): string => `${n / GiB} GiB`;

const refs: TenantFieldRefs = {
  name: { id: 'f-name', label: 'Name' },
  fqdn: { id: 'f-fqdn', label: 'FQDN' },
  defaultLanguage: { id: 'f-lang', label: 'Language' },
  storageQuotaBytes: { id: 'f-quota', label: 'Quota' },
  maxTransferCeiling: { id: 'f-ceiling', label: 'Ceiling' },
  maxTransferBytes: { id: 'f-max', label: 'Max' },
};

function view(partial: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'general',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...partial,
  };
}

describe('list', () => {
  it('redirects a delegated admin with a single tenant to its general settings', () => {
    const one = [{ id: 'ten/1', name: 'A', fqdn: 'a.example.com' }];
    expect(listRedirect(me('delegated_admin', one))).toBe('/tenants/ten%2F1/general');
    expect(listRedirect(me('delegated_admin', [...one, { id: 'b', name: 'B', fqdn: 'b.example.com' }]))).toBe(
      undefined,
    );
    expect(listRedirect(me('delegated_admin', []))).toBe(undefined);
    expect(listRedirect(me('super_admin', one))).toBe(undefined);
    expect(listRedirect(undefined)).toBe(undefined);
  });

  it('lets only the super admin create tenants', () => {
    expect(canManageTenants(me('super_admin', []))).toBe(true);
    expect(canManageTenants(me('delegated_admin', []))).toBe(false);
    expect(canManageTenants(undefined)).toBe(false);
  });

  it('appends a page without duplicating rows', () => {
    const b = { ...tenant, id: 'ten_B' };
    const c = { ...tenant, id: 'ten_C' };
    expect(appendPage([tenant, b], [b, c]).map((r) => r.id)).toEqual(['ten_A', 'ten_B', 'ten_C']);
  });

  it('computes the storage usage', () => {
    expect(quotaUsage(tenant)).toEqual({ used: 256 * GiB, quota: 1024 * GiB, percent: 25 });
    expect(quotaUsage({ storageUsedBytes: 1, storageQuotaBytes: 3 }).percent).toBe(33.3);
    expect(quotaUsage({ storageUsedBytes: 5, storageQuotaBytes: 2 }).percent).toBe(100);
    expect(quotaUsage({ storageUsedBytes: 5, storageQuotaBytes: 0 }).percent).toBe(0);
    expect(quotaUsage({ storageUsedBytes: -1, storageQuotaBytes: 10 })).toEqual({
      used: 0,
      quota: 10,
      percent: 0,
    });
  });

  it('maps the status to a badge', () => {
    expect(statusView('active')).toEqual({ variant: 'ok', key: 'adminTenants.status.active' });
    expect(statusView('deleting')).toEqual({ variant: 'warning', key: 'adminTenants.status.deleting' });
  });

  it('names a language in the interface language', () => {
    expect(languageLabel('fr', 'en')).toBe('French');
    expect(languageLabel('en', 'fr')).toBe('Anglais');
    expect(languageLabel('en', '')).toBe('English');
    expect(languageLabel('zz', 'en')).toBe('zz');
    expect(languageLabel('fr', 'not a locale!')).toBe('fr');
  });
});

describe('form model', () => {
  it('starts the creation form at 20 GiB with no quota', () => {
    expect(emptyForm()).toEqual({
      name: '',
      fqdn: '',
      defaultLanguage: 'en',
      storageQuotaBytes: null,
      maxTransferBytes: MAX_TRANSFER_BYTES,
      maxTransferCeiling: MAX_TRANSFER_BYTES,
    });
    expect(emptyForm('fr').defaultLanguage).toBe('fr');
  });

  it('gives every field to the super admin, the language and limit to a delegated admin', () => {
    expect(editableFields('super_admin')).toEqual(TENANT_FIELDS);
    expect(editableFields('delegated_admin')).toEqual(['defaultLanguage', 'maxTransferBytes']);
    expect(editableFields(undefined)).toEqual(['defaultLanguage', 'maxTransferBytes']);
  });

  it('normalises the FQDN when it is valid', () => {
    expect(normalizeFqdn('  Transfer.Example.COM ')).toBe('transfer.example.com');
    expect(normalizeFqdn(' not valid ')).toBe('not valid');
  });

  it('builds the creation body', () => {
    const form: TenantForm = {
      ...emptyForm('fr'),
      name: ' Entity B ',
      fqdn: 'Transfer.Entity-B.example.com',
      storageQuotaBytes: 512 * GiB,
    };
    expect(createBody(form)).toEqual({
      name: 'Entity B',
      fqdn: 'transfer.entity-b.example.com',
      defaultLanguage: 'fr',
      storageQuotaBytes: 512 * GiB,
      maxTransferBytes: MAX_TRANSFER_BYTES,
      maxTransferCeiling: MAX_TRANSFER_BYTES,
    });
    expect(createBody(emptyForm())).toBeUndefined();
    expect(createBody({ ...form, maxTransferBytes: null })).toBeUndefined();
    expect(createBody({ ...form, maxTransferCeiling: null })).toBeUndefined();
  });
});

describe('tenantPatch', () => {
  it('is empty when nothing changed', () => {
    expect(tenantPatch(tenant, formFromTenant(tenant), 'super_admin')).toEqual({});
    expect(isDirty(tenant, formFromTenant(tenant), 'super_admin')).toBe(false);
  });

  it('sends every changed field for the super admin, normalised', () => {
    const form: TenantForm = {
      name: ' Entity A2 ',
      fqdn: 'NEW.example.com',
      defaultLanguage: 'en',
      storageQuotaBytes: 2048 * GiB,
      maxTransferBytes: 12 * GiB,
      maxTransferCeiling: 20 * GiB,
    };
    expect(tenantPatch(tenant, form, 'super_admin')).toEqual({
      name: 'Entity A2',
      fqdn: 'new.example.com',
      defaultLanguage: 'en',
      storageQuotaBytes: 2048 * GiB,
      maxTransferBytes: 12 * GiB,
      maxTransferCeiling: 20 * GiB,
    });
  });

  it('keeps a trimmed name or a case change of the FQDN out of the patch', () => {
    const form = { ...formFromTenant(tenant), name: ' Entity A ', fqdn: 'TRANSFER.entity-a.example.com' };
    expect(tenantPatch(tenant, form, 'super_admin')).toEqual({});
  });

  it('restricts a delegated admin to the language and the limit', () => {
    const form: TenantForm = {
      ...formFromTenant(tenant),
      name: 'Other',
      fqdn: 'other.example.com',
      storageQuotaBytes: 1,
      maxTransferCeiling: 20 * GiB,
      defaultLanguage: 'en',
      maxTransferBytes: 5 * GiB,
    };
    expect(tenantPatch(tenant, form, 'delegated_admin')).toEqual({
      defaultLanguage: 'en',
      maxTransferBytes: 5 * GiB,
    });
  });

  it('never sends null sizes but reports them as unsaved changes', () => {
    const form = { ...formFromTenant(tenant), storageQuotaBytes: null };
    expect(tenantPatch(tenant, form, 'super_admin')).toEqual({});
    expect(isDirty(tenant, form, 'super_admin')).toBe(true);
    // A field the role cannot edit does not count.
    expect(isDirty(tenant, form, 'delegated_admin')).toBe(false);
    expect(isDirty(tenant, { ...formFromTenant(tenant), maxTransferBytes: null }, 'delegated_admin')).toBe(
      true,
    );
    expect(isDirty(tenant, { ...formFromTenant(tenant), defaultLanguage: 'en' }, 'delegated_admin')).toBe(
      true,
    );
  });

  it('tells whether the profile must be reloaded', () => {
    expect(changesProfile({ name: 'x' })).toBe(true);
    expect(changesProfile({ fqdn: 'x.example.com' })).toBe(true);
    expect(changesProfile({ defaultLanguage: 'en' })).toBe(false);
  });
});

describe('validateTenantForm', () => {
  const valid: TenantForm = { ...formFromTenant(tenant) };

  it('accepts a valid form', () => {
    expect(validateTenantForm(valid, { fields: TENANT_FIELDS }, refs, t, fmt)).toEqual([]);
  });

  it('reports every field in form order', () => {
    const form: TenantForm = {
      name: '  ',
      fqdn: 'not a domain',
      defaultLanguage: 'fr',
      storageQuotaBytes: null,
      maxTransferBytes: null,
      maxTransferCeiling: null,
    };
    const errors = validateTenantForm(
      form,
      { fields: TENANT_FIELDS, empty: { storageQuotaBytes: true, maxTransferCeiling: false } },
      refs,
      t,
      fmt,
    );
    expect(errors).toEqual([
      { id: 'f-name', label: 'Name', message: 'fieldErrors.required' },
      { id: 'f-fqdn', label: 'FQDN', message: 'fieldErrors.invalid-fqdn' },
      { id: 'f-quota', label: 'Quota', message: 'adminComponents.byteSize.errors.required' },
      { id: 'f-ceiling', label: 'Ceiling', message: 'fieldErrors.invalid' },
      { id: 'f-max', label: 'Max', message: 'fieldErrors.invalid' },
    ]);
  });

  it('checks the length of the name and an empty FQDN', () => {
    const errors = validateTenantForm(
      { ...valid, name: 'x'.repeat(101), fqdn: ' ' },
      { fields: TENANT_FIELDS },
      refs,
      t,
      fmt,
    );
    expect(errors.map((e) => e.message)).toEqual(['fieldErrors.too-long', 'fieldErrors.required']);
    expect(
      validateTenantForm({ ...valid, name: 'é'.repeat(100) }, { fields: TENANT_FIELDS }, refs, t, fmt),
    ).toEqual([]);
  });

  it('keeps the limit within the edited ceiling for the super admin', () => {
    const form = { ...valid, maxTransferCeiling: 8 * GiB, maxTransferBytes: 9 * GiB };
    expect(validateTenantForm(form, { fields: TENANT_FIELDS }, refs, t, fmt)).toEqual([
      {
        id: 'f-max',
        label: 'Max',
        message: 'adminTenants.fields.maxTransfer.aboveCeiling {"ceiling":"8 GiB"}',
      },
    ]);
  });

  it('keeps the limit within the saved ceiling for a delegated admin', () => {
    const fields = editableFields('delegated_admin');
    // Fields the delegated admin cannot edit are not checked.
    const form = { ...valid, name: '', maxTransferBytes: 16 * GiB };
    expect(validateTenantForm(form, { fields, ceiling: 15 * GiB }, refs, t, fmt)).toEqual([
      {
        id: 'f-max',
        label: 'Max',
        message: 'adminTenants.fields.maxTransfer.aboveCeiling {"ceiling":"15 GiB"}',
      },
    ]);
    expect(
      validateTenantForm(
        { ...valid, maxTransferBytes: 15 * GiB },
        { fields, ceiling: 15 * GiB },
        refs,
        t,
        fmt,
      ),
    ).toEqual([]);
  });

  it('skips fields without a reference', () => {
    expect(validateTenantForm({ ...valid, name: '' }, { fields: TENANT_FIELDS }, {}, t, fmt)).toEqual([]);
  });

  it('computes the effective ceiling', () => {
    expect(effectiveCeiling(valid, { fields: TENANT_FIELDS })).toBe(15 * GiB);
    expect(effectiveCeiling({ ...valid, maxTransferCeiling: 40 * GiB }, { fields: TENANT_FIELDS })).toBe(
      MAX_TRANSFER_BYTES,
    );
    expect(effectiveCeiling({ ...valid, maxTransferCeiling: null }, { fields: TENANT_FIELDS })).toBe(
      MAX_TRANSFER_BYTES,
    );
    expect(effectiveCeiling(valid, { fields: ['maxTransferBytes'], ceiling: 3 * GiB })).toBe(3 * GiB);
    expect(effectiveCeiling(valid, { fields: ['maxTransferBytes'] })).toBe(MAX_TRANSFER_BYTES);
  });
});

describe('tenantFailure', () => {
  it('reports an FQDN already used on the field', () => {
    expect(tenantFailure(view({ code: 'already-exists', status: 409 }), refs, t)).toEqual({
      ok: false,
      errors: [{ id: 'f-fqdn', label: 'FQDN', message: 'adminTenants.fields.fqdn.taken' }],
    });
    // Without the FQDN field, the general message.
    expect(tenantFailure(view({ code: 'already-exists', status: 409 }), {}, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });

  it('reports an admin host FQDN as reserved', () => {
    const outcome = tenantFailure(
      view({
        code: 'validation-failed',
        status: 400,
        fields: { fqdn: { code: 'reserved-host', message: 'reserved' } },
      }),
      refs,
      t,
    );
    expect(outcome).toEqual({
      ok: false,
      errors: [{ id: 'f-fqdn', label: 'FQDN', message: 'adminTenants.fields.fqdn.reserved' }],
    });
  });

  it('keeps the server message of any other FQDN error', () => {
    const outcome = tenantFailure(
      view({
        code: 'validation-failed',
        status: 400,
        fields: { fqdn: { code: 'invalid-format', message: 'bad format' } },
      }),
      refs,
      t,
    );
    expect(outcome).toEqual({
      ok: false,
      errors: [{ id: 'f-fqdn', label: 'FQDN', message: 'bad format' }],
    });
  });

  it('maps the other field errors and keeps not-nullable on the FQDN', () => {
    const outcome = tenantFailure(
      view({
        code: 'validation-failed',
        status: 400,
        fields: {
          maxTransferBytes: { code: 'too-large', message: 'too large' },
          fqdn: { code: 'not-nullable', message: 'not nullable' },
        },
      }),
      refs,
      t,
    );
    expect(outcome).toEqual({
      ok: false,
      errors: [
        { id: 'f-fqdn', label: 'FQDN', message: 'not nullable' },
        { id: 'f-max', label: 'Max', message: 'too large' },
      ],
    });
  });

  it('adds the general message for errors on unknown fields', () => {
    const outcome = tenantFailure(
      view({
        code: 'validation-failed',
        status: 400,
        fields: { cursor: { code: 'invalid', message: 'x' }, name: { code: 'too-long', message: 'long' } },
      }),
      { name: refs.name },
      t,
    );
    expect(outcome).toEqual({
      ok: false,
      message: 'general',
      errors: [{ id: 'f-name', label: 'Name', message: 'long' }],
    });
  });

  it('shows the general message for any other error', () => {
    expect(tenantFailure(view({ code: 'forbidden', status: 403 }), refs, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });

  it('tells a deletion that resumes from a refused one', () => {
    expect(deletionResumes({ status: 500 })).toBe(true);
    expect(deletionResumes({ status: 400 })).toBe(false);
    expect(deletionResumes({ status: undefined })).toBe(false);
  });
});

describe('limitFollowsCeiling', () => {
  const form = (over: Partial<TenantForm> = {}): TenantForm => ({ ...formFromTenant(tenant), ...over });

  it('lets the server lower an unedited limit when the super admin lowers the ceiling', () => {
    const lowered = form({ maxTransferCeiling: 5 * GiB });
    expect(limitFollowsCeiling(tenant, lowered, 'super_admin')).toBe(true);
    expect(
      validateTenantForm(lowered, { fields: TENANT_FIELDS, limitFollowsCeiling: true }, refs, t, fmt),
    ).toEqual([]);
    expect(tenantPatch(tenant, lowered, 'super_admin')).toEqual({ maxTransferCeiling: 5 * GiB });
    // Without the option, the limit above the ceiling is an error.
    expect(validateTenantForm(lowered, { fields: TENANT_FIELDS }, refs, t, fmt).map((e) => e.id)).toEqual([
      'f-max',
    ]);
  });

  it('does not apply otherwise', () => {
    expect(limitFollowsCeiling(tenant, form({ maxTransferCeiling: 5 * GiB }), 'delegated_admin')).toBe(false);
    expect(limitFollowsCeiling(tenant, form({ maxTransferCeiling: null }), 'super_admin')).toBe(false);
    expect(
      limitFollowsCeiling(
        tenant,
        form({ maxTransferCeiling: 5 * GiB, maxTransferBytes: 8 * GiB }),
        'super_admin',
      ),
    ).toBe(false);
    expect(limitFollowsCeiling(tenant, form({ maxTransferCeiling: 12 * GiB }), 'super_admin')).toBe(false);
    expect(limitFollowsCeiling(tenant, form(), 'super_admin')).toBe(false);
  });
});
