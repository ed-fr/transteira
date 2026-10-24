// Logic of the tenant list, creation and general settings screens (TenantList, TenantCreate,
// TenantGeneral), kept out of the components so that it is unit tested in Node: view models,
// form model, client validation, merge patch per role and mapping of the API errors to fields.
import type { components } from '../../../shared/api/schema';
import type { ErrorView } from '../../../shared/api/problem';
import type { AdminMe } from '../../auth/machine';
import type { FieldRef, SubmitOutcome, SummaryError } from '../../components/form';
import { summaryFromFields } from '../../components/form';
import { MAX_TRANSFER_BYTES } from '../../forms/bytes';
import { parseDomain } from '../../forms/domain';
import { buildPatch } from '../../forms/patch';
import { tenantPath } from '../../shell';

/** A tenant, as returned by the API. */
export type Tenant = components['schemas']['Tenant'];
/** Body of a tenant creation. */
export type TenantCreateBody = components['schemas']['TenantCreate'];
/** Merge patch of the general settings of a tenant. */
export type TenantUpdateBody = components['schemas']['TenantUpdate'];
/** A language of the interface and of the emails. */
export type Language = components['schemas']['Language'];

/** Languages a tenant may choose as its default language. */
export const TENANT_LANGUAGES: readonly Language[] = ['fr', 'en'];

/** Maximum length of a tenant name (TenantCreate.name). */
export const MAX_TENANT_NAME = 100;

/** Translation function. */
export type Translate = (key: string, params?: Record<string, string | number>) => string;

// ---- List ------------------------------------------------------------------------------------

/** Path to go to instead of the list: a delegated admin with a single tenant. */
export function listRedirect(me: AdminMe | undefined): string | undefined {
  if (me?.role !== 'delegated_admin' || me.tenants.length !== 1) {
    return undefined;
  }
  const only = me.tenants[0] as AdminMe['tenants'][number];
  return tenantPath(only.id, 'general');
}

/** Reports whether the admin may create tenants (super admin). */
export function canManageTenants(me: AdminMe | undefined): boolean {
  return me?.role === 'super_admin';
}

/** Appends a page of tenants to the rows already shown, skipping rows already present. */
export function appendPage(rows: readonly Tenant[], page: readonly Tenant[]): Tenant[] {
  const seen = new Set(rows.map((r) => r.id));
  return [...rows, ...page.filter((r) => !seen.has(r.id))];
}

/** Storage usage of a tenant: used and quota in bytes, and the percentage used (0 to 100). */
export interface QuotaUsage {
  used: number;
  quota: number;
  percent: number;
}

/** Storage usage of a tenant; the percentage is capped at 100 and rounded to one decimal. */
export function quotaUsage(tenant: Pick<Tenant, 'storageUsedBytes' | 'storageQuotaBytes'>): QuotaUsage {
  const used = Math.max(0, tenant.storageUsedBytes);
  const quota = Math.max(0, tenant.storageQuotaBytes);
  const ratio = quota > 0 ? Math.min(100, (used / quota) * 100) : 0;
  return { used, quota, percent: Math.round(ratio * 10) / 10 };
}

/** Variant and label key of the status badge of a tenant. */
export function statusView(status: Tenant['status']): { variant: 'ok' | 'warning'; key: string } {
  return status === 'deleting'
    ? { variant: 'warning', key: 'adminTenants.status.deleting' }
    : { variant: 'ok', key: 'adminTenants.status.active' };
}

/** Name of a language in the interface language (e.g. "French" in English), or its code. */
export function languageLabel(code: string, locale: string): string {
  try {
    const name = new Intl.DisplayNames([locale || 'en'], { type: 'language' }).of(code);
    if (name === undefined || name === code) {
      return code;
    }
    return name.charAt(0).toLocaleUpperCase(locale || 'en') + name.slice(1);
  } catch {
    return code;
  }
}

// ---- Form model ------------------------------------------------------------------------------

/** Fields of the general settings form (and of the creation form). */
export type TenantField =
  'name' | 'fqdn' | 'defaultLanguage' | 'storageQuotaBytes' | 'maxTransferBytes' | 'maxTransferCeiling';

/** Fields in form order. */
export const TENANT_FIELDS: readonly TenantField[] = [
  'name',
  'fqdn',
  'defaultLanguage',
  'storageQuotaBytes',
  'maxTransferCeiling',
  'maxTransferBytes',
];

/** Size fields of the form. */
export type SizeField = 'storageQuotaBytes' | 'maxTransferBytes' | 'maxTransferCeiling';

/** Values of the form; a size is null while its field is empty or invalid. */
export interface TenantForm {
  name: string;
  fqdn: string;
  defaultLanguage: Language;
  storageQuotaBytes: number | null;
  maxTransferBytes: number | null;
  maxTransferCeiling: number | null;
}

/** Empty creation form: default language, 20 GiB per transfer and as ceiling, no quota. */
export function emptyForm(defaultLanguage: Language = 'en'): TenantForm {
  return {
    name: '',
    fqdn: '',
    defaultLanguage,
    storageQuotaBytes: null,
    maxTransferBytes: MAX_TRANSFER_BYTES,
    maxTransferCeiling: MAX_TRANSFER_BYTES,
  };
}

/** Form filled with the saved settings of a tenant. */
export function formFromTenant(tenant: Tenant): TenantForm {
  return {
    name: tenant.name,
    fqdn: tenant.fqdn,
    defaultLanguage: tenant.defaultLanguage,
    storageQuotaBytes: tenant.storageQuotaBytes,
    maxTransferBytes: tenant.maxTransferBytes,
    maxTransferCeiling: tenant.maxTransferCeiling,
  };
}

/** Role of an admin, as far as these screens are concerned. */
export type Role = AdminMe['role'];

/** Fields an admin of role may change: every field for a super admin, else language and limit. */
export function editableFields(role: Role | undefined): readonly TenantField[] {
  return role === 'super_admin' ? TENANT_FIELDS : ['defaultLanguage', 'maxTransferBytes'];
}

/** FQDN as sent to the API: normalised (lowercase, punycode) when valid, else trimmed. */
export function normalizeFqdn(input: string): string {
  const parsed = parseDomain(input);
  return parsed.ok ? parsed.value : input.trim();
}

function edited(form: TenantForm): Record<TenantField, string | number | null> {
  return {
    name: form.name.trim(),
    fqdn: normalizeFqdn(form.fqdn),
    defaultLanguage: form.defaultLanguage,
    storageQuotaBytes: form.storageQuotaBytes,
    maxTransferBytes: form.maxTransferBytes,
    maxTransferCeiling: form.maxTransferCeiling,
  };
}

/**
 * Merge patch of the general settings: the fields the role may change that differ from the
 * saved tenant. Empty or invalid sizes (null) are never sent.
 */
export function tenantPatch(tenant: Tenant, form: TenantForm, role: Role | undefined): TenantUpdateBody {
  const original: Record<TenantField, string | number | null> = formFromTenant(tenant);
  return buildPatch(original, edited(form), editableFields(role)) as TenantUpdateBody;
}

/**
 * Reports whether the form has unsaved changes: a field differs from the saved tenant, or an
 * editable size field was emptied or made invalid (so that saving reports the error).
 */
export function isDirty(tenant: Tenant, form: TenantForm, role: Role | undefined): boolean {
  if (Object.keys(tenantPatch(tenant, form, role)).length > 0) {
    return true;
  }
  return editableFields(role).some((f) => isSizeField(f) && form[f] === null);
}

function isSizeField(field: TenantField): field is SizeField {
  return field === 'storageQuotaBytes' || field === 'maxTransferBytes' || field === 'maxTransferCeiling';
}

/** Body of a tenant creation; undefined while a size is missing (validation reports it). */
export function createBody(form: TenantForm): TenantCreateBody | undefined {
  if (form.storageQuotaBytes === null || form.maxTransferBytes === null || form.maxTransferCeiling === null) {
    return undefined;
  }
  return {
    name: form.name.trim(),
    fqdn: normalizeFqdn(form.fqdn),
    defaultLanguage: form.defaultLanguage,
    storageQuotaBytes: form.storageQuotaBytes,
    maxTransferBytes: form.maxTransferBytes,
    maxTransferCeiling: form.maxTransferCeiling,
  };
}

// ---- Validation ------------------------------------------------------------------------------

/** Field references of the form (element id and visible label), by field. */
export type TenantFieldRefs = Partial<Record<TenantField, FieldRef>>;

/** Options of the validation. */
export interface ValidateOptions {
  /** Fields to check (the editable ones). */
  fields: readonly TenantField[];
  /**
   * Ceiling of the limit per transfer when the ceiling field is not checked (delegated admin:
   * the ceiling set by the super admin). With the ceiling field, its value applies.
   */
  ceiling?: number;
  /** Size fields whose input is empty (a null size is then "required", else "invalid"). */
  empty?: Partial<Record<SizeField, boolean>>;
  /**
   * The limit per transfer follows the ceiling (limitFollowsCeiling): it is not checked against
   * the ceiling, the server lowers it.
   */
  limitFollowsCeiling?: boolean;
}

/**
 * Reports whether saving lowers the limit per transfer to the new ceiling on the server: a super
 * admin lowers the ceiling below the saved limit without editing the limit. The API then lowers
 * the limit too (updateTenant), so the form neither blocks the save nor sends the limit; the
 * screen says that the limit will be lowered.
 */
export function limitFollowsCeiling(tenant: Tenant, form: TenantForm, role: Role | undefined): boolean {
  return (
    role === 'super_admin' &&
    form.maxTransferCeiling !== null &&
    form.maxTransferBytes === tenant.maxTransferBytes &&
    form.maxTransferCeiling !== tenant.maxTransferCeiling &&
    tenant.maxTransferBytes > form.maxTransferCeiling
  );
}

/** Effective ceiling of the limit per transfer for the validation. */
export function effectiveCeiling(
  form: TenantForm,
  opts: Pick<ValidateOptions, 'fields' | 'ceiling'>,
): number {
  if (opts.fields.includes('maxTransferCeiling') && form.maxTransferCeiling !== null) {
    return Math.min(form.maxTransferCeiling, MAX_TRANSFER_BYTES);
  }
  return Math.min(opts.ceiling ?? MAX_TRANSFER_BYTES, MAX_TRANSFER_BYTES);
}

/**
 * Client validation of the form, in form order: name (required, at most 100 characters), FQDN
 * (valid domain name), sizes (present) and limit per transfer at most the ceiling (unless it
 * follows the ceiling, limitFollowsCeiling).
 */
export function validateTenantForm(
  form: TenantForm,
  opts: ValidateOptions,
  refs: TenantFieldRefs,
  t: Translate,
  formatBytes: (n: number) => string,
): SummaryError[] {
  const messages: Partial<Record<TenantField, string>> = {};
  const checks = new Set(opts.fields);
  if (checks.has('name')) {
    const name = form.name.trim();
    if (name === '') {
      messages.name = t('fieldErrors.required');
    } else if ([...name].length > MAX_TENANT_NAME) {
      messages.name = t('fieldErrors.too-long');
    }
  }
  if (checks.has('fqdn') && !parseDomain(form.fqdn).ok) {
    messages.fqdn = form.fqdn.trim() === '' ? t('fieldErrors.required') : t('fieldErrors.invalid-fqdn');
  }
  for (const field of ['storageQuotaBytes', 'maxTransferCeiling', 'maxTransferBytes'] as const) {
    if (checks.has(field) && form[field] === null) {
      messages[field] =
        opts.empty?.[field] === true
          ? t('adminComponents.byteSize.errors.required')
          : t('fieldErrors.invalid');
    }
  }
  const ceiling = effectiveCeiling(form, opts);
  if (
    checks.has('maxTransferBytes') &&
    opts.limitFollowsCeiling !== true &&
    form.maxTransferBytes !== null &&
    form.maxTransferBytes > ceiling
  ) {
    messages.maxTransferBytes = t('adminTenants.fields.maxTransfer.aboveCeiling', {
      ceiling: formatBytes(ceiling),
    });
  }
  return toSummary(messages, refs);
}

function toSummary(messages: Partial<Record<TenantField, string>>, refs: TenantFieldRefs): SummaryError[] {
  const out: SummaryError[] = [];
  for (const field of TENANT_FIELDS) {
    const message = messages[field];
    const ref = refs[field];
    if (message !== undefined && ref !== undefined) {
      out.push({ id: ref.id, label: ref.label, message });
    }
  }
  return out;
}

// ---- API errors ------------------------------------------------------------------------------

/**
 * Outcome of a failed creation or update:
 * - 409 already-exists: the FQDN is used by another tenant (on the FQDN field);
 * - 400 validation-failed: the field errors go to their fields with the message of their code;
 *   an FQDN equal to an admin host (field code reserved-host, tenantadmin.CodeAdminHost) gets
 *   the dedicated message of the screen; errors on unknown fields give the general message;
 * - anything else: the general message of the error (403 forbidden, network...).
 */
export function tenantFailure(view: ErrorView, refs: TenantFieldRefs, t: Translate): SubmitOutcome {
  if (view.code === 'already-exists' && refs.fqdn !== undefined) {
    return {
      ok: false,
      errors: [{ id: refs.fqdn.id, label: refs.fqdn.label, message: t('adminTenants.fields.fqdn.taken') }],
    };
  }
  if (view.code === 'validation-failed') {
    const fields = { ...view.fields };
    const fqdn = fields['fqdn'];
    if (fqdn?.code === 'reserved-host') {
      fields['fqdn'] = { ...fqdn, message: t('adminTenants.fields.fqdn.reserved') };
    }
    const known: Record<string, FieldRef> = {};
    for (const field of TENANT_FIELDS) {
      const ref = refs[field];
      if (ref !== undefined) {
        known[field] = ref;
      }
    }
    const { errors, unmatched } = summaryFromFields(fields, known);
    if (errors.length > 0 && unmatched.length === 0) {
      return { ok: false, errors };
    }
    return { ok: false, message: view.message, errors };
  }
  return { ok: false, message: view.message };
}

/** Reports whether a deletion failure leaves the tenant "deleting", resumed automatically. */
export function deletionResumes(view: Pick<ErrorView, 'status'>): boolean {
  return view.status !== undefined && view.status >= 500;
}

/** Reports whether an update changed what the admin profile shows (name or FQDN of a tenant). */
export function changesProfile(patch: TenantUpdateBody): boolean {
  return patch.name !== undefined || patch.fqdn !== undefined;
}
