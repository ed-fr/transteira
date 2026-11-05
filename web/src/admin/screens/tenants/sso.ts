// Logic of the single sign-on screen of a tenant (version 2.0, OpenID Connect), kept out of the
// component so that it is unit tested in Node: form and request body, client-side validation,
// the rule of the client secret (write-only, required again when the issuer or the client ID
// changes), mapping of the API errors to fields, translation of the closed enums of the test
// result and the role rule (only the super admin edits).
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import type { FieldRef, SummaryError } from '../../components/form';
import { parseDomain } from '../../forms/domain';
import { joinLines, parseLineList, type LineList } from '../../forms/lines';
import type { AdminMe } from '../../auth/machine';
import type { Translate } from './network';

/** Single sign-on configuration of a tenant (GET), without its secret. */
export type TenantSso = components['schemas']['TenantSso'];
/** Replacement of the configuration (PUT). */
export type TenantSsoUpdate = components['schemas']['TenantSsoUpdate'];
/** Result of the discovery test. */
export type SsoTestResult = components['schemas']['SsoTestResult'];

/** Limits of the specification (TenantSsoUpdate). */
export const SSO_ISSUER_MIN = 9;
export const SSO_ISSUER_MAX = 512;
export const SSO_CLIENT_ID_MAX = 255;
export const SSO_SECRET_MAX = 1024;
export const SSO_MAX_DOMAINS = 20;

/** Form of the screen. The secret is only what the admin typed: it is never filled in. */
export interface SsoForm {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** One e-mail domain per line. */
  domainsText: string;
  enforced: boolean;
  requireMfa: boolean;
}

/** Form of a tenant without configuration: disabled, multi-factor authentication required. */
export function emptySsoForm(): SsoForm {
  return {
    enabled: false,
    issuer: '',
    clientId: '',
    clientSecret: '',
    domainsText: '',
    enforced: false,
    requireMfa: true,
  };
}

/** Form filled from the saved configuration (the secret field stays empty). */
export function ssoFormFrom(saved: TenantSso | undefined): SsoForm {
  if (saved === undefined) {
    return emptySsoForm();
  }
  return {
    enabled: saved.enabled,
    issuer: saved.issuer,
    clientId: saved.clientId,
    clientSecret: '',
    domainsText: joinLines(saved.emailDomains),
    enforced: saved.enforced,
    requireMfa: saved.requireMfa,
  };
}

/** Parses the domain lines of the form (1 to 20 entries). */
export function parseSsoDomains(text: string): LineList<string> {
  return parseLineList(text, parseDomain, SSO_MAX_DOMAINS);
}

/** Only the super admin may change the configuration; the other roles read it. */
export function canEditSso(role: AdminMe['role'] | undefined): boolean {
  return role === 'super_admin';
}

/**
 * Reports whether the client secret must be typed: no configuration yet, no stored secret, or an
 * issuer or client ID different from the stored ones (a secret is never carried over to another
 * application or provider; the server refuses it too, 400 /clientSecret required).
 */
export function secretRequired(
  saved: TenantSso | undefined,
  form: Pick<SsoForm, 'issuer' | 'clientId'>,
): boolean {
  return (
    saved === undefined ||
    !saved.hasClientSecret ||
    form.issuer.trim() !== saved.issuer ||
    form.clientId.trim() !== saved.clientId
  );
}

/** Reports whether a value is an https URL with a host (the issuer). */
export function isHttpsIssuer(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.hostname !== '' && url.username === '' && url.password === '';
  } catch {
    return false;
  }
}

/** Fields of the form, for the error summary. */
export interface SsoFields {
  issuer: FieldRef;
  clientId: FieldRef;
  clientSecret: FieldRef;
  emailDomains: FieldRef;
}

/** Client-side validation, in the order of the form. */
export function validateSso(
  form: SsoForm,
  domains: LineList<string>,
  saved: TenantSso | undefined,
  fields: SsoFields,
  t: Translate,
): SummaryError[] {
  const out: SummaryError[] = [];
  const add = (ref: FieldRef, key: string, params?: Record<string, string | number>): void => {
    out.push({ id: ref.id, label: ref.label, message: t(key, params) });
  };
  const issuer = form.issuer.trim();
  if (issuer === '') {
    add(fields.issuer, 'fieldErrors.required');
  } else if (!isHttpsIssuer(issuer)) {
    add(fields.issuer, 'adminTenants.sso.errors.issuerHttps');
  } else if (issuer.length < SSO_ISSUER_MIN || issuer.length > SSO_ISSUER_MAX) {
    add(fields.issuer, 'fieldErrors.invalid');
  }
  const clientId = form.clientId.trim();
  if (clientId === '') {
    add(fields.clientId, 'fieldErrors.required');
  } else if (clientId.length > SSO_CLIENT_ID_MAX) {
    add(fields.clientId, 'fieldErrors.too-long');
  }
  if (form.clientSecret.length > SSO_SECRET_MAX) {
    add(fields.clientSecret, 'fieldErrors.too-long');
  } else if (form.clientSecret === '' && secretRequired(saved, form)) {
    add(fields.clientSecret, 'adminTenants.sso.errors.secretRequired');
  }
  if (domains.errors.length > 0) {
    add(fields.emailDomains, 'adminComponents.lineList.invalidLines', { count: domains.errors.length });
  } else if (domains.values.length === 0) {
    add(fields.emailDomains, 'adminTenants.sso.errors.domainsRequired');
  } else if (domains.tooMany) {
    add(fields.emailDomains, 'fieldErrors.too-many');
  }
  return out;
}

/** Body of PUT /admin/tenants/{id}/sso: the secret only when one was typed. */
export function ssoUpdateBody(form: SsoForm, domains: LineList<string>): TenantSsoUpdate {
  const body: TenantSsoUpdate = {
    enabled: form.enabled,
    issuer: form.issuer.trim(),
    clientId: form.clientId.trim(),
    emailDomains: domains.values,
    enforced: form.enforced,
    requireMfa: form.requireMfa,
  };
  if (form.clientSecret !== '') {
    body.clientSecret = form.clientSecret;
  }
  return body;
}

/** Reports whether the form differs from the saved configuration (a typed secret counts). */
export function ssoDirty(saved: TenantSso | undefined, form: SsoForm, domains: LineList<string>): boolean {
  if (form.clientSecret !== '') {
    return true;
  }
  const base = ssoFormFrom(saved);
  const baseDomains = saved?.emailDomains ?? [];
  return (
    base.enabled !== form.enabled ||
    base.issuer !== form.issuer.trim() ||
    base.clientId !== form.clientId.trim() ||
    base.enforced !== form.enforced ||
    base.requireMfa !== form.requireMfa ||
    domains.errors.length > 0 ||
    domains.tooMany ||
    baseDomains.length !== domains.values.length ||
    baseDomains.some((d, i) => d !== domains.values[i])
  );
}

/** Result of the mapping of an API error: summary entries and an optional general message. */
export interface SsoErrorMapping {
  errors: SummaryError[];
  message?: string;
}

/**
 * Maps the error of a save to the fields. 409 sso-domain-conflict points at the domains,
 * 422 sso-issuer-not-allowed at the issuer, 400 validation errors at the field they name
 * (the secret required again included); anything else is a general message.
 */
export function mapSsoSaveError(view: ErrorView, fields: SsoFields, t: Translate): SsoErrorMapping {
  const entry = (ref: FieldRef, message: string): SummaryError => ({ id: ref.id, label: ref.label, message });
  if (view.code === 'sso-domain-conflict') {
    return { errors: [entry(fields.emailDomains, t('errors.sso-domain-conflict'))] };
  }
  if (view.code === 'sso-issuer-not-allowed') {
    return { errors: [entry(fields.issuer, t('errors.sso-issuer-not-allowed'))] };
  }
  if (view.code === 'validation-failed') {
    const errors: SummaryError[] = [];
    let unmatched = false;
    const seen = new Set<string>();
    for (const [path, error] of Object.entries(view.fields)) {
      const name = path.split('.')[0] ?? '';
      const ref = (fields as unknown as Record<string, FieldRef | undefined>)[name];
      if (ref === undefined) {
        unmatched = true;
      } else if (!seen.has(name)) {
        seen.add(name);
        errors.push(
          name === 'clientSecret' && error.code === 'required'
            ? entry(ref, t('adminTenants.sso.errors.secretRequired'))
            : entry(ref, error.message),
        );
      }
    }
    return errors.length > 0 && !unmatched ? { errors } : { errors, message: view.message };
  }
  return { errors: [], message: view.message };
}

const STAGES = ['settings', 'connect', 'tls', 'discovery', 'issuer', 'endpoints', 'done', 'unknown'] as const;
const TEST_ERRORS = [
  'dns_error',
  'connect_error',
  'tls_error',
  'timeout',
  'http_status',
  'invalid_document',
  'issuer_mismatch',
  'missing_endpoint',
  'internal_error',
] as const;

/** Translation key of a stage of the test; a stage added by a later server is "unknown". */
export function ssoStageKey(stage: string): string {
  return `adminTenants.sso.test.stages.${(STAGES as readonly string[]).includes(stage) ? stage : 'unknown'}`;
}

/** Translation key of an error category of the test; an unknown category is "unknown". */
export function ssoTestErrorKey(error: string): string {
  return `adminTenants.sso.test.errors.${(TEST_ERRORS as readonly string[]).includes(error) ? error : 'unknown'}`;
}

/** What the screen shows of a test result: only translated text, never a remote message. */
export interface SsoTestView {
  success: boolean;
  /** Result summary. */
  summary: string;
  /** Stage reached or failed. */
  stage: string;
  /** Category of the failure, absent on success. */
  error: string | undefined;
}

/** View of a test result. */
export function ssoTestView(result: SsoTestResult, t: Translate): SsoTestView {
  return {
    success: result.success,
    summary: t(result.success ? 'adminTenants.sso.test.success' : 'adminTenants.sso.test.failure', {
      ms: result.durationMs,
    }),
    stage: t(ssoStageKey(result.stage)),
    error: result.error === undefined ? undefined : t(ssoTestErrorKey(result.error)),
  };
}
