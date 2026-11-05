// Logic of the export and import of a tenant configuration (since 2.0), kept out of the screens
// (TenantGeneral, TenantImport) so that it is unit tested in Node.
//
// - Export: GET /admin/tenants/{id}/export is downloaded through a plain same-origin link (the
//   session cookie travels with the navigation; the answer is an attachment).
// - Import: the configuration comes from a JSON file chosen by the super admin, or from the
//   export of an existing tenant (duplication, ?from=<tenantId>). The file is parsed in the
//   browser only to be sent as the config of POST /admin/tenants/import: the server validates
//   it strictly and reports the first error as a JSON pointer.
import type { components } from '../../../shared/api/schema';
import type { ErrorView } from '../../../shared/api/problem';
import type { FieldRef, SubmitOutcome } from '../../components/form';
import {
  delegatedLanguage,
  normalizeFqdn,
  tenantFailure,
  type DelegatedFieldRefs,
  type DelegatedForm,
  type Language,
  type Translate,
  type TenantFieldRefs,
} from './tenants';

/** Exported configuration of a tenant (the config of an import). */
export type TenantConfigExport = components['schemas']['TenantConfigExport'];

/** Body of a tenant import. */
export type TenantImportBody = components['schemas']['TenantImport'];

/** Largest configuration file accepted (the server limit of the import body, 32 MiB). */
export const MAX_IMPORT_FILE_BYTES = 32 * 1024 * 1024;

/** Base path of the API, as used by the API client. */
const API_BASE = '/api/v1';

/**
 * URL of the export of a tenant, to use as the href of a download link. The branding files
 * (logo, background image) are included only on request.
 */
export function exportUrl(tenantId: string, includeBranding: boolean): string {
  return `${API_BASE}/admin/tenants/${encodeURIComponent(tenantId)}/export?includeBranding=${includeBranding ? 'true' : 'false'}`;
}

/** Application path of the import screen; with a tenant id, it duplicates that tenant. */
export function importPath(fromTenantId?: string): string {
  return fromTenantId === undefined
    ? '/tenants/import'
    : `/tenants/import?from=${encodeURIComponent(fromTenantId)}`;
}

/** Id of the tenant to duplicate, from the query string of the import screen (undefined: none). */
export function duplicateSource(search: string): string | undefined {
  const from = new URLSearchParams(search).get('from');
  return from === null || from === '' ? undefined : from;
}

/** Why a configuration file is refused before being sent. */
export type ConfigFileProblem = 'too-large' | 'not-json' | 'not-an-object';

/** Result of the reading of a configuration file. */
export type ParsedConfig =
  { ok: true; config: TenantConfigExport } | { ok: false; problem: ConfigFileProblem };

/** Reports whether a file is too large to be a configuration file (before reading it). */
export function configFileTooLarge(size: number): boolean {
  return size > MAX_IMPORT_FILE_BYTES;
}

/**
 * Parses the text of a configuration file: it must be a JSON object. Its content is not checked
 * further (the server does it, strictly, and locates the first error).
 */
export function parseConfigText(text: string): ParsedConfig {
  let value: unknown;
  try {
    // A byte order mark (editors on Windows) is not part of the JSON text.
    value = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    return { ok: false, problem: 'not-json' };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { ok: false, problem: 'not-an-object' };
  }
  return { ok: true, config: value as TenantConfigExport };
}

/** Message of a file problem. */
export function configFileMessage(problem: ConfigFileProblem, t: Translate): string {
  return t(`adminTenants.import.file.errors.${problem}`);
}

/** Fields of the import form (a subset of the tenant form). */
export interface ImportForm {
  name: string;
  fqdn: string;
  storageQuotaBytes: number | null;
}

/** Empty import form. */
export function emptyImportForm(storageQuotaBytes: number | null = null): ImportForm {
  return { name: '', fqdn: '', storageQuotaBytes };
}

/**
 * Default language of the new tenant for the mail of its first administrator: the language of
 * the configuration when it holds one, else the interface language.
 */
export function configLanguage(config: TenantConfigExport | undefined, fallback: Language): Language {
  return config?.settings?.defaultLanguage ?? fallback;
}

/**
 * Body of an import; undefined while the quota is missing (validation reports it). The first
 * administrator is created together with the tenant when enabled.
 */
export function importBody(
  form: ImportForm,
  config: TenantConfigExport,
  delegated: DelegatedForm | undefined,
  defaultLanguage: Language,
): TenantImportBody | undefined {
  if (form.storageQuotaBytes === null) {
    return undefined;
  }
  return {
    name: form.name.trim(),
    fqdn: normalizeFqdn(form.fqdn),
    storageQuotaBytes: form.storageQuotaBytes,
    config,
    ...(delegated?.enabled === true
      ? {
          delegatedAdmin: {
            username: delegated.username.trim(),
            email: delegated.email.trim(),
            language: delegatedLanguage(delegated, defaultLanguage),
            delivery: delegated.delivery,
          },
        }
      : {}),
  };
}

/**
 * Location of an import error for a person: the JSON pointer of the server ("/config/network/
 * internalCidrs/3", decoded) or, for another notation, the field as is.
 */
export function errorLocation(field: string): string {
  if (!field.startsWith('/')) {
    return field;
  }
  return field
    .split('/')
    .map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
    .join('/');
}

/**
 * Outcome of a failed import:
 * - 422 import-invalid: "Error in the file at <location>" (the first error), on the file field
 *   when there is one (the file picker), else as a general message (duplication);
 * - 422 import-schema-unsupported, 413: the message of the code, same placement;
 * - anything else (409 on the FQDN, 400 field errors, 503 system SMTP...): tenantFailure.
 * rawField is the field of the first entry of the problem (errors[0].field), if any.
 */
export function importFailure(
  view: ErrorView,
  rawField: string | undefined,
  refs: TenantFieldRefs,
  t: Translate,
  opts: { file?: FieldRef | undefined; delegatedRefs?: DelegatedFieldRefs | undefined } = {},
): SubmitOutcome {
  let message: string | undefined;
  if (view.code === 'import-invalid') {
    message =
      rawField === undefined || rawField === ''
        ? view.message
        : t('adminTenants.import.errors.location', { location: errorLocation(rawField) });
  } else if (view.code === 'import-schema-unsupported' || view.status === 413) {
    message = view.message;
  }
  if (message !== undefined) {
    return opts.file === undefined
      ? { ok: false, message }
      : { ok: false, errors: [{ id: opts.file.id, label: opts.file.label, message }] };
  }
  return tenantFailure(
    view,
    refs,
    t,
    opts.delegatedRefs === undefined ? undefined : { refs: opts.delegatedRefs },
  );
}

/** Webhooks noted in a configuration (for information; they are not recreated by an import). */
export function webhookCount(config: TenantConfigExport | undefined): number {
  return config?.webhooks?.length ?? 0;
}
