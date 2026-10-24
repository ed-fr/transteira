// Start-up of the public application: tenant configuration (GET /tenant) and interface
// language (CLAUDE.md section 14). Browser objects and the API are injected so that the logic
// is unit tested in Node.
//
// The language is chosen twice: first among every language the interface ships (stored choice,
// then browser languages), so that GET /tenant is asked in the right Accept-Language and an
// error page can be translated; then among the languages the tenant offers. When the second
// choice differs, the tenant is fetched again to get its texts (maintenance message) in that
// language.
import type { components } from '../shared/api/schema';
import { pickInitialLanguage, type LanguageStorage } from '../shared/i18n/language';

/** Public configuration of the current tenant. */
export type PublicTenant = components['schemas']['PublicTenant'];

/** Legal document of a tenant. */
export type LegalDocumentName = PublicTenant['legalDocuments'][number];

/** Dependencies of the start-up. */
export interface BootstrapDeps {
  /** GET /tenant in the current language. */
  fetchTenant(): Promise<PublicTenant>;
  /** Loads and activates a language; resolves to the language applied. */
  setLocale(lang: string): Promise<string>;
  /** Languages the interface ships translations for. */
  supported: readonly string[];
  /** Language used when nothing else matches. */
  fallback: string;
  /** Browser preferred languages (navigator.languages). */
  browserLanguages?: readonly string[];
  /** Storage of the language picked by the user. */
  storage?: LanguageStorage | undefined;
}

/**
 * Activates a first language guess (without the tenant). Resolves to the language applied.
 * Used before GET /tenant and for the start-up error page.
 */
export function guessLanguage(deps: BootstrapDeps): Promise<string> {
  return deps.setLocale(
    pickInitialLanguage({
      available: deps.supported,
      tenantLanguage: deps.fallback,
      browserLanguages: deps.browserLanguages,
      storage: deps.storage,
    }),
  );
}

/** Loads the tenant and the interface language; rejects when GET /tenant fails. */
export async function bootstrapTenant(deps: BootstrapDeps): Promise<PublicTenant> {
  const guessed = await guessLanguage(deps);
  let tenant = await deps.fetchTenant();
  const applied = await deps.setLocale(
    pickInitialLanguage({
      available: tenant.availableLanguages,
      tenantLanguage: tenant.language,
      browserLanguages: deps.browserLanguages,
      storage: deps.storage,
    }),
  );
  if (applied !== guessed) {
    tenant = await deps.fetchTenant();
  }
  return tenant;
}

/** Path of a legal document page. */
export function legalPath(document: LegalDocumentName): string {
  return `/legal/${document}`;
}

/** Reports whether a value names a legal document the tenant publishes. */
export function isPublishedLegalDocument(
  tenant: Pick<PublicTenant, 'legalDocuments'>,
  document: string,
): document is LegalDocumentName {
  return (tenant.legalDocuments as readonly string[]).includes(document);
}

/**
 * Maintenance message to display with the language it is written in (lang attribute, RGAA 8.7;
 * undefined without message), or undefined when maintenance is off.
 */
export function maintenanceNotice(
  tenant: Pick<PublicTenant, 'maintenance' | 'maintenanceMessage' | 'maintenanceMessageLanguage'>,
): { message: string | undefined; language: string | undefined } | undefined {
  if (!tenant.maintenance) {
    return undefined;
  }
  const message = tenant.maintenanceMessage?.trim();
  if (message === undefined || message === '') {
    return { message: undefined, language: undefined };
  }
  return { message, language: tenant.maintenanceMessageLanguage };
}

/** Document title: "<page> – <site>", or the page alone when the site name is unknown. */
export function documentTitle(page: string, site: string | undefined): string {
  return site === undefined || site === '' || site === page ? page : `${page} – ${site}`;
}
