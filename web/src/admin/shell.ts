// Pure helpers of the admin application shell (App.svelte, AdminLayout, TenantNav): initial
// language (plan D5), aria-current of the navigation links, links of the tenant sub-navigation
// and the redirect decided by the navigation guard.
import type { AccessDecision } from './auth/guard';
import type { AdminMe } from './auth/machine';

/** Language used when nothing else applies. */
export const DEFAULT_ADMIN_LANGUAGE = 'en';

/** Inputs of the admin language choice. */
export interface AdminLanguageContext {
  /** Languages the interface ships translations for. */
  available: readonly string[];
  /** Language picked earlier on this browser (localStorage "tt.lang"). */
  stored?: string | undefined;
  /** Language of the admin profile (AdminMe.language), once known. */
  meLanguage?: string | undefined;
  /** Browser preferred languages (navigator.languages), most preferred first. */
  browserLanguages?: readonly string[];
}

/**
 * Picks the admin interface language: the stored choice, then the language of the profile,
 * then the first browser language offered, then English. Values not offered are skipped.
 */
export function pickAdminLanguage(ctx: AdminLanguageContext): string {
  for (const candidate of [ctx.stored, ctx.meLanguage]) {
    if (candidate !== undefined && ctx.available.includes(candidate)) {
      return candidate;
    }
  }
  for (const tag of ctx.browserLanguages ?? []) {
    const primary = tag.toLowerCase().split('-')[0] ?? '';
    if (ctx.available.includes(primary)) {
      return primary;
    }
  }
  return ctx.available.includes(DEFAULT_ADMIN_LANGUAGE)
    ? DEFAULT_ADMIN_LANGUAGE
    : (ctx.available[0] ?? DEFAULT_ADMIN_LANGUAGE);
}

/** Value of aria-current for a navigation link. */
export type AriaCurrent = 'page' | 'true' | undefined;

/**
 * aria-current of a link to target while path is shown: "page" on the exact page, "true" on a
 * page below it (a section link stays marked on its sub-pages, except the root "/"), otherwise
 * undefined.
 */
export function navCurrent(path: string, target: string): AriaCurrent {
  const here = trimSlash(path);
  const to = trimSlash(target);
  if (here === to) {
    return 'page';
  }
  return to !== '/' && here.startsWith(`${to}/`) ? 'true' : undefined;
}

function trimSlash(path: string): string {
  return path.replace(/\/+$/, '') || '/';
}

/** Sections of the configuration of a tenant, in navigation order. */
export const TENANT_SECTIONS = ['general', 'branding', 'network', 'smtp', 'templates', 'legal'] as const;

/** A section of the configuration of a tenant. */
export type TenantSection = (typeof TENANT_SECTIONS)[number];

/** A link of the tenant sub-navigation. */
export interface TenantLink {
  section: TenantSection;
  /** Application path, for example "/tenants/ten_1/branding". */
  path: string;
  /** Translation key of the link text. */
  labelKey: string;
}

/** Application path of a section of a tenant (the id is percent-encoded). */
export function tenantPath(tenantId: string, section: TenantSection): string {
  return `/tenants/${encodeURIComponent(tenantId)}/${section}`;
}

/** Links of the tenant sub-navigation. */
export function tenantLinks(tenantId: string): TenantLink[] {
  return TENANT_SECTIONS.map((section) => ({
    section,
    path: tenantPath(tenantId, section),
    labelKey: `adminTenants.nav.${section}`,
  }));
}

/** Name of a tenant of the profile (every tenant for a super admin), undefined when unknown. */
export function tenantNameOf(me: AdminMe | undefined, tenantId: string | undefined): string | undefined {
  if (me === undefined || tenantId === undefined) {
    return undefined;
  }
  return me.tenants.find((tenant) => tenant.id === tenantId)?.name;
}

/**
 * Path to navigate to (history replace) for a guard decision, or undefined when nothing has to
 * change: not a redirect, or a redirect to the page already shown (never loops).
 */
export function redirectTarget(decision: AccessDecision, current: string): string | undefined {
  if (decision.kind !== 'redirect' || decision.to === current) {
    return undefined;
  }
  return decision.to;
}

/**
 * Translation key of a role name (admin.role.<role>, or "unknown" for a future or missing role).
 * The single definition, used by the layout, the account page and the admin accounts screens.
 */
export function roleKey(role: string | undefined): string {
  return role === 'super_admin' || role === 'delegated_admin' ? `admin.role.${role}` : 'admin.role.unknown';
}
