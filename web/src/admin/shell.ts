// Pure helpers of the admin application shell (App.svelte, AdminLayout, TenantNav, SystemNav):
// initial language (plan D5), aria-current of the navigation links, links of the tenant and
// system sub-navigations and the redirect decided by the navigation guard.
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
 * undefined. With exact, only the exact page is marked (a link to a parent path that is itself a
 * sibling section, such as the system overview "/system" next to "/system/maintenance").
 */
export function navCurrent(path: string, target: string, exact = false): AriaCurrent {
  const here = trimSlash(path);
  const to = trimSlash(target);
  if (here === to) {
    return 'page';
  }
  return !exact && to !== '/' && here.startsWith(`${to}/`) ? 'true' : undefined;
}

function trimSlash(path: string): string {
  return path.replace(/\/+$/, '') || '/';
}

/** Sections of the configuration of a tenant (group "configuration"), in navigation order. */
export const TENANT_CONFIG_SECTIONS = [
  'general',
  'branding',
  'network',
  'smtp',
  'templates',
  'legal',
] as const;

/** Sections of the operation of a tenant (group "operations"), in navigation order. */
export const TENANT_OPS_SECTIONS = [
  'transfers',
  'invitations',
  'blocklist',
  'tokens',
  'audit',
  'stats',
  'privacy',
] as const;

/** Sections of a tenant, in navigation order: configuration, then operations. */
export const TENANT_SECTIONS = [...TENANT_CONFIG_SECTIONS, ...TENANT_OPS_SECTIONS] as const;

/** A section of a tenant. */
export type TenantSection = (typeof TENANT_SECTIONS)[number];

/** A group of the tenant sub-navigation. */
export type TenantSectionGroup = 'configuration' | 'operations';

/** Groups of the tenant sub-navigation, in order, with their sections and heading key. */
export const TENANT_SECTION_GROUPS: readonly {
  group: TenantSectionGroup;
  labelKey: string;
  sections: readonly TenantSection[];
}[] = [
  { group: 'configuration', labelKey: 'adminOps.nav.groupConfiguration', sections: TENANT_CONFIG_SECTIONS },
  { group: 'operations', labelKey: 'adminOps.nav.groupOperations', sections: TENANT_OPS_SECTIONS },
];

/** A link of the tenant sub-navigation. */
export interface TenantLink {
  section: TenantSection;
  /** Group of the section. */
  group: TenantSectionGroup;
  /** Application path, for example "/tenants/ten_1/branding". */
  path: string;
  /** Translation key of the link text (adminTenants.nav.* or adminOps.nav.*). */
  labelKey: string;
}

/** A titled group of links of the tenant sub-navigation. */
export interface TenantLinkGroup {
  group: TenantSectionGroup;
  /** Translation key of the group heading. */
  labelKey: string;
  links: TenantLink[];
}

/** Application path of a section of a tenant (the id is percent-encoded). */
export function tenantPath(tenantId: string, section: TenantSection): string {
  return `/tenants/${encodeURIComponent(tenantId)}/${section}`;
}

/** Group of a section. */
export function sectionGroup(section: TenantSection): TenantSectionGroup {
  return (TENANT_OPS_SECTIONS as readonly string[]).includes(section) ? 'operations' : 'configuration';
}

/** Links of the tenant sub-navigation, in order (every group). */
export function tenantLinks(tenantId: string): TenantLink[] {
  return TENANT_SECTIONS.map((section) => {
    const group = sectionGroup(section);
    return {
      section,
      group,
      path: tenantPath(tenantId, section),
      labelKey: `${group === 'operations' ? 'adminOps' : 'adminTenants'}.nav.${section}`,
    };
  });
}

/** Links of the tenant sub-navigation, by group (TenantNav renders one titled list each). */
export function tenantLinkGroups(tenantId: string): TenantLinkGroup[] {
  const links = tenantLinks(tenantId);
  return TENANT_SECTION_GROUPS.map(({ group, labelKey }) => ({
    group,
    labelKey,
    links: links.filter((link) => link.group === group),
  }));
}

/** Sections of the system administration (super admin), in navigation order. */
export const SYSTEM_SECTIONS = ['overview', 'maintenance', 'settings', 'audit', 'masterKey'] as const;

/** A section of the system administration. */
export type SystemSection = (typeof SYSTEM_SECTIONS)[number];

/** A link of the system sub-navigation. */
export interface SystemLink {
  section: SystemSection;
  /** Application path, for example "/system/maintenance". */
  path: string;
  /** Translation key of the link text (adminSystem.nav.*). */
  labelKey: string;
  /** Marks the link only on its exact page (navCurrent exact): the overview is the parent path. */
  exact: boolean;
}

const SYSTEM_SEGMENTS: Record<SystemSection, string> = {
  overview: '',
  maintenance: '/maintenance',
  settings: '/settings',
  audit: '/audit',
  masterKey: '/master-key',
};

/** Application path of a section of the system administration ("/system" for the overview). */
export function systemPath(section: SystemSection): string {
  return `/system${SYSTEM_SEGMENTS[section]}`;
}

/** Links of the system sub-navigation, in order. */
export function systemLinks(): SystemLink[] {
  return SYSTEM_SECTIONS.map((section) => ({
    section,
    path: systemPath(section),
    labelKey: `adminSystem.nav.${section}`,
    exact: section === 'overview',
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
