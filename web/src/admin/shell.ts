// Pure helpers of the admin application shell (App.svelte, AdminShell, Sidebar and its tenant and
// system blocks): initial language (plan D5), aria-current of the navigation links, links of the
// tenant and system navigations, the model of the sidebar (CLAUDE.md section 13.2) and the
// redirect decided by the navigation guard.
import type { IconName } from '../shared/components/icons';
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
  'setup',
  'general',
  'branding',
  'network',
  'recipientRules',
  'abuse',
  'confidentiality',
  'secretSettings',
  'smtp',
  'sso',
  'templates',
  'legal',
] as const;

/** Sections of the operation of a tenant (group "operations"), in navigation order. */
export const TENANT_OPS_SECTIONS = [
  'transfers',
  'invitations',
  'blocklist',
  'abuseReports',
  'tokens',
  'dropLinks',
  'secrets',
  'webhooks',
  'audit',
  'security',
  'stats',
  'privacy',
] as const;

/** Sections of a tenant, in navigation order: configuration, then operations. */
export const TENANT_SECTIONS = [...TENANT_CONFIG_SECTIONS, ...TENANT_OPS_SECTIONS] as const;

/** A section of a tenant. */
export type TenantSection = (typeof TENANT_SECTIONS)[number];

/**
 * Sections of a tenant an auditor (read-only role) may open, in navigation order: the summary
 * (the general view, read-only), the single sign-on configuration (read-only), the transfers, the
 * audit log, the security log and the statistics. No configuration section.
 */
export const AUDITOR_TENANT_SECTIONS = [
  'general',
  'sso',
  'transfers',
  'dropLinks',
  'secrets',
  'audit',
  'security',
  'stats',
] as const satisfies readonly TenantSection[];

/** A group of the tenant navigation ("consultation": the single group of an auditor). */
export type TenantSectionGroup = 'configuration' | 'operations' | 'consultation';

/** Role of an admin (AdminMe.role), undefined while the profile is not known. */
export type NavRole = AdminMe['role'] | undefined;

/** Reports whether a role is the read-only auditor. */
export function isAuditor(role: NavRole): boolean {
  return role === 'auditor';
}

/** Groups of the tenant navigation, in order, with their sections and heading key. */
export const TENANT_SECTION_GROUPS: readonly {
  group: TenantSectionGroup;
  labelKey: string;
  sections: readonly TenantSection[];
}[] = [
  { group: 'configuration', labelKey: 'adminOps.nav.groupConfiguration', sections: TENANT_CONFIG_SECTIONS },
  { group: 'operations', labelKey: 'adminOps.nav.groupOperations', sections: TENANT_OPS_SECTIONS },
];

/** A link of the tenant navigation. */
export interface TenantLink {
  section: TenantSection;
  /** Group of the section. */
  group: TenantSectionGroup;
  /** Application path, for example "/tenants/ten_1/branding". */
  path: string;
  /** Translation key of the link text (adminTenants.nav.* or adminOps.nav.*). */
  labelKey: string;
}

/** A titled group of links of the tenant navigation. */
export interface TenantLinkGroup {
  group: TenantSectionGroup;
  /** Translation key of the group heading. */
  labelKey: string;
  links: TenantLink[];
}

/** Path segment of the sections whose segment differs from their name. */
const TENANT_SEGMENTS: Partial<Record<TenantSection, string>> = {
  recipientRules: 'recipient-rules',
  abuseReports: 'abuse-reports',
  dropLinks: 'drop-links',
  secretSettings: 'secret-settings',
  security: 'security-events',
};

/** Path segment of a section of a tenant. */
export function tenantSegment(section: TenantSection): string {
  return TENANT_SEGMENTS[section] ?? section;
}

/** Application path of a section of a tenant (the id is percent-encoded). */
export function tenantPath(tenantId: string, section: TenantSection): string {
  return `/tenants/${encodeURIComponent(tenantId)}/${tenantSegment(section)}`;
}

/** Group of a section. */
export function sectionGroup(section: TenantSection): TenantSectionGroup {
  return (TENANT_OPS_SECTIONS as readonly string[]).includes(section) ? 'operations' : 'configuration';
}

/**
 * Links of the tenant navigation, in order. An auditor only gets the sections it may open
 * (AUDITOR_TENANT_SECTIONS), all in the "consultation" group, and its general view is labelled
 * "Summary" (it is read-only).
 */
export function tenantLinks(tenantId: string, role?: NavRole): TenantLink[] {
  if (isAuditor(role)) {
    return AUDITOR_TENANT_SECTIONS.map((section) => ({
      section,
      group: 'consultation' as const,
      path: tenantPath(tenantId, section),
      labelKey: section === 'general' ? 'adminTenants.nav.summary' : navLabelKey(section),
    }));
  }
  return TENANT_SECTIONS.map((section) => ({
    section,
    group: sectionGroup(section),
    path: tenantPath(tenantId, section),
    labelKey: navLabelKey(section),
  }));
}

function navLabelKey(section: TenantSection): string {
  return `${sectionGroup(section) === 'operations' ? 'adminOps' : 'adminTenants'}.nav.${section}`;
}

/** Links of the tenant navigation, by group (the sidebar renders one titled list each). */
export function tenantLinkGroups(tenantId: string, role?: NavRole): TenantLinkGroup[] {
  const links = tenantLinks(tenantId, role);
  if (isAuditor(role)) {
    return [{ group: 'consultation', labelKey: 'adminOps.nav.groupConsultation', links }];
  }
  return TENANT_SECTION_GROUPS.map(({ group, labelKey }) => ({
    group,
    labelKey,
    links: links.filter((link) => link.group === group),
  }));
}

/** Entry of the main navigation. */
export type MainEntryId = 'home' | 'tenants' | 'admins' | 'system' | 'account';

/** A link of the main navigation. */
export interface MainLink {
  /** Entry of the navigation. */
  id: MainEntryId;
  path: string;
  /** Translation key of the link text (admin.nav.*). */
  key: string;
  /** Decorative icon of the sidebar link (Icon.svelte). */
  icon: IconName;
}

/**
 * Links of the main navigation: home, entities and My account for every role, plus the
 * administrators and the system administration for a super admin.
 */
export function mainLinks(role: NavRole): MainLink[] {
  const items: MainLink[] = [
    { id: 'home', path: '/', key: 'admin.nav.home', icon: 'home' },
    { id: 'tenants', path: '/tenants', key: 'admin.nav.tenants', icon: 'grid' },
  ];
  if (role === 'super_admin') {
    items.push({ id: 'admins', path: '/admins', key: 'admin.nav.admins', icon: 'users' });
    items.push({ id: 'system', path: systemPath('overview'), key: 'admin.nav.system', icon: 'settings' });
  }
  items.push({ id: 'account', path: '/account', key: 'admin.nav.account', icon: 'user' });
  return items;
}

/** Sections of the system administration (super admin), in navigation order. */
export const SYSTEM_SECTIONS = [
  'overview',
  'maintenance',
  'settings',
  'webhooks',
  'audit',
  'security',
  'masterKey',
  'provisioning',
] as const;

/** A section of the system administration. */
export type SystemSection = (typeof SYSTEM_SECTIONS)[number];

/** A link of the system navigation. */
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
  webhooks: '/webhooks',
  audit: '/audit',
  security: '/security-events',
  masterKey: '/master-key',
  provisioning: '/provisioning-tokens',
};

/** Application path of a section of the system administration ("/system" for the overview). */
export function systemPath(section: SystemSection): string {
  return `/system${SYSTEM_SEGMENTS[section]}`;
}

/** Links of the system navigation, in order. */
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
 * Reports whether a screen is shown in the signed-in frame of AdminShell (sidebar, then the
 * screen on the muted page background, its content in cards) rather than inside the card of
 * PageLayout (setup, sign-in, activation, and a visitor not signed in on a screen any visitor can
 * open: help, not found). The condition of AdminShell, for the screens App.svelte renders.
 */
export function inAdminFrame(session: {
  readonly state: { readonly kind: string };
  readonly me: AdminMe | undefined;
}): boolean {
  return session.state.kind === 'authenticated' && session.me !== undefined;
}

// ---- Sidebar (CLAUDE.md section 13.2) -----------------------------------------------------------

/** A link of the sidebar with its aria-current for the page shown. */
export interface SidebarLink {
  path: string;
  /** Translation key of the link text. */
  labelKey: string;
  current: AriaCurrent;
}

/** A group of the tenant block: a disclosure button over a list of links. */
export interface SidebarGroup {
  group: TenantSectionGroup;
  /** Translation key of the group heading (text of its disclosure button). */
  labelKey: string;
  links: (SidebarLink & { section: TenantSection })[];
  /** The group holds the link of the page shown (or of its parent section). */
  holdsCurrent: boolean;
}

/** Tenant block of the sidebar, nested under the "Entities" entry. */
export interface SidebarTenantBlock {
  tenantId: string;
  /** Name of the tenant (from the profile). */
  name: string;
  /** Shown on every page because the admin has a single tenant (pinnedTenantId). */
  pinned: boolean;
  groups: SidebarGroup[];
}

/** System block of the sidebar (super admin), nested under the "System" entry. */
export interface SidebarSystemBlock {
  links: (SidebarLink & { section: SystemSection })[];
}

/** An entry of the main navigation of the sidebar, with its nested block if any. */
export interface SidebarEntry extends MainLink {
  /**
   * aria-current of the entry: navCurrent of its path, except that an entry whose nested block
   * holds the exact page ("page") is marked "true" (the system overview is "/system" too).
   */
  current: AriaCurrent;
  /** Tenant block, only on the "tenants" entry. */
  tenant?: SidebarTenantBlock;
  /** System block, only on the "system" entry. */
  system?: SidebarSystemBlock;
}

/** Model of the sidebar navigation. */
export interface SidebarModel {
  entries: SidebarEntry[];
}

/**
 * Tenant whose block the sidebar shows on every page: the single tenant of an admin who has
 * exactly one (any role), otherwise undefined.
 */
export function pinnedTenantId(me: AdminMe | undefined): string | undefined {
  return me !== undefined && me.tenants.length === 1 ? me.tenants[0]?.id : undefined;
}

/**
 * Model of the sidebar for the page shown:
 * - the main entries (mainLinks of the role) with their icon and aria-current;
 * - under "Entities", the block of the tenant of the page (tenantId, the :id of a tenant route),
 *   only when that tenant is in the scope of the admin (me.tenants), otherwise the block of the
 *   pinned tenant (pinnedTenantId); its groups are those of tenantLinkGroups (Configuration and
 *   Operations, or the single Consultation group of an auditor);
 * - under "System", the system block on the system pages (inSystem) of a super admin.
 * Without a profile, the main entries of an unknown role and no block.
 */
export function sidebarModel(
  me: AdminMe | undefined,
  path: string,
  tenantId: string | undefined,
  inSystem: boolean,
): SidebarModel {
  const role = me?.role;
  const tenant = tenantBlock(me, path, tenantId);
  const system = inSystem && role === 'super_admin' ? systemBlock(path) : undefined;
  const entries = mainLinks(role).map((link): SidebarEntry => {
    const nested = link.id === 'tenants' ? tenant : link.id === 'system' ? system : undefined;
    const entry: SidebarEntry = {
      ...link,
      current: entryCurrent(navCurrent(path, link.path), nested !== undefined && holdsPage(nested)),
    };
    if (link.id === 'tenants' && tenant !== undefined) {
      entry.tenant = tenant;
    }
    if (link.id === 'system' && system !== undefined) {
      entry.system = system;
    }
    return entry;
  });
  return { entries };
}

function entryCurrent(current: AriaCurrent, nestedPage: boolean): AriaCurrent {
  return current === 'page' && nestedPage ? 'true' : current;
}

function holdsPage(block: SidebarTenantBlock | SidebarSystemBlock): boolean {
  const links = 'groups' in block ? block.groups.flatMap((g) => g.links) : block.links;
  return links.some((link) => link.current === 'page');
}

function tenantBlock(
  me: AdminMe | undefined,
  path: string,
  tenantId: string | undefined,
): SidebarTenantBlock | undefined {
  if (me === undefined) {
    return undefined;
  }
  const pinned = pinnedTenantId(me);
  const inScope = tenantId !== undefined && me.tenants.some((t) => t.id === tenantId);
  const id = inScope ? tenantId : pinned;
  const name = tenantNameOf(me, id);
  if (id === undefined || name === undefined) {
    return undefined;
  }
  const groups = tenantLinkGroups(id, me.role).map((group): SidebarGroup => {
    const links = group.links.map((link) => ({
      section: link.section,
      path: link.path,
      labelKey: link.labelKey,
      current: navCurrent(path, link.path),
    }));
    return {
      group: group.group,
      labelKey: group.labelKey,
      links,
      holdsCurrent: links.some((link) => link.current !== undefined),
    };
  });
  return { tenantId: id, name, pinned: id === pinned, groups };
}

function systemBlock(path: string): SidebarSystemBlock {
  return {
    links: systemLinks().map((link) => ({
      section: link.section,
      path: link.path,
      labelKey: link.labelKey,
      current: navCurrent(path, link.path, link.exact),
    })),
  };
}

/**
 * Collapsed groups of the tenant block. The groups are open by default; the state lives in the
 * memory of the sidebar only, never in a browser storage (plan deviation 9, i18n.spec.ts).
 */
export type CollapsedGroups = ReadonlySet<TenantSectionGroup>;

/** Reports whether a group is open. */
export function isGroupOpen(collapsed: CollapsedGroups, group: TenantSectionGroup): boolean {
  return !collapsed.has(group);
}

/** Opens a collapsed group, collapses an open one (a new set). */
export function toggleGroup(collapsed: CollapsedGroups, group: TenantSectionGroup): CollapsedGroups {
  const next = new Set(collapsed);
  if (!next.delete(group)) {
    next.add(group);
  }
  return next;
}

/**
 * Opens the groups that hold the page shown (called on each navigation): the group of the
 * current page is always open when the page is reached; the admin may still collapse it then.
 * Returns the same set when nothing changes.
 */
export function revealCurrentGroups(
  collapsed: CollapsedGroups,
  groups: readonly Pick<SidebarGroup, 'group' | 'holdsCurrent'>[],
): CollapsedGroups {
  const hidden = groups.filter((g) => g.holdsCurrent && collapsed.has(g.group));
  if (hidden.length === 0) {
    return collapsed;
  }
  const next = new Set(collapsed);
  for (const g of hidden) {
    next.delete(g.group);
  }
  return next;
}

/**
 * Whether a key closes the menu of narrow screens (the sidebar "Menu" button): Escape, while the
 * menu is open and the focus is in the sidebar, on its "Menu" button (just opened with the
 * keyboard) or in its panel. Escape pressed elsewhere (e.g. in a dialog of the screen) is left to
 * that element.
 */
export function closesSidebarMenu(key: string, open: boolean, focusInSidebar: boolean): boolean {
  return key === 'Escape' && open && focusInSidebar;
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
 * The single definition, used by the sidebar, the account page and the admin accounts screens.
 */
export function roleKey(role: string | undefined): string {
  return role === 'super_admin' || role === 'delegated_admin' || role === 'auditor'
    ? `admin.role.${role}`
    : 'admin.role.unknown';
}

/**
 * Whether the role may search the tenant lists by e-mail address (the email filter of the transfer
 * list, the actor filter of the audit log). Since 2.0 the auditor may not (T-282, 403
 * read-only-role): its screens hide these inputs. A missing or unknown role may not either.
 */
export function canSearchByAddress(role: string | undefined): boolean {
  return role === 'super_admin' || role === 'delegated_admin';
}
