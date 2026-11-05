// Logic of the admin accounts screens (AdminList, AdminCreate, AdminEdit; CLAUDE.md section 6.5),
// kept out of the components so that it is unit tested in Node: row view models, status of an
// account, forms and their client-side validation, merge patch of an update, actions offered on
// an account (none of the dangerous ones on one's own account) and contextual messages of the
// 409 state-conflict answers, which carry no reason: the reason is deduced from the action and
// from the state of the account.
import type { components } from '../../../shared/api/schema';
import { buildPatch, deepEqual } from '../../forms/patch';
import { roleKey } from '../../shell';

// Translation key of a role name: defined once in shell.ts, re-exported for the screens.
export { roleKey };

/** An admin account (GET /admin/admins/{adminId}). */
export type Admin = components['schemas']['Admin'];
/** An admin account with its single-use activation link (create, reset credentials). */
export type AdminWithActivation = components['schemas']['AdminWithActivation'];
/**
 * Answer of POST /admin/admins (since API 1.2): the account and how its activation link was
 * delivered; the link itself only with the copy delivery.
 */
export type AdminCreated = components['schemas']['AdminCreated'];
/** Body of POST /admin/admins. */
export type AdminCreate = components['schemas']['AdminCreate'];
/** Merge patch of PATCH /admin/admins/{adminId}. */
export type AdminUpdate = components['schemas']['AdminUpdate'];
/** Role of an admin account. */
export type AdminRole = components['schemas']['AdminRole'];

/** Translation function. */
export type Translate = (key: string, params?: Record<string, string | number>) => string;

/** An activation link, shown once (threat model T-162: kept in component memory only). */
export interface ActivationLink {
  url: string;
  expiresAt: string;
}

/**
 * Splits an answer of createAdmin or resetAdminCredentials into the account, without the link,
 * and the link, so that the account can be kept in the screen state without the secret.
 */
export function splitActivation(data: AdminWithActivation): { account: Admin; link: ActivationLink } {
  const { activationUrl, activationExpiresAt, ...account } = data;
  return { account, link: { url: activationUrl, expiresAt: activationExpiresAt } };
}

/** Delivery of an activation link: mailed through the system SMTP, or shown to copy. */
export type InvitationDelivery = components['schemas']['InvitationDelivery'];
/** Language of the invitation mail. */
export type InvitationLanguage = components['schemas']['Language'];
/** Body of POST /admin/admins/{adminId}/invite and member `invitation` of AdminCreate. */
export type AdminInvitation = components['schemas']['AdminInvitation'];

/** Languages offered for the invitation mail. */
export const INVITATION_LANGUAGES: readonly InvitationLanguage[] = ['fr', 'en'];

/** The language of a select value, or the fallback when it is not an offered language. */
export function asInvitationLanguage(value: string, fallback: InvitationLanguage): InvitationLanguage {
  return INVITATION_LANGUAGES.find((code) => code === value) ?? fallback;
}

/** Default language of the invitation mail: the interface language when offered, else English. */
export function defaultInvitationLanguage(uiLanguage: string): InvitationLanguage {
  return uiLanguage === 'fr' ? 'fr' : 'en';
}

/**
 * Invitation member of a request: the mail delivery carries the language of the mail, the copy
 * delivery nothing (the language is ignored then).
 */
export function invitationBody(delivery: InvitationDelivery, language: InvitationLanguage): AdminInvitation {
  return delivery === 'mail' ? { delivery, language } : { delivery };
}

/** What the screen shows after an invitation: the link to copy, or the confirmation of the mail. */
export interface InvitationResult {
  account: Admin;
  delivery: InvitationDelivery;
  /** The link, only with the copy delivery. */
  link: ActivationLink | undefined;
  /** End of validity of the link (ISO 8601). */
  expiresAt: string;
}

/**
 * Splits an answer of createAdmin or inviteAdmin like splitActivation, for either delivery: the
 * link is present only with the copy delivery (a mailed link is never returned).
 */
export function splitCreated(data: AdminCreated): InvitationResult {
  const { invitationDelivery: delivery, activationUrl, activationExpiresAt, ...account } = data;
  const link =
    delivery === 'copy' && activationUrl !== undefined
      ? { url: activationUrl, expiresAt: activationExpiresAt }
      : undefined;
  return { account, delivery, link, expiresAt: activationExpiresAt };
}

/** The parts of an ErrorView (describeError) used to word an invitation error. */
export interface InvitationErrorLike extends ErrorLike {
  status?: number | undefined;
  retryAfterSeconds?: number | undefined;
}

/** Wait before a new attempt, as a short text: seconds under a minute, else minutes (rounded up). */
export function retryDelayText(seconds: number): string {
  const s = Math.max(1, Math.ceil(seconds));
  return s < 60 ? `${s} s` : `${Math.ceil(s / 60)} min`;
}

/**
 * Message of an error specific to sending an activation link, or undefined for any other error:
 * - system-smtp-unavailable (503): the operator did not configure the system mail; choose the
 *   copy delivery and submit again (the form keeps its values);
 * - 429 rate-limited: with the delay of Retry-After when known;
 * - admin-already-active (409): the account was activated meanwhile.
 */
export function invitationErrorMessage(error: InvitationErrorLike, t: Translate): string | undefined {
  if (error.code === 'system-smtp-unavailable') {
    return t('adminAccounts.invitation.errors.smtpUnavailable');
  }
  if (error.code === 'admin-already-active') {
    return t('adminAccounts.invitation.errors.alreadyActive');
  }
  if (error.code === 'rate-limited' || error.status === 429) {
    return error.retryAfterSeconds === undefined
      ? t('adminAccounts.invitation.errors.rateLimited')
      : t('adminAccounts.invitation.errors.rateLimitedIn', {
          delay: retryDelayText(error.retryAfterSeconds),
        });
  }
  return undefined;
}

/** Reports whether an account can be sent a new invitation: not activated and not disabled. */
export function canInvite(admin: Pick<Admin, 'activated' | 'disabled'>): boolean {
  return !admin.activated && !admin.disabled;
}

/** Reports whether the activation link of an account can be mailed (not for a super admin). */
export function canMailInvitation(admin: Pick<Admin, 'role'>): boolean {
  return admin.role === 'delegated_admin' || admin.role === 'auditor';
}

/** Roles attached to entities (and so needing at least one), unlike the super admin. */
export function needsTenants(role: AdminRole): boolean {
  return role === 'delegated_admin' || role === 'auditor';
}

/** Roles a new account can be created with (a super admin is promoted from an existing account). */
export const CREATABLE_ROLES = ['delegated_admin', 'auditor'] as const satisfies readonly AdminRole[];

/** Role of a new account. */
export type CreatableRole = (typeof CREATABLE_ROLES)[number];

/** Application path of the edit screen of an account (the id is percent-encoded). */
export function adminPath(id: string): string {
  return `/admins/${encodeURIComponent(id)}`;
}

/** Status of an account: disabled first, then pending activation, otherwise active. */
export type AccountStatus = 'active' | 'disabled' | 'pendingActivation';

/** Status of an account. */
export function accountStatus(admin: Pick<Admin, 'disabled' | 'activated'>): AccountStatus {
  if (admin.disabled) {
    return 'disabled';
  }
  return admin.activated ? 'active' : 'pendingActivation';
}

/** Two-factor status of an account: enabled, required but not configured yet, or not enabled. */
export type TotpStatus = 'enabled' | 'required' | 'disabled';

/** Two-factor status of an account (a super admin always requires it). */
export function totpStatus(admin: Pick<Admin, 'totpEnabled' | 'requireTotp' | 'role'>): TotpStatus {
  if (admin.totpEnabled) {
    return 'enabled';
  }
  return admin.requireTotp === true || admin.role === 'super_admin' ? 'required' : 'disabled';
}

/** Variant of StatusBadge for a status (the text always says the status). */
export function statusVariant(status: AccountStatus | TotpStatus): 'ok' | 'warning' | 'error' | 'info' {
  switch (status) {
    case 'active':
    case 'enabled':
      return 'ok';
    case 'pendingActivation':
    case 'required':
      return 'warning';
    case 'disabled':
      return 'info';
  }
}

/** Map of tenant id to tenant name. */
export type TenantNames = ReadonlyMap<string, string>;

/** Builds the tenant name map from a tenant list. */
export function tenantNameMap(tenants: readonly { id: string; name: string }[]): Map<string, string> {
  return new Map(tenants.map((tenant) => [tenant.id, tenant.name]));
}

/**
 * Names of the tenants of an account: "All entities" for a super admin, "No entity" when there
 * is none, otherwise the names (the id when the name is unknown), sorted.
 */
export function tenantLabel(
  admin: Pick<Admin, 'role' | 'tenantIds'>,
  names: TenantNames,
  t: Translate,
): string {
  if (admin.role === 'super_admin') {
    return t('adminAccounts.list.allTenants');
  }
  if (admin.tenantIds.length === 0) {
    return t('adminAccounts.list.noTenant');
  }
  return admin.tenantIds
    .map((id) => names.get(id) ?? id)
    .sort((a, b) => a.localeCompare(b))
    .join(', ');
}

/** One row of the admin list. */
export interface AdminRow {
  id: string;
  username: string;
  email: string;
  /** Edit screen of the account. */
  path: string;
  /** Role, translated. */
  role: string;
  /** Tenant names, see tenantLabel. */
  tenants: string;
  totp: TotpStatus;
  status: AccountStatus;
  /** Last sign-in, formatted, or "Never". */
  lastLogin: string;
  /** The row is the account of the signed-in admin. */
  self: boolean;
}

/** Builds the row of an account. */
export function adminRow(
  admin: Admin,
  ctx: { names: TenantNames; meId: string | undefined; t: Translate; formatDate: (iso: string) => string },
): AdminRow {
  return {
    id: admin.id,
    username: admin.username,
    email: admin.email,
    path: adminPath(admin.id),
    role: ctx.t(roleKey(admin.role)),
    tenants: tenantLabel(admin, ctx.names, ctx.t),
    totp: totpStatus(admin),
    status: accountStatus(admin),
    lastLogin:
      admin.lastLoginAt === undefined || admin.lastLoginAt === null
        ? ctx.t('adminAccounts.list.never')
        : ctx.formatDate(admin.lastLoginAt),
    self: admin.id === ctx.meId,
  };
}

/**
 * Loads every page of a cursor-paginated list (at most maxPages pages, a guard against a
 * cursor that never ends).
 */
export async function loadAllPages<T>(
  fetchPage: (cursor: string | undefined) => Promise<{ items: readonly T[]; nextCursor?: string | null }>,
  maxPages = 50,
): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const res = await fetchPage(cursor);
    out.push(...res.items);
    if (res.nextCursor === undefined || res.nextCursor === null || res.nextCursor === '') {
      break;
    }
    cursor = res.nextCursor;
  }
  return out;
}

/** Same pattern as the Username schema of the specification. */
const USERNAME = /^[a-z0-9][a-z0-9._-]{2,63}$/;
/** A light email check: the server validates the address. */
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** A client-side error of a form field: field name and fieldErrors code (or a message key). */
export interface FieldIssue {
  field: 'username' | 'email' | 'tenantIds';
  /** Translation key of the message. */
  key: string;
}

function emailIssues(email: string): FieldIssue[] {
  const value = email.trim();
  if (value === '') {
    return [{ field: 'email', key: 'fieldErrors.required' }];
  }
  return EMAIL.test(value) ? [] : [{ field: 'email', key: 'fieldErrors.invalid-email' }];
}

function tenantIssues(tenantIds: readonly string[]): FieldIssue[] {
  return tenantIds.length === 0 ? [{ field: 'tenantIds', key: 'adminAccounts.form.tenants.required' }] : [];
}

/** Form of the creation of a delegated admin or an auditor. */
export interface CreateForm {
  /** Role of the account: delegated admin (default) or auditor (read-only). */
  role: CreatableRole;
  username: string;
  email: string;
  tenantIds: string[];
  requireTotp: boolean;
  /** Delivery of the activation link. */
  delivery: InvitationDelivery;
  /** Language of the invitation mail (used with the mail delivery). */
  language: InvitationLanguage;
}

/**
 * Initial creation form: two-factor authentication required, activation link sent by mail, in
 * the given language (English by default).
 */
export function emptyCreateForm(language: InvitationLanguage = 'en'): CreateForm {
  return {
    role: 'delegated_admin',
    username: '',
    email: '',
    tenantIds: [],
    requireTotp: true,
    delivery: 'mail',
    language,
  };
}

/** Client-side validation of a username and an email address, in the order of the form. */
export function validateInvitee(input: { username: string; email: string }): FieldIssue[] {
  const issues: FieldIssue[] = [];
  const username = input.username.trim();
  if (username === '') {
    issues.push({ field: 'username', key: 'fieldErrors.required' });
  } else if (!USERNAME.test(username)) {
    issues.push({ field: 'username', key: 'fieldErrors.invalid-username' });
  }
  return [...issues, ...emailIssues(input.email)];
}

/** Client-side validation of the creation form, in the order of the form. */
export function validateCreate(form: CreateForm): FieldIssue[] {
  return [...validateInvitee(form), ...tenantIssues(form.tenantIds)];
}

/** Body of POST /admin/admins: a delegated admin or an auditor (a super admin is promoted later). */
export function createBody(form: CreateForm): AdminCreate {
  return {
    username: form.username.trim(),
    email: form.email.trim(),
    role: form.role,
    tenantIds: [...new Set(form.tenantIds)].sort(),
    // The server forces two-factor authentication for an invitation by mail.
    requireTotp: form.requireTotp || form.delivery === 'mail',
    invitation: invitationBody(form.delivery, form.language),
  };
}

/** Form of the edition of an account. */
export interface EditForm {
  email: string;
  role: AdminRole;
  tenantIds: string[];
  requireTotp: boolean;
  disabled: boolean;
}

/** Edit form filled from an account. */
export function editFormFrom(admin: Admin): EditForm {
  return {
    email: admin.email,
    role: admin.role,
    tenantIds: [...admin.tenantIds].sort(),
    requireTotp: admin.requireTotp === true || admin.role === 'super_admin',
    disabled: admin.disabled,
  };
}

/** Client-side validation of the edit form: a delegated admin or an auditor needs at least one entity. */
export function validateEdit(form: EditForm): FieldIssue[] {
  return [...emailIssues(form.email), ...(needsTenants(form.role) ? tenantIssues(form.tenantIds) : [])];
}

/**
 * Merge patch of an edit (only the changed fields, never null):
 * - promotion to super admin: the role only (the server clears the assignments, and two-factor
 *   authentication is always required for a super admin);
 * - demotion to delegated admin or auditor: the role and the assignments (required by the
 *   server); a switch between those two roles sends the role, and the assignments when changed;
 * - otherwise the changed fields; for a super admin, tenantIds and requireTotp are never sent.
 */
export function buildAdminPatch(admin: Admin, form: EditForm): AdminUpdate {
  const original = editFormFrom(admin);
  const edited: EditForm = {
    ...form,
    email: form.email.trim(),
    tenantIds: [...new Set(form.tenantIds)].sort(),
  };
  const patch: AdminUpdate = buildPatch(original, edited, ['email', 'role', 'disabled']);
  if (needsTenants(edited.role)) {
    Object.assign(patch, buildPatch(original, edited, ['requireTotp']));
    if (original.role === 'super_admin' || !deepEqual(original.tenantIds, edited.tenantIds)) {
      patch.tenantIds = edited.tenantIds;
    }
  }
  return patch;
}

/** Reports whether an account can be promoted to super admin (activated, TOTP enabled). */
export function canPromote(admin: Pick<Admin, 'activated' | 'totpEnabled'>): boolean {
  return admin.activated && admin.totpEnabled;
}

/** Actions offered on an account. */
export interface AccountActions {
  /** The account is the signed-in admin's own. */
  self: boolean;
  changeRole: boolean;
  disable: boolean;
  reset: boolean;
  remove: boolean;
}

/**
 * Actions offered on an account: on one's own account, no role change, disabling, credentials
 * reset or deletion (the server refuses them; the password and TOTP are managed from My
 * account).
 */
export function accountActions(admin: Pick<Admin, 'id'>, meId: string | undefined): AccountActions {
  const self = admin.id === meId;
  return { self, changeRole: !self, disable: !self, reset: !self, remove: !self };
}

/** Action that received the answer. */
export type AccountAction = { kind: 'update'; patch: AdminUpdate } | { kind: 'reset' } | { kind: 'delete' };

/**
 * Translation key of the message of a 409 state-conflict answer, deduced from the action and
 * from the state of the account: own account, promotion of an account that is not activated or
 * has no TOTP, credentials reset of a disabled account, last usable super admin (demotion,
 * disabling, reset or deletion of a super admin); otherwise the generic conflict message.
 */
export function conflictKey(
  admin: Pick<Admin, 'id' | 'role' | 'activated' | 'totpEnabled' | 'disabled'>,
  action: AccountAction,
  meId: string | undefined,
): string {
  if (admin.id === meId) {
    return 'adminAccounts.errors.ownAccount';
  }
  if (action.kind === 'update' && action.patch.role === 'super_admin' && admin.role !== 'super_admin') {
    return canPromote(admin) ? 'adminAccounts.errors.conflict' : 'adminAccounts.errors.notPromotable';
  }
  if (action.kind === 'reset' && admin.disabled) {
    return 'adminAccounts.errors.accountDisabled';
  }
  if (admin.role === 'super_admin') {
    const affectsAccess =
      action.kind !== 'update' ||
      action.patch.disabled === true ||
      action.patch.role === 'delegated_admin' ||
      action.patch.role === 'auditor';
    if (affectsAccess) {
      return 'adminAccounts.errors.lastSuperAdmin';
    }
  }
  return 'adminAccounts.errors.conflict';
}

/** The parts of an ErrorView (describeError) used to word an account error. */
export interface ErrorLike {
  code: string | undefined;
  message: string;
}

/** Message of an error of an account action: contextual for a state conflict. */
export function accountErrorMessage(
  error: ErrorLike,
  admin: Pick<Admin, 'id' | 'role' | 'activated' | 'totpEnabled' | 'disabled'>,
  action: AccountAction,
  meId: string | undefined,
  t: Translate,
): string {
  return error.code === 'state-conflict' ? t(conflictKey(admin, action, meId)) : error.message;
}
