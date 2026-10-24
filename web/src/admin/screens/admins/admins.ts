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

/** Form of the creation of a delegated admin. */
export interface CreateForm {
  username: string;
  email: string;
  tenantIds: string[];
  requireTotp: boolean;
}

/** Initial creation form: two-factor authentication required by default. */
export function emptyCreateForm(): CreateForm {
  return { username: '', email: '', tenantIds: [], requireTotp: true };
}

/** Client-side validation of the creation form, in the order of the form. */
export function validateCreate(form: CreateForm): FieldIssue[] {
  const issues: FieldIssue[] = [];
  const username = form.username.trim();
  if (username === '') {
    issues.push({ field: 'username', key: 'fieldErrors.required' });
  } else if (!USERNAME.test(username)) {
    issues.push({ field: 'username', key: 'fieldErrors.invalid-username' });
  }
  return [...issues, ...emailIssues(form.email), ...tenantIssues(form.tenantIds)];
}

/** Body of POST /admin/admins: always a delegated admin (a super admin is promoted later). */
export function createBody(form: CreateForm): AdminCreate {
  return {
    username: form.username.trim(),
    email: form.email.trim(),
    role: 'delegated_admin',
    tenantIds: [...new Set(form.tenantIds)].sort(),
    requireTotp: form.requireTotp,
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

/** Client-side validation of the edit form: a delegated admin needs at least one entity. */
export function validateEdit(form: EditForm): FieldIssue[] {
  return [
    ...emailIssues(form.email),
    ...(form.role === 'delegated_admin' ? tenantIssues(form.tenantIds) : []),
  ];
}

/**
 * Merge patch of an edit (only the changed fields, never null):
 * - promotion to super admin: the role only (the server clears the assignments, and two-factor
 *   authentication is always required for a super admin);
 * - demotion to delegated admin: the role and the assignments (required by the server);
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
  if (edited.role === 'delegated_admin') {
    Object.assign(patch, buildPatch(original, edited, ['requireTotp']));
    if (original.role !== 'delegated_admin' || !deepEqual(original.tenantIds, edited.tenantIds)) {
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
      action.kind !== 'update' || action.patch.disabled === true || action.patch.role === 'delegated_admin';
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
