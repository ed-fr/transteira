// Logic of the invitation list of a tenant (CLAUDE.md section 9), kept out of the component so
// that it is unit tested in Node: status badges (the status enum is extensible: an unknown value
// is shown as is with a neutral badge), the issuer erased under the GDPR (pseudonym
// "erased-<16 hex>"), which invitations can be revoked, the filter options and the list update
// after a revocation.
import type { components } from '../../../shared/api/schema';
import type { StatusVariant } from '../../components/fields';
import type { SelectOption } from '../../components/select';
import { INVITATION_STATUSES, type InvitationFilters } from './filters';
import { removeItem, replaceItem, type PagedList } from './paging';
import type { Translate } from '../../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** An invitation as listed by listTenantInvitations. */
export type Invitation = components['schemas']['Invitation'];

/** Message key of each known status. */
const STATUS_KEYS: Record<string, string> = {
  pending: 'opsInvitations.status.pending',
  used: 'opsInvitations.status.used',
  expired: 'opsInvitations.status.expired',
  revoked: 'opsInvitations.status.revoked',
};

/** Badge variant of each known status (the text always says the status). */
const STATUS_VARIANTS: Record<string, StatusVariant> = {
  pending: 'info',
  used: 'ok',
  expired: 'warning',
  revoked: 'error',
};

/** Badge of a status. */
export interface StatusView {
  variant: StatusVariant;
  label: string;
}

/**
 * Badge of an invitation status: a translated label and a variant; a status unknown to this
 * version of the interface is shown as is, with a neutral (info) badge.
 */
export function invitationStatusView(status: string, t: Translate): StatusView {
  const key = Object.hasOwn(STATUS_KEYS, status) ? STATUS_KEYS[status] : undefined;
  if (key === undefined) {
    return { variant: 'info', label: status };
  }
  return { variant: STATUS_VARIANTS[status] as StatusVariant, label: t(key) };
}

/** Pseudonym that replaces the address of an issuer whose data was erased (GDPR). */
export const ERASED_ISSUER = /^erased-[0-9a-f]{16}$/;

/** Reports whether invitedBy is the pseudonym of an erased issuer. */
export function isErasedIssuer(invitedBy: string): boolean {
  return ERASED_ISSUER.test(invitedBy);
}

/** Text of the issuer column: the address, or "Erased address" for a pseudonym. */
export function issuerText(invitedBy: string, t: Translate): string {
  return isErasedIssuer(invitedBy) ? t('opsInvitations.erasedIssuer') : invitedBy;
}

/** Reports whether a status may still be revoked (the invitation is still usable). */
export function isRevocableStatus(status: string): boolean {
  return status === 'pending' || status === 'used';
}

/**
 * Reports whether the revoke action is offered: a pending or used invitation that has not
 * expired yet (the status may lag behind the expiry date until the next cleanup).
 */
export function canRevoke(invitation: Invitation, now: number = Date.now()): boolean {
  if (!isRevocableStatus(invitation.status)) {
    return false;
  }
  const expires = Date.parse(invitation.expiresAt);
  return Number.isNaN(expires) || expires > now;
}

/** Options of the status filter: "All statuses" then each known status. */
export function statusFilterOptions(t: Translate): SelectOption[] {
  return [
    { value: '', label: t('opsInvitations.filters.allStatuses') },
    ...INVITATION_STATUSES.map((s) => ({ value: s, label: t(STATUS_KEYS[s] as string) })),
  ];
}

/**
 * List after the revocation of an invitation: the row shows the "revoked" status, or leaves the
 * list when it is filtered on another status.
 */
export function afterRevoke(
  state: PagedList<Invitation>,
  id: string,
  filters: InvitationFilters,
): PagedList<Invitation> {
  if (filters.status !== undefined && filters.status !== 'revoked') {
    return removeItem(state, id);
  }
  const row = state.items.find((r) => r.id === id);
  return row === undefined ? state : replaceItem(state, { ...row, status: 'revoked' });
}

/** Result text of the filter bar: number of invitations loaded, "or more" when a page remains. */
export function loadedText(count: number, hasMore: boolean, t: Translate): string {
  return t(hasMore ? 'opsInvitations.loadedMore' : 'opsInvitations.loaded', { count });
}
