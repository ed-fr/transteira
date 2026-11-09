// Logic of the one-time secrets list of a tenant (SecretList, since 2.1), kept out of the
// component so that it is unit tested in Node: filter wiring, state badges, labels and the list
// after a deletion. The API returns metadata only, never the text, the file or the link of a
// secret.
import type { components } from '../../../shared/api/schema';
import type { StatusVariant } from '../../components/fields';
import type { SelectOption } from '../../components/select';
import { filterErrors, filterIssueMessage, type Translate } from './common';
import {
  SECRET_FILTERS,
  SECRET_STATES,
  formToFilters,
  pathWithFilters,
  validateFilters,
  type FilterForm,
  type Filters,
  type SecretState,
} from './filters';
import { removeItem, replaceItem, type PagedList } from './paging';

/** A secret of the list (AdminSecret). */
export type AdminSecret = components['schemas']['AdminSecret'];

export type { Translate };

/** Form of the secret filters (every field, "" when not set). */
export type SecretFilterForm = Required<FilterForm<typeof SECRET_FILTERS>>;
/** Field of the secret filter form. */
export type SecretFilterField = keyof typeof SECRET_FILTERS & string;

/** Outcome of the validation of the filter form. */
export type SecretFilterSubmit =
  | { ok: true; path: string }
  | { ok: false; errors: Partial<Record<SecretFilterField, string>>; first: SecretFilterField };

/** Validates the filter form: the path to navigate to, or a message per invalid field. */
export function submitSecretFilters(
  listPath: string,
  form: SecretFilterForm,
  t: Translate,
): SecretFilterSubmit {
  const failed = filterErrors(
    validateFilters(SECRET_FILTERS, form),
    (issue) => filterIssueMessage(issue.code, t),
    (issue) => issue.field,
  );
  if (failed !== undefined) {
    return { ok: false, ...failed };
  }
  return {
    ok: true,
    path: pathWithFilters(listPath, SECRET_FILTERS, formToFilters(SECRET_FILTERS, form) ?? {}),
  };
}

/** Badge of a state: variant and visible label. */
export interface SecretBadge {
  variant: StatusVariant;
  label: string;
}

const STATE_VARIANTS: Readonly<Record<SecretState, StatusVariant>> = {
  pending: 'info',
  active: 'ok',
  read: 'info',
  expired: 'warning',
  deleted: 'info',
  locked: 'error',
};

/** Badge of a state; an unknown state shows its raw value with a neutral badge. */
export function secretStateView(state: string, t: Translate): SecretBadge {
  return Object.hasOwn(STATE_VARIANTS, state)
    ? { variant: STATE_VARIANTS[state as SecretState], label: t(`adminSecrets.state.${state}`) }
    : { variant: 'info', label: state };
}

/** Options of the state filter: "any state" first, then every state. */
export function secretStateOptions(t: Translate): SelectOption[] {
  return [
    { value: '', label: t('adminSecrets.list.stateAny') },
    ...SECRET_STATES.map((s) => ({ value: s, label: secretStateView(s, t).label })),
  ];
}

/** Label of a delivery mode ("e-mail to a@example.com" or "link"). */
export function deliveryText(secret: Pick<AdminSecret, 'delivery' | 'recipient'>, t: Translate): string {
  if (secret.delivery === 'email') {
    return secret.recipient === undefined
      ? t('adminSecrets.delivery.email')
      : t('adminSecrets.delivery.emailTo', { recipient: secret.recipient });
  }
  return secret.delivery === 'link' ? t('adminSecrets.delivery.link') : String(secret.delivery);
}

/** Label of the creator kind (internal, from outside, external, API token); raw when unknown. */
export function creatorKindLabel(kind: string, t: Translate): string {
  return ['internal', 'internal_remote', 'external', 'api_token'].includes(kind)
    ? t(`adminSecrets.creatorKind.${kind}`)
    : kind;
}

/** A date, or the fallback text when there is none. */
export function dateOr(
  value: string | undefined,
  fallback: string,
  formatDate: (d: string) => string,
): string {
  return value === undefined || value === '' ? fallback : formatDate(value);
}

/** The secret can be deleted by an admin (not ended yet: pending or active). */
export function canDeleteSecret(state: string): boolean {
  return state === 'pending' || state === 'active';
}

/**
 * List after the deletion of a secret: the row shows the "deleted" state, or leaves the list when
 * it is filtered on another state.
 */
export function afterSecretDelete(
  state: PagedList<AdminSecret>,
  id: string,
  filters: Filters<typeof SECRET_FILTERS>,
  endedAt: string,
): PagedList<AdminSecret> {
  if (filters.state !== undefined && filters.state !== 'deleted') {
    return removeItem(state, id);
  }
  const row = state.items.find((r) => r.id === id);
  return row === undefined
    ? state
    : replaceItem(state, { ...row, state: 'deleted', endedAt, endReason: 'deleted' });
}

/** Result text of the filter bar: number of secrets loaded, "or more" when a page remains. */
export function secretsResultText(count: number, hasMore: boolean, t: Translate): string {
  return t(hasMore ? 'adminSecrets.list.loadedMore' : 'adminSecrets.list.loaded', { count });
}
