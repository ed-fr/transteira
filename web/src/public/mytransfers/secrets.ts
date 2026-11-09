// Pure logic of the "My secrets" section of the "My transfers" page (since 2.1): translation keys
// of the states and deliveries, which secrets can be deleted, the list after a deletion and the
// classification of a failed deletion. The API never returns the content of a secret.
import { ApiProblem } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';

/** A secret of the list (Secret). */
export type MySecret = components['schemas']['Secret'];

const STATES: readonly string[] = ['pending', 'active', 'read', 'expired', 'deleted', 'locked'];

/** Translation key of the state of a secret ("unknown" for a state of a future version). */
export function secretStateKey(state: string): string {
  return `myTransfers.secrets.state.${STATES.includes(state) ? state : 'unknown'}`;
}

/** Translation key of the delivery of a secret. */
export function secretDeliveryKey(delivery: string): string {
  return delivery === 'email' ? 'myTransfers.secrets.delivery.email' : 'myTransfers.secrets.delivery.link';
}

/** A secret the creator can delete: not ended yet (pending or active, never read). */
export function canDeleteMySecret(secret: Pick<MySecret, 'state'>): boolean {
  return secret.state === 'pending' || secret.state === 'active';
}

/** List after a deletion: the row shows the "deleted" state (it stays listed as a tombstone). */
export function markSecretDeleted(items: readonly MySecret[], id: string, endedAt: string): MySecret[] {
  return items.map((s) =>
    s.id === id ? { ...s, state: 'deleted', endedAt, endReason: 'deleted' as const } : s,
  );
}

/** Outcome of a failed deletion. */
export type SecretDeleteFailure = 'session-expired' | 'gone' | 'error';

/** Classifies the error of DELETE /me/secrets/{id}: 401 session over, 404 already gone. */
export function secretDeleteFailure(err: unknown): SecretDeleteFailure {
  if (err instanceof ApiProblem) {
    if (err.status === 401) {
      return 'session-expired';
    }
    if (err.status === 404) {
      return 'gone';
    }
  }
  return 'error';
}

/**
 * Whether a failed load of GET /me/secrets is to be kept silent: the tenant does not offer
 * secrets (404, or 403 secrets-disabled), so the section is simply left out of the page.
 */
export function secretListSilent(err: unknown): boolean {
  return err instanceof ApiProblem && (err.status === 404 || err.code === 'secrets-disabled');
}
