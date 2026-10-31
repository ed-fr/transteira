// Last known setup state of the tenants the admin looked at (GET /admin/tenants/{id}/setup), for
// the "being set up" badge of the tenant navigation. Read once per tenant shown (no timer: a
// background poll would keep the admin session alive, threat model T-165) and updated by the
// setup wizard when the setup is completed.
import { adminApi } from './api';
import type { TenantSetup } from './screens/tenants/setup';

/** Setup state of a tenant. */
export type SetupState = TenantSetup['setupState'];

/** Reads the setup of a tenant. */
export type SetupReader = (tenantId: string) => Promise<TenantSetup>;

/** Reactive store of setup states by tenant id. */
export interface SetupStates {
  /** State known for a tenant (reactive), undefined while unknown. */
  stateOf(tenantId: string): SetupState | undefined;
  /** Records a state known otherwise (answer of the wizard). */
  set(tenantId: string, state: SetupState): void;
  /** Reads the state of a tenant unless already known; a failure leaves it unknown. */
  ensure(tenantId: string): Promise<void>;
  /** Forgets everything (sign-out). */
  clear(): void;
}

/** Creates a store reading through the given reader. */
export function createSetupStates(read: SetupReader): SetupStates {
  let states = $state.raw<Record<string, SetupState>>({});
  const pending: Record<string, true | undefined> = {};
  return {
    stateOf: (tenantId) => states[tenantId],
    set(tenantId, state) {
      states = { ...states, [tenantId]: state };
    },
    async ensure(tenantId) {
      if (states[tenantId] !== undefined || pending[tenantId] === true) {
        return;
      }
      pending[tenantId] = true;
      try {
        const setup = await read(tenantId);
        states = { ...states, [tenantId]: setup.setupState };
      } catch {
        // The badge is informative: an unreadable setup leaves the tenant without badge.
      } finally {
        pending[tenantId] = undefined;
      }
    },
    clear() {
      states = {};
    },
  };
}

/** Setup states of the running admin application. */
export const setupStates: SetupStates = createSetupStates(
  async (tenantId) => (await adminApi.get('/admin/tenants/{tenantId}/setup', { path: { tenantId } })).data,
);
