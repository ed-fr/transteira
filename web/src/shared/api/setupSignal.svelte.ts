// Signal raised when the API answers 503 tenant-in-setup: the tenant is still being configured.
// The public application reads it to show its "service being set up" page, whichever call
// noticed it first (the page loaded before the tenant went back to setup, for example).

/** Holder of the "tenant in setup" signal. */
export interface TenantSetupSignal {
  /** True once a call has been refused with tenant-in-setup. */
  readonly inSetup: boolean;
  /** Records the refusal. */
  markInSetup(): void;
  /** Forgets the signal (tests). */
  reset(): void;
}

/** Creates an independent signal (tests, or one per application). */
export function createTenantSetupSignal(): TenantSetupSignal {
  let inSetup = $state(false);
  return {
    get inSetup() {
      return inSetup;
    },
    markInSetup() {
      inSetup = true;
    },
    reset() {
      inSetup = false;
    },
  };
}

/** The signal of the running application. */
export const tenantSetup: TenantSetupSignal = createTenantSetupSignal();
