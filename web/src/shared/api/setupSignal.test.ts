import { describe, expect, it } from 'vitest';
import { createTenantSetupSignal } from './setupSignal.svelte';

describe('tenant setup signal', () => {
  it('is raised by a refusal and reset', () => {
    const signal = createTenantSetupSignal();
    expect(signal.inSetup).toBe(false);
    signal.markInSetup();
    expect(signal.inSetup).toBe(true);
    signal.reset();
    expect(signal.inSetup).toBe(false);
  });
});
