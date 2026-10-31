import { describe, expect, it, vi } from 'vitest';
import { createSetupStates } from './setupStates.svelte';
import type { TenantSetup } from './screens/tenants/setup';

const setup = (setupState: TenantSetup['setupState']): TenantSetup => ({
  setupState,
  canComplete: false,
  items: [],
});

describe('setup states', () => {
  it('reads a tenant once and remembers its state', async () => {
    const read = vi.fn(async () => setup('setup'));
    const states = createSetupStates(read);
    expect(states.stateOf('a')).toBeUndefined();
    await Promise.all([states.ensure('a'), states.ensure('a')]);
    await states.ensure('a');
    expect(read).toHaveBeenCalledTimes(1);
    expect(states.stateOf('a')).toBe('setup');
  });

  it('takes a state set by the wizard and forgets everything on clear', async () => {
    const states = createSetupStates(async () => setup('setup'));
    states.set('a', 'active');
    await states.ensure('a');
    expect(states.stateOf('a')).toBe('active');
    states.clear();
    expect(states.stateOf('a')).toBeUndefined();
  });

  it('leaves the state unknown when the read fails, and retries later', async () => {
    const read = vi.fn<() => Promise<TenantSetup>>().mockRejectedValueOnce(new Error('x'));
    read.mockResolvedValue(setup('active'));
    const states = createSetupStates(read);
    await states.ensure('a');
    expect(states.stateOf('a')).toBeUndefined();
    await states.ensure('a');
    expect(states.stateOf('a')).toBe('active');
  });
});
