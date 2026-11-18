// Debounced announcement of the counter of the express secret text (liveCounter.svelte.ts).
import { describe, expect, it } from 'vitest';
import { COUNTER_ANNOUNCE_DELAY, LiveCounter, type CounterTimers } from './liveCounter.svelte';

/** Manual timers: run() fires the pending callback. */
function manualTimers() {
  let pending: { fn: () => void; ms: number } | undefined;
  let cleared = 0;
  const timers: CounterTimers = {
    setTimeout: (fn, ms) => {
      pending = { fn, ms };
      return pending;
    },
    clearTimeout: (handle) => {
      if (handle === pending) pending = undefined;
      cleared++;
    },
  };
  return {
    timers,
    run: () => {
      const p = pending;
      pending = undefined;
      p?.fn();
    },
    get pending() {
      return pending;
    },
    get cleared() {
      return cleared;
    },
  };
}

describe('LiveCounter', () => {
  it('announces the count only after a pause in typing', () => {
    const clock = manualTimers();
    const counter = new LiveCounter('0 of 10', { timers: clock.timers });
    expect(counter.message).toBe('');
    counter.update('1 of 10');
    counter.update('2 of 10');
    expect(clock.cleared).toBe(1);
    expect(clock.pending?.ms).toBe(COUNTER_ANNOUNCE_DELAY);
    expect(counter.message).toBe('');
    clock.run();
    expect(counter.message).toBe('2 of 10');
  });

  it('does not announce the same message twice nor the untouched field', () => {
    const clock = manualTimers();
    const counter = new LiveCounter('0 of 10', { timers: clock.timers, delay: 50 });
    counter.update('0 of 10');
    expect(clock.pending?.ms).toBe(50);
    clock.run();
    expect(counter.message).toBe('');
    counter.update('3 of 10');
    clock.run();
    counter.update('3 of 10');
    clock.run();
    expect(counter.message).toBe('3 of 10');
  });

  it('cancels a pending announcement on reset', () => {
    const clock = manualTimers();
    const counter = new LiveCounter('', { timers: clock.timers });
    counter.update('4 of 10');
    clock.run();
    counter.update('5 of 10');
    counter.reset('0 of 10');
    expect(clock.pending).toBeUndefined();
    expect(counter.message).toBe('');
    counter.reset();
    counter.update('0 of 10');
    clock.run();
    expect(counter.message).toBe('0 of 10');
  });

  it('uses the browser timers by default', async () => {
    const counter = new LiveCounter('', { delay: 1 });
    counter.update('1 of 10');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(counter.message).toBe('1 of 10');
    counter.update('2 of 10');
    counter.reset();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(counter.message).toBe('');
  });
});
