import { describe, expect, it } from 'vitest';
import { createCountdown, type CountdownClock } from './countdown.svelte';

function fakeClock() {
  let now = 0;
  let next = 1;
  const timers = new Map<number, () => void>();
  const clock: CountdownClock = {
    now: () => now,
    setInterval(fn) {
      const id = next++;
      timers.set(id, fn);
      return id;
    },
    clearInterval(handle) {
      timers.delete(handle as number);
    },
  };
  return {
    clock,
    timers,
    advance(ms: number) {
      now += ms;
      for (const fn of [...timers.values()]) {
        fn();
      }
    },
  };
}

describe('createCountdown', () => {
  it('counts down every second and stops at zero', () => {
    const f = fakeClock();
    const c = createCountdown(f.clock);
    expect(c.remaining).toBe(0);
    c.start(2);
    expect(c.remaining).toBe(2);
    expect(f.timers.size).toBe(1);
    f.advance(1000);
    expect(c.remaining).toBe(1);
    f.advance(1000);
    expect(c.remaining).toBe(0);
    expect(f.timers.size).toBe(0);
  });

  it('restarts, stops and ignores missing delays', () => {
    const f = fakeClock();
    const c = createCountdown(f.clock);
    c.start(5);
    c.start(10);
    expect(f.timers.size).toBe(1);
    expect(c.remaining).toBe(10);
    c.stop();
    expect(c.remaining).toBe(0);
    expect(f.timers.size).toBe(0);
    c.start(undefined);
    expect(c.remaining).toBe(0);
    expect(f.timers.size).toBe(0);
  });

  it('uses the browser clock by default', () => {
    const c = createCountdown();
    c.start(30);
    expect(c.remaining).toBe(30);
    c.stop();
    expect(c.remaining).toBe(0);
  });
});
