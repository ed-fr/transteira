import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Countdown, secondsLeft } from './countdown.svelte';

describe('secondsLeft', () => {
  it('rounds up and never goes negative', () => {
    expect(secondsLeft(10_000, 0)).toBe(10);
    expect(secondsLeft(10_000, 9_001)).toBe(1);
    expect(secondsLeft(10_000, 10_000)).toBe(0);
    expect(secondsLeft(10_000, 20_000)).toBe(0);
  });
});

describe('Countdown', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('counts down to zero and calls ondone once', () => {
    const ondone = vi.fn();
    const c = new Countdown({ ondone });
    c.start(3);
    expect(c.remaining).toBe(3);
    expect(c.active).toBe(true);
    vi.advanceTimersByTime(1000);
    expect(c.remaining).toBe(2);
    vi.advanceTimersByTime(2000);
    expect(c.remaining).toBe(0);
    expect(c.active).toBe(false);
    expect(ondone).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(5000);
    expect(ondone).toHaveBeenCalledTimes(1);
  });

  it('follows the deadline when ticks are late', () => {
    const c = new Countdown();
    c.start(10);
    vi.setSystemTime(Date.now() + 7000);
    vi.advanceTimersByTime(1000);
    expect(c.remaining).toBe(2);
    c.stop();
  });

  it('ignores missing or non-positive durations and stops without ondone', () => {
    const ondone = vi.fn();
    const c = new Countdown({ ondone });
    c.start(undefined);
    expect(c.active).toBe(false);
    c.start(0);
    c.start(Number.NaN);
    expect(c.active).toBe(false);
    c.start(5);
    c.stop();
    expect(c.remaining).toBe(0);
    vi.advanceTimersByTime(10_000);
    expect(ondone).not.toHaveBeenCalled();
  });

  it('restarts with a new duration', () => {
    const c = new Countdown();
    c.start(2);
    c.start(60);
    vi.advanceTimersByTime(3000);
    expect(c.remaining).toBe(57);
    c.stop();
  });

  it('accepts an injected clock', () => {
    let now = 0;
    let tick: (() => void) | undefined;
    const cleared: unknown[] = [];
    const c = new Countdown({
      clock: {
        now: () => now,
        setInterval: (fn) => {
          tick = fn;
          return 42;
        },
        clearInterval: (handle) => cleared.push(handle),
      },
    });
    c.start(2);
    now = 2000;
    tick?.();
    expect(c.remaining).toBe(0);
    expect(cleared).toEqual([42]);
  });
});
