import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RELATIVE_CLOCK_MS, startClock } from './clock';
import { browserClock } from './countdown.svelte';

describe('startClock', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('ticks with the current time at the interval until stopped', () => {
    const tick = vi.fn();
    const stop = startClock(tick);
    vi.advanceTimersByTime(RELATIVE_CLOCK_MS - 1);
    expect(tick).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(tick).toHaveBeenLastCalledWith(1_000_000 + RELATIVE_CLOCK_MS);
    vi.advanceTimersByTime(RELATIVE_CLOCK_MS);
    expect(tick).toHaveBeenCalledTimes(2);
    expect(tick).toHaveBeenLastCalledWith(1_000_000 + 2 * RELATIVE_CLOCK_MS);
    stop();
    vi.advanceTimersByTime(RELATIVE_CLOCK_MS * 3);
    expect(tick).toHaveBeenCalledTimes(2);
  });

  it('uses the injected clock and interval', () => {
    let fire: (() => void) | undefined;
    const clock = {
      now: () => 42,
      setInterval: vi.fn((fn: () => void) => {
        fire = fn;
        return 'handle';
      }),
      clearInterval: vi.fn(),
    };
    const tick = vi.fn();
    const stop = startClock(tick, clock, 5);
    expect(clock.setInterval).toHaveBeenCalledWith(expect.any(Function), 5);
    fire?.();
    expect(tick).toHaveBeenCalledWith(42);
    stop();
    expect(clock.clearInterval).toHaveBeenCalledWith('handle');
  });

  it('reads the time of the browser by default', () => {
    expect(browserClock.now()).toBe(1_000_000);
  });
});
