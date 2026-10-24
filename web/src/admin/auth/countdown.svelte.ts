// Reactive countdown of a rate limit (429 retryAfterSeconds): `remaining` is the number of whole
// seconds before a new attempt, updated every second, and 0 when no wait is running. The
// screens disable their submit button while it is positive. Clock and timers are injectable.
import { retryAt, secondsLeft } from './views';

/** Clock and timers used by a countdown. */
export interface CountdownClock {
  now(): number;
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}

const browserClock: CountdownClock = {
  now: () => Date.now(),
  setInterval: (fn, ms) => setInterval(fn, ms),
  clearInterval: (handle) => clearInterval(handle as ReturnType<typeof setInterval>),
};

/** A running or idle countdown. */
export interface Countdown {
  /** Whole seconds left (reactive); 0 when idle. */
  readonly remaining: number;
  /** Starts (or restarts) a wait of seconds; undefined or not positive stops it. */
  start(seconds: number | undefined): void;
  /** Stops the wait. */
  stop(): void;
}

/** Creates a countdown; call stop() when the component is destroyed. */
export function createCountdown(clock: CountdownClock = browserClock): Countdown {
  let remaining = $state(0);
  let until: number | undefined;
  let handle: unknown;

  function stop(): void {
    if (handle !== undefined) {
      clock.clearInterval(handle);
      handle = undefined;
    }
    until = undefined;
    remaining = 0;
  }

  function tick(): void {
    remaining = secondsLeft(until, clock.now());
    if (remaining === 0) {
      stop();
    }
  }

  return {
    get remaining() {
      return remaining;
    },
    start(seconds) {
      stop();
      until = retryAt(seconds, clock.now());
      tick();
      if (remaining > 0) {
        handle = clock.setInterval(tick, 1000);
      }
    },
    stop,
  };
}
