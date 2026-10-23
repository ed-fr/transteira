// Reactive countdown in whole seconds (rate limits, locked transfer). Based on a deadline
// rather than on counting ticks, so that a throttled background tab stays accurate. Timers and
// clock are injectable for tests.

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

/** Seconds left before deadline (ceil, never negative). */
export function secondsLeft(deadline: number, now: number): number {
  return Math.max(0, Math.ceil((deadline - now) / 1000));
}

/** A countdown; `remaining` is reactive and reaches 0 when done. */
export class Countdown {
  remaining = $state(0);
  #deadline = 0;
  #handle: unknown;
  readonly #clock: CountdownClock;
  readonly #ondone: (() => void) | undefined;

  constructor(options: { clock?: CountdownClock; ondone?: () => void } = {}) {
    this.#clock = options.clock ?? browserClock;
    this.#ondone = options.ondone;
  }

  /** True while seconds remain. */
  get active(): boolean {
    return this.remaining > 0;
  }

  /** (Re)starts the countdown for seconds; a value that is not positive stops it. */
  start(seconds: number | undefined): void {
    this.stop();
    if (seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) {
      return;
    }
    this.#deadline = this.#clock.now() + seconds * 1000;
    this.remaining = secondsLeft(this.#deadline, this.#clock.now());
    this.#handle = this.#clock.setInterval(() => this.#tick(), 1000);
  }

  /** Stops the countdown and resets it to 0 (ondone is not called). */
  stop(): void {
    if (this.#handle !== undefined) {
      this.#clock.clearInterval(this.#handle);
      this.#handle = undefined;
    }
    this.remaining = 0;
  }

  #tick(): void {
    this.remaining = secondsLeft(this.#deadline, this.#clock.now());
    if (this.remaining === 0) {
      this.stop();
      this.#ondone?.();
    }
  }
}
