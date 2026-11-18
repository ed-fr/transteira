// Debounced announcement of a character counter: the message of a polite live region is updated
// only once the user pauses typing, and only when it changed since the last announcement, so that
// a screen reader reads "120 characters of 10,000" after a pause instead of interrupting every
// keystroke (the visible counter of TextArea stays linked to the field by aria-describedby).
// Timers are injectable for tests.

/** Timers used by the counter. */
export interface CounterTimers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const browserTimers: CounterTimers = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Pause after the last keystroke before the count is announced, in milliseconds. */
export const COUNTER_ANNOUNCE_DELAY = 1000;

/** A debounced live message; `message` is reactive (bind it to a LiveRegion). */
export class LiveCounter {
  message = $state('');
  #last: string;
  #handle: unknown;
  readonly #delay: number;
  readonly #timers: CounterTimers;

  /** initial is the message of the untouched field: it is never announced. */
  constructor(initial = '', options: { delay?: number; timers?: CounterTimers } = {}) {
    this.#last = initial;
    this.#delay = options.delay ?? COUNTER_ANNOUNCE_DELAY;
    this.#timers = options.timers ?? browserTimers;
  }

  /** The field changed: next is announced after the pause unless it equals the last one. */
  update(next: string): void {
    this.#cancel();
    this.#handle = this.#timers.setTimeout(() => {
      this.#handle = undefined;
      if (next !== this.#last) {
        this.#last = next;
        this.message = next;
      }
    }, this.#delay);
  }

  /** Cancels a pending announcement and empties the region (form reset, page left). */
  reset(initial = ''): void {
    this.#cancel();
    this.#last = initial;
    this.message = '';
  }

  #cancel(): void {
    if (this.#handle !== undefined) {
      this.#timers.clearTimeout(this.#handle);
      this.#handle = undefined;
    }
  }
}
