// Self-scheduling poller: runs an asynchronous step, then waits the delay the step returns
// before running it again, until the step returns undefined or stop() is called. Only one step
// runs at a time (a slow answer delays the next read instead of piling requests up). When the
// page becomes visible again while a wait is pending, the step runs at once (the step itself
// chooses a longer delay while the page is hidden). Timers and page visibility are injectable
// for the tests; stop() also drops the result of a step still in flight.
import type { PageVisibility } from '../../maintenance.svelte';

/** One run of the poller: returns the delay before the next run, or undefined to stop. */
export type PollStep = (context: { visible: boolean }) => Promise<number | undefined>;

/** Timers and visibility used by a poller. */
export interface PollerDeps {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  visibility: PageVisibility;
}

/** A poller (see the file comment). */
export interface Poller {
  /** Reports whether the poller is started (waiting or running a step). */
  readonly active: boolean;
  /** Starts (or restarts) polling with step, first run after delayMs (0 by default). */
  start(step: PollStep, delayMs?: number): void;
  /** Stops polling; a step in flight is ignored when it ends. */
  stop(): void;
}

/** Browser timers and document visibility. */
export function browserPollerDeps(visibility: PageVisibility): PollerDeps {
  return {
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
    visibility,
  };
}

/** Creates a stopped poller. */
export function createPoller(deps: PollerDeps): Poller {
  let step: PollStep | undefined;
  // Incremented by start() and stop(): a step of an older generation is ignored.
  let generation = 0;
  let handle: unknown;
  let inFlight = false;
  let unsubscribe: (() => void) | undefined;

  function clearTimer(): void {
    if (handle !== undefined) {
      deps.clearTimeout(handle);
      handle = undefined;
    }
  }

  function schedule(ms: number): void {
    clearTimer();
    const gen = generation;
    handle = deps.setTimeout(
      () => {
        handle = undefined;
        if (gen === generation) {
          void run();
        }
      },
      Math.max(0, ms),
    );
  }

  async function run(): Promise<void> {
    const current = step;
    if (current === undefined || inFlight) {
      return;
    }
    const gen = generation;
    inFlight = true;
    let next: number | undefined;
    try {
      next = await current({ visible: deps.visibility.visible() });
    } catch {
      next = undefined;
    } finally {
      if (gen === generation) {
        inFlight = false;
      }
    }
    if (gen !== generation) {
      return;
    }
    if (next === undefined) {
      stop();
    } else {
      schedule(next);
    }
  }

  function onVisibilityChange(): void {
    if (step !== undefined && !inFlight && handle !== undefined && deps.visibility.visible()) {
      clearTimer();
      void run();
    }
  }

  function stop(): void {
    generation++;
    step = undefined;
    inFlight = false;
    clearTimer();
    unsubscribe?.();
    unsubscribe = undefined;
  }

  return {
    get active() {
      return step !== undefined;
    },
    start(next, delayMs = 0) {
      stop();
      step = next;
      unsubscribe = deps.visibility.subscribe(onVisibilityChange);
      schedule(delayMs);
    },
    stop,
  };
}
