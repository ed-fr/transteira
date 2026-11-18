// Pointer press in progress on the page (RecipientInput, CLAUDE.md section 13.2). A press of the
// primary button on another control blurs the focused field before the click of that control is
// dispatched: on the release for a mouse, after the tap for a finger. A field that changes the
// layout when it loses the focus (the recipient input turns its draft into a chip, which may add a
// row) would move the pressed control away from the pointer, and the click would be lost.
// afterPress() defers such a change until the press is over: after the click (whose own handlers
// run first), after a cancelled press (e.g. a scroll), or a while after a release that no click
// follows (the pointer was dragged away). Without a press in progress (keyboard, focus() calls),
// the change runs at once. Timers are injectable for tests.

/** Timers used by PointerPress. */
export interface PressTimers {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const browserTimers: PressTimers = {
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Delay after a release that no click follows before the press is over (milliseconds). */
export const RELEASE_GRACE_MS = 1000;

/** Events listened to (capture phase), and what they mean for the press. */
const DOWN = 'pointerdown';
const UP = 'pointerup';
const ENDS = ['pointercancel', 'click'] as const;
/** Listener options: an object rather than a boolean, which every EventTarget reads alike. */
const CAPTURE: EventListenerOptions = { capture: true };

/** Follows the pointer presses on target (the window) until dispose(). */
export class PointerPress {
  #pressing = false;
  #pending: (() => void)[] = [];
  #timer: unknown;
  readonly #target: EventTarget;
  readonly #timers: PressTimers;

  constructor(target: EventTarget, timers: PressTimers = browserTimers) {
    this.#target = target;
    this.#timers = timers;
    target.addEventListener(DOWN, this.#onDown, CAPTURE);
    target.addEventListener(UP, this.#onUp, CAPTURE);
    for (const type of ENDS) {
      target.addEventListener(type, this.#onEnd, CAPTURE);
    }
  }

  /** A press of the primary button is in progress. */
  get pressing(): boolean {
    return this.#pressing;
  }

  /** Runs fn now, or once the press in progress is over. */
  afterPress(fn: () => void): void {
    if (this.#pressing) {
      this.#pending.push(fn);
    } else {
      fn();
    }
  }

  /** Stops following the presses; the deferred functions are dropped. */
  dispose(): void {
    this.#target.removeEventListener(DOWN, this.#onDown, CAPTURE);
    this.#target.removeEventListener(UP, this.#onUp, CAPTURE);
    for (const type of ENDS) {
      this.#target.removeEventListener(type, this.#onEnd, CAPTURE);
    }
    this.#clearTimer();
    this.#pending = [];
    this.#pressing = false;
  }

  // Only the primary button (or a finger, or a pen) clicks: a right press opens a context menu.
  readonly #onDown = (event: Event): void => {
    if ((event as PointerEvent).button !== 0) {
      return;
    }
    this.#clearTimer();
    this.#pressing = true;
  };

  // The click follows the release (at once for a mouse, after the tap gesture for a finger).
  readonly #onUp = (): void => {
    if (this.#pressing) {
      this.#settleIn(RELEASE_GRACE_MS);
    }
  };

  // Seen in the capture phase: the press is over once the click handlers have run.
  readonly #onEnd = (): void => {
    if (this.#pressing) {
      this.#settleIn(0);
    }
  };

  #settleIn(ms: number): void {
    this.#clearTimer();
    this.#timer = this.#timers.setTimeout(() => this.#settle(), ms);
  }

  #clearTimer(): void {
    if (this.#timer !== undefined) {
      this.#timers.clearTimeout(this.#timer);
      this.#timer = undefined;
    }
  }

  #settle(): void {
    this.#timer = undefined;
    this.#pressing = false;
    const pending = this.#pending;
    this.#pending = [];
    for (const fn of pending) {
      fn();
    }
  }
}
