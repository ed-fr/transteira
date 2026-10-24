// Reactive state of an authentication form: field errors, general message, attempts left, busy
// flag and the rate limit countdown (submit disabled while it runs). A lock is announced once
// through announce, the visible message then counts down without being re-announced.
import { createCountdown, type CountdownClock } from './countdown.svelte';
import { generalMessage, isValid, type FormErrors, type FormFailure, type Message } from './views';

/** Options of a form state. */
export interface FormStateOptions {
  /** Announces a lock message once (assertive), with its initial count. */
  announce?: (message: Message) => void;
  /** Clock of the countdown (tests). */
  clock?: CountdownClock;
}

/** State of a form. */
export interface FormState {
  /** Field errors. */
  readonly fields: FormErrors;
  /** General message, with the live count during a lock. */
  readonly general: Message | undefined;
  /** The general message is a lock (shown as a static alert, announced once). */
  readonly locked: boolean;
  /** Attempts left after a wrong code, when the server said. */
  readonly attemptsRemaining: number | undefined;
  /** Seconds left before a new attempt. */
  readonly remaining: number;
  /** A request is running. */
  busy: boolean;
  /** Submitting is not possible (busy or locked). */
  readonly blocked: boolean;
  /** Client-side errors: returns true when the form is valid (errors cleared then). */
  check(errors: FormErrors): boolean;
  /** Shows an API failure. */
  fail(failure: FormFailure): void;
  /** Clears every message (the countdown keeps running). */
  clear(): void;
  /** Stops the countdown and clears everything (component destroyed). */
  dispose(): void;
}

/** Creates a form state. */
export function createFormState(options: FormStateOptions = {}): FormState {
  let fields = $state.raw<FormErrors>({});
  let general = $state.raw<Message | undefined>(undefined);
  let locked = $state(false);
  let attemptsRemaining = $state<number | undefined>(undefined);
  let busy = $state(false);
  const countdown = options.clock === undefined ? createCountdown() : createCountdown(options.clock);

  function clear(): void {
    fields = {};
    general = undefined;
    locked = false;
    attemptsRemaining = undefined;
  }

  return {
    get fields() {
      return fields;
    },
    get general() {
      return generalMessage(general, locked ? countdown.remaining : undefined);
    },
    get locked() {
      return locked && countdown.remaining > 0;
    },
    get attemptsRemaining() {
      return attemptsRemaining;
    },
    get remaining() {
      return countdown.remaining;
    },
    get busy() {
      return busy;
    },
    set busy(value: boolean) {
      busy = value;
    },
    get blocked() {
      return busy || countdown.remaining > 0;
    },
    check(errors) {
      clear();
      fields = errors;
      return isValid(errors);
    },
    fail(failure) {
      clear();
      fields = failure.fields;
      general = failure.general;
      attemptsRemaining = failure.attemptsRemaining;
      locked = failure.retryAfterSeconds !== undefined;
      countdown.start(failure.retryAfterSeconds);
      if (locked && failure.general !== undefined) {
        options.announce?.(failure.general);
      }
    },
    clear,
    dispose() {
      countdown.stop();
      clear();
      busy = false;
    },
  };
}
