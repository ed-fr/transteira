// User activity tracking, for the screens that read the API on a timer. Every read of the
// administration API extends the admin session (sliding idle timeout, internal/adminauth): a
// screen left open would keep the session alive forever (threat model T-165). A timer-driven
// read is therefore made only while the admin is active: a pointer press or a key press on the
// page, or the page becoming visible again, in the last IDLE_PAUSE_MS. The activity source and
// the clock are injectable for the tests.

/** Time without user activity after which timer-driven reads pause. */
export const IDLE_PAUSE_MS = 10 * 60_000;

/** Source of user activity events. */
export interface ActivitySource {
  /** Calls fn on each user activity; returns the unsubscribe function. */
  subscribe(fn: () => void): () => void;
}

/** Events of a document that count as user activity. */
type ActivityDocument = Pick<Document, 'visibilityState' | 'addEventListener' | 'removeEventListener'>;

/**
 * Activity of a document: pointerdown and keydown (captured, so that a handler stopping the
 * propagation does not hide them) and visibilitychange to visible. Without a document (tests,
 * server), no event is ever delivered.
 */
export function documentActivity(doc: ActivityDocument | undefined): ActivitySource {
  return {
    subscribe(fn) {
      if (doc === undefined) {
        return () => {};
      }
      const onInput = (): void => fn();
      const onVisibility = (): void => {
        if (doc.visibilityState === 'visible') {
          fn();
        }
      };
      const options = { capture: true, passive: true };
      doc.addEventListener('pointerdown', onInput, options);
      doc.addEventListener('keydown', onInput, options);
      doc.addEventListener('visibilitychange', onVisibility);
      return () => {
        doc.removeEventListener('pointerdown', onInput, options);
        doc.removeEventListener('keydown', onInput, options);
        doc.removeEventListener('visibilitychange', onVisibility);
      };
    },
  };
}

/** Tracks the time of the last user activity. */
export interface ActivityTracker {
  /** Clock time (epoch ms) of the last activity, or of the creation or the last reset(). */
  readonly lastActivity: number;
  /** Reports whether there was no activity for idleMs or more. */
  isIdle(): boolean;
  /** Records an activity now (e.g. a "Resume updates" button). */
  reset(): void;
  /** Stops listening to the source. */
  dispose(): void;
}

/** Creates a tracker listening to source; the creation counts as an activity. */
export function createActivityTracker(
  source: ActivitySource,
  now: () => number = Date.now,
  idleMs: number = IDLE_PAUSE_MS,
): ActivityTracker {
  let last = now();
  const unsubscribe = source.subscribe(() => {
    last = now();
  });
  return {
    get lastActivity() {
      return last;
    },
    isIdle: () => now() - last >= idleMs,
    reset() {
      last = now();
    },
    dispose: unsubscribe,
  };
}
