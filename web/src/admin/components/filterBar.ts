// Logic of FilterBar, kept out of the component so that it is unit tested in Node.
//
// The result text of a filter bar (e.g. "12 transfers loaded.") is announced only as the outcome
// of an apply or a reset, never for other changes: "Load more" changes the text too, but the
// DataTable already announces the added rows. A small state machine follows this:
// - idle: result text changes are not announced (initial load, load more);
// - pending (after apply or reset): the next defined, non-empty result text is announced, even
//   when it equals the previous one (the text goes undefined while the list reloads, then comes
//   back the same), and the machine returns to idle.
// When the action finished without the text ever going undefined (nothing reloaded), settle()
// announces the current text; an action that applied nothing (refused by validation) cancels.

/** State of the result announcer of a filter bar. */
export type FilterAnnouncerState = 'idle' | 'pending';

/** Result announcer of a filter bar (see the file comment). */
export interface FilterAnnouncer {
  /** Current state. */
  readonly state: FilterAnnouncerState;
  /** An apply or a reset started: the next result text is announced. */
  trigger(): void;
  /** The result text changed: the text to announce, or undefined (nothing to say). */
  result(text: string | undefined): string | undefined;
  /**
   * The apply or reset action finished (applied false: refused, nothing changed): the text to
   * announce when still pending with a defined text, or undefined.
   */
  settle(text: string | undefined, applied: boolean): string | undefined;
}

const isText = (text: string | undefined): text is string => text !== undefined && text !== '';

/** Creates a result announcer, idle. */
export function createFilterAnnouncer(): FilterAnnouncer {
  let state: FilterAnnouncerState = 'idle';
  const announceIfPending = (text: string | undefined): string | undefined => {
    if (state !== 'pending' || !isText(text)) {
      return undefined;
    }
    state = 'idle';
    return text;
  };
  return {
    get state() {
      return state;
    },
    trigger() {
      state = 'pending';
    },
    result: announceIfPending,
    settle(text, applied) {
      if (!applied) {
        state = 'idle';
        return undefined;
      }
      return announceIfPending(text);
    },
  };
}
