// Shared screen reader announcer: announce() writes into the two live regions rendered by
// Announcer.svelte (mounted once by PageLayout). Repeating the same message re-announces it:
// the region is emptied first, then filled on the next tick.

/** Politeness of a live region announcement. */
export type Politeness = 'polite' | 'assertive';

/** State of the announcer (one message per politeness). */
export interface AnnouncerState {
  polite: string;
  assertive: string;
}

/** Scheduler used to fill the region after emptying it (injectable for tests). */
export type Schedule = (fn: () => void) => void;

const defaultSchedule: Schedule = (fn) => {
  setTimeout(fn, 50);
};

/** Creates an announcer; the application uses the shared one below. */
export function createAnnouncer(schedule: Schedule = defaultSchedule): {
  readonly state: AnnouncerState;
  announce(message: string, politeness?: Politeness): void;
  clear(): void;
} {
  const state = $state<AnnouncerState>({ polite: '', assertive: '' });
  const tickets: Record<Politeness, number> = { polite: 0, assertive: 0 };
  return {
    state,
    announce(message, politeness = 'polite') {
      const mine = ++tickets[politeness];
      state[politeness] = '';
      schedule(() => {
        if (mine === tickets[politeness]) {
          state[politeness] = message;
        }
      });
    },
    clear() {
      tickets.polite++;
      tickets.assertive++;
      state.polite = '';
      state.assertive = '';
    },
  };
}

/** The shared announcer, rendered by Announcer.svelte. */
export const announcer = createAnnouncer();

/** Announces a message to screen readers through the shared announcer. */
export function announce(message: string, politeness: Politeness = 'polite'): void {
  announcer.announce(message, politeness);
}
