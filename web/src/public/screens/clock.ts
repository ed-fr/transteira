// Clock of the relative times of a page left open (CLAUDE.md section 13.2: the relative expiry of
// the download page). The page sets its clock when it reads the transfer; startClock() moves it
// on at a coarse interval, so that "Expires in 3 hours" does not stay frozen while the tab stays
// open. The relative text is rounded to the minute at best: twice a minute is enough.
import { browserClock, type CountdownClock } from './countdown.svelte';

/** Interval between two ticks of the clock of relative times (milliseconds). */
export const RELATIVE_CLOCK_MS = 30_000;

/**
 * Calls tick with the current time (epoch milliseconds) every intervalMs; returns the function
 * that stops it (an onMount cleanup).
 */
export function startClock(
  tick: (now: number) => void,
  clock: CountdownClock = browserClock,
  intervalMs: number = RELATIVE_CLOCK_MS,
): () => void {
  const handle = clock.setInterval(() => tick(clock.now()), intervalMs);
  return () => clock.clearInterval(handle);
}
