// Last known versions of the admin application: the running version (every admin, footer) and,
// for a super admin, the update check state (notice of the layout). Read once when the admin is
// authenticated, never on a timer (a poll would keep the session alive, T-165); the system
// overview records the answer of "Check now" with setSystem().
import { adminApi } from './api';
import { loadRunningVersion, loadSystemVersion, type SystemVersion } from './version';

class VersionStore {
  /** Running version; undefined before the first answer. */
  running = $state<string | undefined>(undefined);
  /** Update check state (super admin only); undefined when unknown. */
  system = $state.raw<SystemVersion | undefined>(undefined);
  #generation = 0;

  /** Reads the versions; the update check state only for a super admin. */
  async start(superAdmin: boolean): Promise<void> {
    const mine = ++this.#generation;
    const running = await loadRunningVersion(adminApi);
    if (mine !== this.#generation) {
      // The session ended or changed meanwhile: the role given may no longer be the caller's,
      // so the super admin read is not sent.
      return;
    }
    this.running = running;
    if (!superAdmin) {
      return;
    }
    try {
      const system = await loadSystemVersion(adminApi);
      if (mine === this.#generation) {
        this.system = system;
      }
    } catch {
      // The notice is optional: a failed read shows nothing.
    }
  }

  /** Records the state returned by the update check. */
  setSystem(state: SystemVersion): void {
    this.system = state;
  }

  /** Forgets everything (sign-out); answers in flight are ignored. */
  stop(): void {
    this.#generation++;
    this.running = undefined;
    this.system = undefined;
  }
}

/** The version store of the admin application. */
export const adminVersion = new VersionStore();
