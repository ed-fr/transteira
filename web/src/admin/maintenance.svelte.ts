// Last known maintenance state (GET /admin/system/maintenance, readable by every admin), for the
// maintenance banner of AdminLayout, the dashboard card and the screens that change it.
//
// No timer: every read of the administration API extends the admin session (sliding idle
// timeout, internal/adminauth), so a background poll would keep an unattended session open
// forever (threat model T-165). The state is therefore read only on events that come from the
// admin:
// - start() (application start or sign-in);
// - routeChanged(path) with a new path (AdminLayout, on each navigation of the admin);
// - the page becoming visible again (the admin comes back to the tab);
// - refresh() on demand, and set(state) with the answer of a PUT (maintenance screen).
// Answers are ordered: an older answer never overwrites a newer one or a state given to set().
// A failed read keeps the last value and raises failed until the next successful read.
// stop() (sign-out, layout destroyed) forgets the state and ignores the answers in flight. The
// reader and the page visibility are injectable for the tests.
import { adminApi } from './api';
import type { Maintenance } from './maintenanceBanner';

/** Page visibility (document.visibilityState and its visibilitychange event). */
export interface PageVisibility {
  /** Reports whether the page is visible. */
  visible(): boolean;
  /** Calls fn on every visibility change; returns the unsubscribe function. */
  subscribe(fn: () => void): () => void;
}

/** Dependencies of a maintenance store. */
export interface MaintenanceStoreDeps {
  /** Reads the maintenance state. */
  read(): Promise<Maintenance>;
  visibility: PageVisibility;
}

/** Reactive maintenance state, read on admin events (see the file comment). */
export interface MaintenanceStore {
  /** Last state known (reactive); undefined before the first answer and after stop(). */
  readonly current: Maintenance | undefined;
  /** The latest read failed (reactive); cleared by a successful read, set() and stop(). */
  readonly failed: boolean;
  /** Reads the state now; never rejects (a failure keeps the last value). */
  refresh(): Promise<void>;
  /** Records a state known otherwise (answer of a PUT); answers still in flight are dropped. */
  set(state: Maintenance): void;
  /** Reads the state when path differs from the previous one (first call: recorded only). */
  routeChanged(path: string): void;
  /** Starts listening (reads at once); does nothing when already started. */
  start(): void;
  /** Stops listening and forgets the state; answers still in flight are ignored. */
  stop(): void;
}

/** Visibility of a document (always visible without one). */
export function documentVisibility(
  doc: Pick<Document, 'visibilityState' | 'addEventListener' | 'removeEventListener'> | undefined,
): PageVisibility {
  return {
    visible: () => doc === undefined || doc.visibilityState !== 'hidden',
    subscribe(fn) {
      if (doc === undefined) {
        return () => {};
      }
      doc.addEventListener('visibilitychange', fn);
      return () => doc.removeEventListener('visibilitychange', fn);
    },
  };
}

/** Creates a maintenance store. */
export function createMaintenanceStore(deps: MaintenanceStoreDeps): MaintenanceStore {
  let current = $state.raw<Maintenance | undefined>(undefined);
  let failed = $state(false);
  let started = false;
  let lastPath: string | undefined;
  // Sequence of the reads and of set(): issued is the last number given, applied the number of
  // the state shown. stop() moves both forward, so every earlier answer is dropped.
  let issued = 0;
  let applied = 0;
  let unsubscribe: (() => void) | undefined;

  async function refresh(): Promise<void> {
    const seq = ++issued;
    try {
      const state = await deps.read();
      if (seq > applied) {
        applied = seq;
        current = state;
        failed = false;
      }
    } catch {
      // Keep the last value: the banner must not flicker on a transient error.
      if (seq > applied && seq === issued) {
        failed = true;
      }
    }
  }

  function onVisibilityChange(): void {
    if (started && deps.visibility.visible()) {
      void refresh();
    }
  }

  return {
    get current() {
      return current;
    },
    get failed() {
      return failed;
    },
    refresh,
    set(state) {
      applied = ++issued;
      current = state;
      failed = false;
    },
    routeChanged(path) {
      if (!started) {
        return;
      }
      const previous = lastPath;
      lastPath = path;
      if (previous !== undefined && previous !== path) {
        void refresh();
      }
    },
    start() {
      if (started) {
        return;
      }
      started = true;
      unsubscribe = deps.visibility.subscribe(onVisibilityChange);
      void refresh();
    },
    stop() {
      started = false;
      lastPath = undefined;
      applied = ++issued;
      unsubscribe?.();
      unsubscribe = undefined;
      current = undefined;
      failed = false;
    },
  };
}

/** The maintenance store of the admin application. */
export const adminMaintenance: MaintenanceStore = createMaintenanceStore({
  read: async () => (await adminApi.get('/admin/system/maintenance')).data,
  visibility: documentVisibility(typeof document === 'undefined' ? undefined : document),
});
