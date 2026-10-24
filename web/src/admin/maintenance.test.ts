import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  adminMaintenance,
  createMaintenanceStore,
  documentVisibility,
  type MaintenanceStoreDeps,
} from './maintenance.svelte';
import type { Maintenance } from './maintenanceBanner';

const on: Maintenance = { enabled: true, source: 'admin', adminEnabled: true, since: '2026-10-24T08:00:00Z' };
const off: Maintenance = { enabled: false, source: 'none', adminEnabled: false };

function fakeDeps(answers: (Maintenance | Error)[]) {
  let visible = true;
  const listeners = new Set<() => void>();
  const read = vi.fn(async () => {
    const answer = answers.length > 1 ? answers.shift() : answers[0];
    if (answer instanceof Error || answer === undefined) {
      throw answer ?? new Error('none');
    }
    return answer;
  });
  const deps: MaintenanceStoreDeps = {
    read,
    visibility: {
      visible: () => visible,
      subscribe(fn) {
        listeners.add(fn);
        return () => listeners.delete(fn);
      },
    },
  };
  return {
    deps,
    read,
    listeners,
    setVisible(v: boolean) {
      visible = v;
      for (const fn of [...listeners]) {
        fn();
      }
    },
  };
}

/** A reader whose answers are resolved by hand, in any order. */
function manualDeps() {
  const pending: { resolve: (m: Maintenance) => void; reject: (e: Error) => void }[] = [];
  const deps: MaintenanceStoreDeps = {
    read: () =>
      new Promise<Maintenance>((resolve, reject) => {
        pending.push({ resolve, reject });
      }),
    visibility: { visible: () => true, subscribe: () => () => {} },
  };
  return { deps, pending };
}

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe('createMaintenanceStore', () => {
  it('reads once at start and never on a timer', async () => {
    vi.useFakeTimers();
    try {
      const f = fakeDeps([off, on]);
      const store = createMaintenanceStore(f.deps);
      expect(store.current).toBeUndefined();
      store.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(store.current).toEqual(off);
      // Background reads would extend the admin session forever (T-165): none.
      await vi.advanceTimersByTimeAsync(60 * 60_000);
      expect(f.read).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('starts only once', async () => {
    const f = fakeDeps([off]);
    const store = createMaintenanceStore(f.deps);
    store.start();
    store.start();
    await flush();
    expect(f.read).toHaveBeenCalledTimes(1);
    expect(f.listeners.size).toBe(1);
  });

  it('reads again when the page becomes visible, not when it is hidden', async () => {
    const f = fakeDeps([off, on]);
    const store = createMaintenanceStore(f.deps);
    store.start();
    await flush();
    f.setVisible(false);
    await flush();
    expect(f.read).toHaveBeenCalledTimes(1);
    f.setVisible(true);
    await flush();
    expect(store.current).toEqual(on);
    expect(f.read).toHaveBeenCalledTimes(2);
  });

  it('reads again on a route change only', async () => {
    const f = fakeDeps([off, on]);
    const store = createMaintenanceStore(f.deps);
    store.routeChanged('/'); // not started: ignored
    store.start();
    await flush();
    store.routeChanged('/'); // first path: recorded, start() already read
    store.routeChanged('/');
    await flush();
    expect(f.read).toHaveBeenCalledTimes(1);
    store.routeChanged('/tenants');
    await flush();
    expect(f.read).toHaveBeenCalledTimes(2);
    expect(store.current).toEqual(on);
  });

  it('keeps the last value on a failed read and reports the failure', async () => {
    const f = fakeDeps([on, new Error('network'), off]);
    const store = createMaintenanceStore(f.deps);
    await store.refresh();
    expect(store.current).toEqual(on);
    expect(store.failed).toBe(false);
    await expect(store.refresh()).resolves.toBeUndefined();
    expect(store.current).toEqual(on);
    expect(store.failed).toBe(true);
    await store.refresh();
    expect(store.current).toEqual(off);
    expect(store.failed).toBe(false);
  });

  it('reports a first read that fails (state unknown)', async () => {
    const f = fakeDeps([new Error('network')]);
    const store = createMaintenanceStore(f.deps);
    store.start();
    await flush();
    expect(store.current).toBeUndefined();
    expect(store.failed).toBe(true);
  });

  it('never lets an older answer overwrite a newer one', async () => {
    const m = manualDeps();
    const store = createMaintenanceStore(m.deps);
    const first = store.refresh();
    const second = store.refresh();
    m.pending[1]?.resolve(on);
    await second;
    m.pending[0]?.resolve(off);
    await first;
    expect(store.current).toEqual(on);
  });

  it('ignores an older failure once a newer read is pending or done', async () => {
    const m = manualDeps();
    const store = createMaintenanceStore(m.deps);
    const first = store.refresh();
    const second = store.refresh();
    m.pending[0]?.reject(new Error('network'));
    await first;
    expect(store.failed).toBe(false);
    m.pending[1]?.resolve(on);
    await second;
    expect(store.current).toEqual(on);
    expect(store.failed).toBe(false);
  });

  it('set() records the state of a PUT and drops the reads in flight', async () => {
    const m = manualDeps();
    const store = createMaintenanceStore(m.deps);
    const late = store.refresh();
    store.set(on);
    expect(store.current).toEqual(on);
    m.pending[0]?.resolve(off);
    await late;
    expect(store.current).toEqual(on);
    expect(store.failed).toBe(false);
  });

  it('stops listening, forgets the state and drops late answers', async () => {
    const f = fakeDeps([on]);
    const store = createMaintenanceStore(f.deps);
    store.start();
    await flush();
    expect(store.current).toEqual(on);
    const late = store.refresh();
    store.stop();
    await late;
    expect(store.current).toBeUndefined();
    expect(store.failed).toBe(false);
    expect(f.listeners.size).toBe(0);
    // A visibility event or a route change after stop does nothing.
    f.setVisible(true);
    store.routeChanged('/x');
    expect(f.read).toHaveBeenCalledTimes(2);
    // It can start again (next sign-in).
    store.start();
    await flush();
    expect(store.current).toEqual(on);
  });

  it('ignores a visibility change delivered after stop', async () => {
    const f = fakeDeps([on]);
    const store = createMaintenanceStore(f.deps);
    store.start();
    const [listener] = [...f.listeners];
    store.stop();
    listener?.();
    expect(f.read).toHaveBeenCalledTimes(1);
  });

  it('stops without having started', () => {
    const store = createMaintenanceStore(fakeDeps([on]).deps);
    expect(() => store.stop()).not.toThrow();
  });
});

describe('documentVisibility', () => {
  it('is always visible without a document', () => {
    const v = documentVisibility(undefined);
    expect(v.visible()).toBe(true);
    expect(() => v.subscribe(() => {})()).not.toThrow();
  });

  it('reads the visibility state and the visibilitychange event', () => {
    const doc = {
      visibilityState: 'hidden' as DocumentVisibilityState,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
    const v = documentVisibility(doc);
    expect(v.visible()).toBe(false);
    doc.visibilityState = 'visible';
    expect(v.visible()).toBe(true);
    const fn = () => {};
    const unsubscribe = v.subscribe(fn);
    expect(doc.addEventListener).toHaveBeenCalledWith('visibilitychange', fn);
    unsubscribe();
    expect(doc.removeEventListener).toHaveBeenCalledWith('visibilitychange', fn);
  });
});

describe('adminMaintenance', () => {
  afterEach(() => {
    adminMaintenance.stop();
    vi.unstubAllGlobals();
  });

  it('reads GET /admin/system/maintenance', async () => {
    const fetch = vi.fn(
      async () =>
        new Response(JSON.stringify(on), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetch);
    await adminMaintenance.refresh();
    expect(adminMaintenance.current).toEqual(on);
    expect(String((fetch.mock.calls[0] as unknown[])[0])).toContain('/admin/system/maintenance');
  });
});
