import { afterEach, describe, expect, it, vi } from 'vitest';
import { browserPollerDeps, createPoller, type PollerDeps } from './poller';

function fakeDeps() {
  let visible = true;
  let next = 1;
  const timers = new Map<number, { fn: () => void; ms: number }>();
  const listeners = new Set<() => void>();
  const deps: PollerDeps = {
    setTimeout(fn, ms) {
      const id = next++;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimeout(handle) {
      timers.delete(handle as number);
    },
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
    timers,
    listeners,
    /** Delays of the pending timers. */
    pending: () => [...timers.values()].map((t) => t.ms),
    /** Fires every pending timer, then lets the steps settle. */
    async fire() {
      const due = [...timers.entries()];
      for (const [id, { fn }] of due) {
        timers.delete(id);
        fn();
      }
      await flush();
    },
    async setVisible(v: boolean) {
      visible = v;
      for (const fn of [...listeners]) {
        fn();
      }
      await flush();
    },
  };
}

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await Promise.resolve();
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe('createPoller', () => {
  it('runs the step after the first delay, then after the delay it returns', async () => {
    const f = fakeDeps();
    const step = vi.fn(async () => 2_000);
    const poller = createPoller(f.deps);
    expect(poller.active).toBe(false);
    poller.start(step, 500);
    expect(poller.active).toBe(true);
    expect(f.pending()).toEqual([500]);
    expect(step).not.toHaveBeenCalled();
    await f.fire();
    expect(step).toHaveBeenCalledTimes(1);
    expect(step).toHaveBeenCalledWith({ visible: true });
    expect(f.pending()).toEqual([2_000]);
    await f.fire();
    expect(step).toHaveBeenCalledTimes(2);
  });

  it('starts at once by default and passes the visibility to the step', async () => {
    const f = fakeDeps();
    const seen: boolean[] = [];
    const poller = createPoller(f.deps);
    poller.start(async ({ visible }) => {
      seen.push(visible);
      return visible ? 2_000 : 10_000;
    });
    expect(f.pending()).toEqual([0]);
    await f.fire();
    await f.setVisible(false);
    expect(f.pending()).toEqual([2_000]);
    await f.fire();
    expect(seen).toEqual([true, false]);
    expect(f.pending()).toEqual([10_000]);
  });

  it('stops when the step returns undefined or throws', async () => {
    const f = fakeDeps();
    const poller = createPoller(f.deps);
    poller.start(async () => undefined);
    await f.fire();
    expect(poller.active).toBe(false);
    expect(f.pending()).toEqual([]);
    expect(f.listeners.size).toBe(0);

    poller.start(async () => {
      throw new Error('boom');
    });
    await f.fire();
    expect(poller.active).toBe(false);
    expect(f.pending()).toEqual([]);
  });

  it('runs at once when the page becomes visible during a wait', async () => {
    const f = fakeDeps();
    const step = vi.fn(async () => 10_000);
    const poller = createPoller(f.deps);
    poller.start(step);
    await f.fire();
    expect(step).toHaveBeenCalledTimes(1);
    await f.setVisible(false);
    expect(step).toHaveBeenCalledTimes(1);
    await f.setVisible(true);
    expect(step).toHaveBeenCalledTimes(2);
    expect(f.pending()).toEqual([10_000]);
  });

  it('does not run twice when the page becomes visible during a step', async () => {
    const f = fakeDeps();
    let release: (v: number) => void = () => {};
    const step = vi.fn(() => new Promise<number>((resolve) => (release = resolve)));
    const poller = createPoller(f.deps);
    poller.start(step);
    await f.fire();
    expect(step).toHaveBeenCalledTimes(1);
    await f.setVisible(true);
    expect(step).toHaveBeenCalledTimes(1);
    release(2_000);
    await flush();
    expect(f.pending()).toEqual([2_000]);
  });

  it('ignores a step still in flight after stop() and leaves no timer', async () => {
    const f = fakeDeps();
    let release: (v: number) => void = () => {};
    const poller = createPoller(f.deps);
    poller.start(() => new Promise<number>((resolve) => (release = resolve)));
    await f.fire();
    poller.stop();
    expect(poller.active).toBe(false);
    expect(f.listeners.size).toBe(0);
    release(2_000);
    await flush();
    expect(f.pending()).toEqual([]);
    await f.setVisible(true);
    expect(f.pending()).toEqual([]);
  });

  it('restarts cleanly: the old step and timer are dropped', async () => {
    const f = fakeDeps();
    const first = vi.fn(async () => 2_000);
    const second = vi.fn(async () => 2_000);
    const poller = createPoller(f.deps);
    poller.start(first, 1_000);
    poller.start(second, 300);
    expect(f.pending()).toEqual([300]);
    expect(f.listeners.size).toBe(1);
    await f.fire();
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
  });

  it('ignores a timer that fires after a restart', async () => {
    const f = fakeDeps();
    const first = vi.fn(async () => 2_000);
    const poller = createPoller(f.deps);
    poller.start(first, 1_000);
    const stale = [...f.timers.values()][0];
    poller.stop();
    stale?.fn();
    await flush();
    expect(first).not.toHaveBeenCalled();
  });

  it('clamps a negative delay to 0', () => {
    const f = fakeDeps();
    createPoller(f.deps).start(async () => undefined, -5);
    expect(f.pending()).toEqual([0]);
  });
});

describe('browserPollerDeps', () => {
  it('uses the global timers', () => {
    vi.useFakeTimers();
    const visibility = { visible: () => true, subscribe: () => () => {} };
    const deps = browserPollerDeps(visibility);
    expect(deps.visibility).toBe(visibility);
    const fn = vi.fn();
    const handle = deps.setTimeout(fn, 100);
    vi.advanceTimersByTime(100);
    expect(fn).toHaveBeenCalledTimes(1);
    const cancelled = vi.fn();
    const other = deps.setTimeout(cancelled, 100);
    deps.clearTimeout(other);
    vi.advanceTimersByTime(200);
    expect(cancelled).not.toHaveBeenCalled();
    expect(handle).toBeDefined();
  });
});
