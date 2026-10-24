import { describe, expect, it, vi } from 'vitest';
import { IDLE_PAUSE_MS, createActivityTracker, documentActivity, type ActivitySource } from './activity';

function fakeSource() {
  const listeners = new Set<() => void>();
  const source: ActivitySource = {
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
  return {
    source,
    listeners,
    emit() {
      for (const fn of [...listeners]) {
        fn();
      }
    },
  };
}

describe('createActivityTracker', () => {
  it('pauses after 10 minutes without activity', () => {
    expect(IDLE_PAUSE_MS).toBe(600_000);
    let clock = 1_000;
    const f = fakeSource();
    const tracker = createActivityTracker(f.source, () => clock);
    expect(tracker.lastActivity).toBe(1_000);
    expect(tracker.isIdle()).toBe(false);
    clock += IDLE_PAUSE_MS - 1;
    expect(tracker.isIdle()).toBe(false);
    clock += 1;
    expect(tracker.isIdle()).toBe(true);
  });

  it('restarts the idle clock on each activity and on reset', () => {
    let clock = 0;
    const f = fakeSource();
    const tracker = createActivityTracker(f.source, () => clock, 100);
    clock = 90;
    f.emit();
    expect(tracker.lastActivity).toBe(90);
    clock = 150;
    expect(tracker.isIdle()).toBe(false);
    clock = 190;
    expect(tracker.isIdle()).toBe(true);
    tracker.reset();
    expect(tracker.isIdle()).toBe(false);
    expect(tracker.lastActivity).toBe(190);
  });

  it('stops listening once disposed', () => {
    let clock = 0;
    const f = fakeSource();
    const tracker = createActivityTracker(f.source, () => clock, 100);
    expect(f.listeners.size).toBe(1);
    tracker.dispose();
    expect(f.listeners.size).toBe(0);
    clock = 500;
    f.emit();
    expect(tracker.isIdle()).toBe(true);
  });

  it('uses the system clock by default', () => {
    const tracker = createActivityTracker(fakeSource().source);
    expect(tracker.isIdle()).toBe(false);
    expect(Math.abs(tracker.lastActivity - Date.now())).toBeLessThan(1_000);
  });
});

describe('documentActivity', () => {
  it('delivers nothing without a document', () => {
    const fn = vi.fn();
    const unsubscribe = documentActivity(undefined).subscribe(fn);
    expect(fn).not.toHaveBeenCalled();
    expect(() => unsubscribe()).not.toThrow();
  });

  it('counts pointer and key presses, and the page becoming visible', () => {
    const handlers = new Map<string, () => void>();
    const doc = {
      visibilityState: 'hidden' as DocumentVisibilityState,
      addEventListener: vi.fn((type: string, handler: () => void) => {
        handlers.set(type, handler);
      }),
      removeEventListener: vi.fn((type: string) => {
        handlers.delete(type);
      }),
    };
    const fn = vi.fn();
    const unsubscribe = documentActivity(doc as unknown as Document).subscribe(fn);
    expect([...handlers.keys()].sort()).toEqual(['keydown', 'pointerdown', 'visibilitychange']);
    expect(doc.addEventListener).toHaveBeenCalledWith('pointerdown', expect.any(Function), {
      capture: true,
      passive: true,
    });
    handlers.get('pointerdown')?.();
    handlers.get('keydown')?.();
    expect(fn).toHaveBeenCalledTimes(2);
    // Hidden: not an activity.
    handlers.get('visibilitychange')?.();
    expect(fn).toHaveBeenCalledTimes(2);
    doc.visibilityState = 'visible';
    handlers.get('visibilitychange')?.();
    expect(fn).toHaveBeenCalledTimes(3);
    unsubscribe();
    expect(handlers.size).toBe(0);
    expect(doc.removeEventListener).toHaveBeenCalledTimes(3);
  });
});
