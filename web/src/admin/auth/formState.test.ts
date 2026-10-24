import { describe, expect, it, vi } from 'vitest';
import type { CountdownClock } from './countdown.svelte';
import { createFormState } from './formState.svelte';
import { generalMessage, summaryEntries } from './views';

function clock() {
  let now = 0;
  const timers = new Map<number, () => void>();
  let id = 0;
  const c: CountdownClock = {
    now: () => now,
    setInterval: (fn) => {
      timers.set(++id, fn);
      return id;
    },
    clearInterval: (h) => timers.delete(h as number),
  };
  return {
    c,
    advance(ms: number) {
      now += ms;
      for (const fn of [...timers.values()]) {
        fn();
      }
    },
  };
}

describe('generalMessage', () => {
  it('counts down a lock message and hides it at the end', () => {
    const lock = { key: 'adminAuth.login.locked', params: { count: 30 } };
    expect(generalMessage(undefined, 3)).toBeUndefined();
    expect(generalMessage(lock, undefined)).toBe(lock);
    expect(generalMessage(lock, 12)).toEqual({ key: 'adminAuth.login.locked', params: { count: 12 } });
    expect(generalMessage(lock, 0)).toBeUndefined();
    expect(generalMessage(lock, 60)).toEqual({ key: 'adminAuth.login.lockedMinutes', params: { count: 1 } });
    expect(generalMessage(lock, 61)).toEqual({ key: 'adminAuth.login.lockedMinutes', params: { count: 2 } });
    expect(generalMessage(lock, 900)).toEqual({
      key: 'adminAuth.login.lockedMinutes',
      params: { count: 15 },
    });
    expect(generalMessage({ text: 'x' }, 4)).toEqual({ text: 'x' });
  });
});

describe('summaryEntries', () => {
  it('lists the errors in the order of the fields', () => {
    const t = (key: string) => `T(${key})`;
    expect(
      summaryEntries(
        { b: { key: 'kb' }, a: { text: 'ta' } },
        [
          { name: 'a', id: 'ia', label: 'A' },
          { name: 'b', id: 'ib', label: 'B' },
          { name: 'c', id: 'ic', label: 'C' },
        ],
        t,
      ),
    ).toEqual([
      { id: 'ia', label: 'A', message: 'ta' },
      { id: 'ib', label: 'B', message: 'T(kb)' },
    ]);
  });
});

describe('createFormState', () => {
  it('checks client-side errors', () => {
    const s = createFormState();
    expect(s.check({ a: { key: 'k' } })).toBe(false);
    expect(s.fields).toEqual({ a: { key: 'k' } });
    expect(s.check({})).toBe(true);
    expect(s.fields).toEqual({});
  });

  it('shows failures, attempts and clears them', () => {
    const s = createFormState();
    s.fail({ fields: { code: { key: 'k' } }, attemptsRemaining: 2, general: { text: 'g' } });
    expect(s.fields).toEqual({ code: { key: 'k' } });
    expect(s.attemptsRemaining).toBe(2);
    expect(s.general).toEqual({ text: 'g' });
    expect(s.locked).toBe(false);
    expect(s.blocked).toBe(false);
    s.clear();
    expect(s.general).toBeUndefined();
    expect(s.attemptsRemaining).toBeUndefined();
  });

  it('locks, announces once, counts down and unlocks', () => {
    const k = clock();
    const announce = vi.fn();
    const s = createFormState({ announce, clock: k.c });
    s.fail({ fields: {}, general: { key: 'lock', params: { count: 2 } }, retryAfterSeconds: 2 });
    expect(announce).toHaveBeenCalledOnce();
    expect(announce).toHaveBeenCalledWith({ key: 'lock', params: { count: 2 } });
    expect(s.locked).toBe(true);
    expect(s.blocked).toBe(true);
    expect(s.remaining).toBe(2);
    k.advance(1000);
    expect(s.general).toEqual({ key: 'lock', params: { count: 1 } });
    k.advance(1000);
    expect(s.general).toBeUndefined();
    expect(s.locked).toBe(false);
    expect(s.blocked).toBe(false);
  });

  it('tracks busy and disposes', () => {
    const k = clock();
    const s = createFormState({ clock: k.c });
    s.busy = true;
    expect(s.busy).toBe(true);
    expect(s.blocked).toBe(true);
    s.fail({ fields: {}, general: { key: 'lock' }, retryAfterSeconds: 5 });
    s.dispose();
    expect(s.busy).toBe(false);
    expect(s.remaining).toBe(0);
    expect(s.general).toBeUndefined();
  });

  it('does not announce a lock without message', () => {
    const announce = vi.fn();
    const s = createFormState({ announce, clock: clock().c });
    s.fail({ fields: {}, retryAfterSeconds: 5 });
    expect(announce).not.toHaveBeenCalled();
    s.dispose();
  });
});
