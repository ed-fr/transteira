import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PointerPress, RELEASE_GRACE_MS } from './pointerPress';

/** A pointer event of the given button (Node has no PointerEvent). */
function pointer(type: string, button = 0): Event {
  return Object.assign(new Event(type), { button });
}

describe('PointerPress', () => {
  let target: EventTarget;
  let press: PointerPress;

  beforeEach(() => {
    vi.useFakeTimers();
    target = new EventTarget();
    press = new PointerPress(target);
  });

  afterEach(() => {
    press.dispose();
    vi.useRealTimers();
  });

  it('runs at once without a press in progress', () => {
    const fn = vi.fn();
    expect(press.pressing).toBe(false);
    press.afterPress(fn);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('defers until the click of a mouse press has been handled', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown'));
    expect(press.pressing).toBe(true);
    // The press blurs the field: the change waits.
    press.afterPress(fn);
    target.dispatchEvent(pointer('pointerup'));
    expect(fn).not.toHaveBeenCalled();
    target.dispatchEvent(new Event('click'));
    // The handlers of the click run first, in the same task.
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(0);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(press.pressing).toBe(false);
  });

  it('waits for the click that follows a tap, after the release', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown'));
    target.dispatchEvent(pointer('pointerup'));
    // The tap gesture blurs the field after the release.
    vi.advanceTimersByTime(RELEASE_GRACE_MS - 1);
    press.afterPress(fn);
    target.dispatchEvent(new Event('click'));
    vi.advanceTimersByTime(0);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('ends a while after a release that no click follows', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown'));
    press.afterPress(fn);
    target.dispatchEvent(pointer('pointerup'));
    vi.advanceTimersByTime(RELEASE_GRACE_MS - 1);
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('ends when the press is cancelled', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown'));
    press.afterPress(fn);
    target.dispatchEvent(pointer('pointercancel'));
    vi.advanceTimersByTime(0);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('keeps pressing when a new press starts before the end of the previous one', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown'));
    target.dispatchEvent(pointer('pointerup'));
    target.dispatchEvent(pointer('pointerdown'));
    press.afterPress(fn);
    vi.advanceTimersByTime(RELEASE_GRACE_MS * 2);
    expect(fn).not.toHaveBeenCalled();
    target.dispatchEvent(new Event('click'));
    vi.advanceTimersByTime(0);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('ignores the other buttons and the events outside a press', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown', 2));
    expect(press.pressing).toBe(false);
    target.dispatchEvent(pointer('pointerup', 2));
    target.dispatchEvent(new Event('click'));
    target.dispatchEvent(pointer('pointercancel'));
    expect(vi.getTimerCount()).toBe(0);
    press.afterPress(fn);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('runs every deferred function once, in order', () => {
    const calls: string[] = [];
    target.dispatchEvent(pointer('pointerdown'));
    press.afterPress(() => calls.push('a'));
    press.afterPress(() => calls.push('b'));
    target.dispatchEvent(new Event('click'));
    vi.advanceTimersByTime(0);
    vi.advanceTimersByTime(RELEASE_GRACE_MS);
    expect(calls).toEqual(['a', 'b']);
  });

  it('drops the deferred functions and stops listening once disposed', () => {
    const fn = vi.fn();
    target.dispatchEvent(pointer('pointerdown'));
    press.afterPress(fn);
    target.dispatchEvent(pointer('pointerup'));
    press.dispose();
    expect(press.pressing).toBe(false);
    vi.advanceTimersByTime(RELEASE_GRACE_MS);
    expect(fn).not.toHaveBeenCalled();
    target.dispatchEvent(pointer('pointerdown'));
    expect(press.pressing).toBe(false);
  });

  it('uses the injected timers', () => {
    const timers = { setTimeout: vi.fn(() => 'handle'), clearTimeout: vi.fn() };
    const own = new PointerPress(target, timers);
    target.dispatchEvent(pointer('pointerdown'));
    target.dispatchEvent(pointer('pointerup'));
    expect(timers.setTimeout).toHaveBeenCalledWith(expect.any(Function), RELEASE_GRACE_MS);
    target.dispatchEvent(new Event('click'));
    expect(timers.clearTimeout).toHaveBeenCalledWith('handle');
    own.dispose();
  });
});
