import { describe, expect, it } from 'vitest';
import { announce, announcer, createAnnouncer } from './announce.svelte';

describe('announcer', () => {
  it('empties the region, then fills it on the next tick', () => {
    const queue: (() => void)[] = [];
    const a = createAnnouncer((fn: () => void) => queue.push(fn));
    a.state.polite = 'old';
    a.announce('Upload 50 %');
    expect(a.state.polite).toBe('');
    queue.shift()?.();
    expect(a.state.polite).toBe('Upload 50 %');
  });

  it('keeps only the last of overlapping messages, per politeness', () => {
    const queue: (() => void)[] = [];
    const a = createAnnouncer((fn: () => void) => queue.push(fn));
    a.announce('first');
    a.announce('urgent', 'assertive');
    a.announce('second');
    for (const fn of queue) {
      fn();
    }
    expect(a.state.polite).toBe('second');
    expect(a.state.assertive).toBe('urgent');
  });

  it('clear cancels pending messages', () => {
    const queue: (() => void)[] = [];
    const a = createAnnouncer((fn: () => void) => queue.push(fn));
    a.announce('pending');
    a.clear();
    queue.shift()?.();
    expect(a.state).toEqual({ polite: '', assertive: '' });
  });

  it('announces through the shared instance with a timer', async () => {
    announce('shared');
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(announcer.state.polite).toBe('shared');
  });
});
