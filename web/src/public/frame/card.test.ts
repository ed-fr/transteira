import { describe, expect, it, vi } from 'vitest';
import {
  CARD_SIZES,
  CardFrame,
  provideCardFrame,
  routeCardSize,
  useCardFrame,
  type ContextApi,
} from './card.svelte';
import { notFoundRoute, routes } from '../routes';

/** A context store standing for the Svelte component context. */
function fakeContext(): ContextApi & { values: Map<unknown, unknown> } {
  const values = new Map<unknown, unknown>();
  return {
    values,
    set: (key, value) => {
      values.set(key, value);
      return value;
    },
    get: <T>(key: unknown) => values.get(key) as T | undefined,
  };
}

describe('routeCardSize', () => {
  it.each([
    ['/me', 'wide'],
    ['/legal/:document', 'medium'],
    ['/help', 'medium'],
    ['/help/:topic', 'medium'],
    ['/help/print', 'medium'],
    ['/', 'narrow'],
    ['/d/:token', 'narrow'],
    ['/x', 'narrow'],
    ['/helpdesk', 'narrow'],
    ['*', 'narrow'],
  ])('gives %s the size %s', (pattern, size) => {
    expect(routeCardSize(pattern)).toBe(size);
  });

  it('gives every route of the application a known size', () => {
    for (const route of [...routes, notFoundRoute]) {
      expect(CARD_SIZES).toContain(routeCardSize(route.pattern));
    }
  });
});

describe('CardFrame', () => {
  it('is narrow without a route getter nor a request', () => {
    expect(new CardFrame().size).toBe('narrow');
  });

  it('follows the route size until a screen requests another one', () => {
    let pattern = '/me';
    const frame = new CardFrame(() => routeCardSize(pattern));
    expect(frame.size).toBe('wide');
    pattern = '/help';
    expect(frame.size).toBe('medium');
    const release = frame.request('split');
    expect(frame.size).toBe('split');
    release();
    expect(frame.size).toBe('medium');
  });

  it('lets the last request win and restores the previous one when it is released', () => {
    const frame = new CardFrame();
    const releaseMedium = frame.request('medium');
    const releaseWide = frame.request('wide');
    expect(frame.size).toBe('wide');
    releaseWide();
    expect(frame.size).toBe('medium');
    // Releasing twice does not remove another request.
    releaseWide();
    expect(frame.size).toBe('medium');
    releaseMedium();
    expect(frame.size).toBe('narrow');
  });

  it('removes an earlier request without changing the latest one', () => {
    const frame = new CardFrame();
    const first = frame.request('split');
    const second = frame.request('medium');
    first();
    expect(frame.size).toBe('medium');
    second();
    expect(frame.size).toBe('narrow');
  });

  it('keeps two requests of the same size apart', () => {
    const frame = new CardFrame();
    const a = frame.request('split');
    const b = frame.request('split');
    a();
    expect(frame.size).toBe('split');
    b();
    expect(frame.size).toBe('narrow');
  });

  it('tells whether the card is split (its content pads its own sections)', () => {
    const frame = new CardFrame();
    expect(frame.split).toBe(false);
    const release = frame.request('split');
    expect(frame.split).toBe(true);
    const medium = frame.request('medium');
    expect(frame.split).toBe(false);
    medium();
    release();
    expect(frame.split).toBe(false);
  });
});

describe('card frame context', () => {
  it('provides the frame to the components below', () => {
    const context = fakeContext();
    expect(useCardFrame(context)).toBeUndefined();
    const frame = new CardFrame();
    expect(provideCardFrame(frame, context)).toBe(frame);
    expect(useCardFrame(context)).toBe(frame);
  });

  it('uses the Svelte context by default', async () => {
    vi.resetModules();
    const store = new Map<unknown, unknown>();
    vi.doMock('svelte', async (importOriginal) => ({
      ...(await importOriginal<typeof import('svelte')>()),
      setContext: (key: unknown, value: unknown) => {
        store.set(key, value);
        return value;
      },
      getContext: (key: unknown) => store.get(key),
    }));
    const mod = await import('./card.svelte');
    const frame = new mod.CardFrame();
    mod.provideCardFrame(frame);
    expect(mod.useCardFrame()).toBe(frame);
    vi.doUnmock('svelte');
    vi.resetModules();
  });
});
