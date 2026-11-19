import { describe, expect, it } from 'vitest';
import { createSearchQuery, searchQuery } from './search.svelte';

describe('search query store', () => {
  it('stores a trimmed query until it is consumed', () => {
    const store = createSearchQuery();
    expect(store.current).toBeUndefined();
    store.set('  alice@example.com ');
    expect(store.current).toBe('alice@example.com');
    expect(store.consume()).toBe('alice@example.com');
    expect(store.current).toBeUndefined();
    expect(store.consume()).toBeUndefined();
  });

  it('clears on an empty query and on clear', () => {
    const store = createSearchQuery();
    store.set('trf_01');
    store.set('   ');
    expect(store.current).toBeUndefined();
    store.set('trf_01');
    store.clear();
    expect(store.current).toBeUndefined();
  });

  it('shares one store in the application', () => {
    searchQuery.set('trf_02');
    expect(searchQuery.current).toBe('trf_02');
    searchQuery.clear();
    expect(searchQuery.current).toBeUndefined();
  });
});
