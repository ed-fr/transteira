import { describe, expect, it } from 'vitest';
import {
  appendPage,
  emptyList,
  receiveError,
  receivePage,
  removeItem,
  replaceItem,
  startMore,
  startReset,
  type PagedList,
} from './paging';

interface Row {
  id: string;
  n: number;
}

const r = (id: string, n = 0): Row => ({ id, n });

describe('appendPage', () => {
  it('appends and skips duplicates, by id by default', () => {
    expect(appendPage([r('a'), r('b')], [r('b', 1), r('c'), r('c', 2)])).toEqual([r('a'), r('b'), r('c')]);
  });

  it('accepts a key function', () => {
    const rows = [{ value: 'x' }];
    expect(appendPage(rows, [{ value: 'x' }, { value: 'y' }], (e) => e.value)).toEqual([
      { value: 'x' },
      { value: 'y' },
    ]);
  });
});

describe('paged list transitions', () => {
  it('loads a first page then the next one', () => {
    let s: PagedList<Row> = emptyList();
    expect(s).toMatchObject({ items: [], nextCursor: null, loading: false, loaded: false, generation: 0 });
    s = startReset(s);
    expect(s).toMatchObject({ loading: true, generation: 1 });
    const gen = s.generation;
    s = receivePage(s, gen, { items: [r('a'), r('b')], nextCursor: 'c1' });
    expect(s).toMatchObject({ items: [r('a'), r('b')], nextCursor: 'c1', loading: false, loaded: true });
    s = startMore(s);
    expect(s.loading).toBe(true);
    expect(startMore(s)).toBe(s);
    s = receivePage(s, gen, { items: [r('b'), r('c')], nextCursor: '' });
    expect(s.items.map((x) => x.id)).toEqual(['a', 'b', 'c']);
    expect(s.nextCursor).toBeNull();
    expect(startMore(s)).toBe(s);
  });

  it('treats a missing or null cursor as the last page', () => {
    const s = startReset(emptyList<Row>());
    expect(receivePage(s, 1, { items: [] }).nextCursor).toBeNull();
    expect(receivePage(s, 1, { items: [], nextCursor: null }).nextCursor).toBeNull();
  });

  it('ignores answers of an outdated generation', () => {
    const first = startReset(emptyList<Row>());
    const second = startReset(first);
    expect(receivePage(second, first.generation, { items: [r('old')] })).toBe(second);
    expect(receiveError(second, first.generation, new Error('late'))).toBe(second);
  });

  it('records an error and clears it on the next request', () => {
    let s = startReset(emptyList<Row>());
    s = receiveError(s, s.generation, 'boom');
    expect(s).toMatchObject({ loading: false, error: 'boom' });
    s = startReset(s);
    expect(s.error).toBeUndefined();
    s = receivePage(s, s.generation, { items: [r('a')], nextCursor: 'n' });
    s = receiveError(startMore(s), s.generation, 'again');
    expect(s.items).toEqual([r('a')]);
    expect(startMore(s).error).toBeUndefined();
  });

  it('removes and replaces rows', () => {
    let s = receivePage(startReset(emptyList<Row>()), 1, { items: [r('a'), r('b')] });
    s = replaceItem(s, r('b', 5));
    expect(s.items).toEqual([r('a'), r('b', 5)]);
    expect(replaceItem(s, r('z'))).toBe(s);
    s = removeItem(s, 'a');
    expect(s.items).toEqual([r('b', 5)]);
    const keyed = receivePage(startReset(emptyList<{ k: string }>()), 1, { items: [{ k: 'x' }] }, (e) => e.k);
    expect(removeItem(keyed, 'x', (e) => e.k).items).toEqual([]);
    expect(replaceItem(keyed, { k: 'x' }, (e) => e.k).items).toEqual([{ k: 'x' }]);
  });
});
