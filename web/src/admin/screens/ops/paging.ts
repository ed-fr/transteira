// State of a cursor-paginated list of the tenant operation screens (first page, "Load more",
// reload after a filter change), kept as pure transitions so that it is unit tested in Node. A
// screen holds a PagedList in a $state and replaces it with the result of each transition; the
// generation number lets it ignore the answer of a request made for filters that have changed
// since (a slow first page must not overwrite the list of the new filters).

/** State of a paginated list. */
export interface PagedList<T> {
  /** Rows shown, in API order, without duplicates. */
  items: T[];
  /** Cursor of the next page; null when the last page is loaded. */
  nextCursor: string | null;
  /** A request is in progress. */
  loading: boolean;
  /** Error of the last request (any value the screen describes, e.g. an ErrorView). */
  error: unknown;
  /** The first page has been received at least once. */
  loaded: boolean;
  /** Incremented on each reset: an answer of an older generation is ignored. */
  generation: number;
}

/** One page of a list answer. */
export interface Page<T> {
  items: readonly T[];
  nextCursor?: string | null;
}

/** Initial state: nothing loaded. */
export function emptyList<T>(): PagedList<T> {
  return { items: [], nextCursor: null, loading: false, error: undefined, loaded: false, generation: 0 };
}

/**
 * Appends a page to the rows already shown, skipping rows whose key is already present (a row
 * created between two requests shifts the pages of a list sorted by date).
 */
export function appendPage<T>(
  rows: readonly T[],
  page: readonly T[],
  key: (row: T) => string = (row) => (row as { id: string }).id,
): T[] {
  const seen = new Set(rows.map(key));
  const out = [...rows];
  for (const row of page) {
    const k = key(row);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(row);
    }
  }
  return out;
}

/** Starts loading the first page (filters changed or reload): rows cleared, new generation. */
export function startReset<T>(state: PagedList<T>): PagedList<T> {
  return {
    items: [],
    nextCursor: null,
    loading: true,
    error: undefined,
    loaded: false,
    generation: state.generation + 1,
  };
}

/** Starts loading the next page; the state is unchanged when there is none or a request runs. */
export function startMore<T>(state: PagedList<T>): PagedList<T> {
  if (state.loading || state.nextCursor === null) {
    return state;
  }
  return { ...state, loading: true, error: undefined };
}

function cursorOf(page: Page<unknown>): string | null {
  return page.nextCursor === undefined || page.nextCursor === null || page.nextCursor === ''
    ? null
    : page.nextCursor;
}

/**
 * Applies a received page of the given generation (first page: replaces the rows; next page:
 * appends them); ignored when the generation is outdated.
 */
export function receivePage<T>(
  state: PagedList<T>,
  generation: number,
  page: Page<T>,
  key?: (row: T) => string,
): PagedList<T> {
  if (generation !== state.generation) {
    return state;
  }
  return {
    ...state,
    items: appendPage(state.items, page.items, key),
    nextCursor: cursorOf(page),
    loading: false,
    error: undefined,
    loaded: true,
  };
}

/** Records the failure of a request of the given generation; ignored when outdated. */
export function receiveError<T>(state: PagedList<T>, generation: number, error: unknown): PagedList<T> {
  if (generation !== state.generation) {
    return state;
  }
  return { ...state, loading: false, error };
}

/** Removes a row (deleted or revoked from the list) by key. */
export function removeItem<T>(
  state: PagedList<T>,
  id: string,
  key: (row: T) => string = (row) => (row as { id: string }).id,
): PagedList<T> {
  return { ...state, items: state.items.filter((row) => key(row) !== id) };
}

/** Replaces a row (updated from the list) by key; the state is unchanged when it is absent. */
export function replaceItem<T>(
  state: PagedList<T>,
  row: T,
  key: (row: T) => string = (r) => (r as { id: string }).id,
): PagedList<T> {
  const id = key(row);
  if (!state.items.some((r) => key(r) === id)) {
    return state;
  }
  return { ...state, items: state.items.map((r) => (key(r) === id ? row : r)) };
}
