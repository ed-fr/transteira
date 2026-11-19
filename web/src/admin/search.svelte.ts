// Query of the transfer search of the administration (searchTransfers, POST
// /admin/transfers/search; CLAUDE.md section 13.2, plan of step 3c, deviation 3). The search form
// of the home header stores the query here and opens /search, whose screen reads it. The query
// may be an e-mail address: it lives in this in-memory store only, NEVER in the URL (address bar,
// history, reverse proxy logs, Referer) nor in a browser storage (threat model T-412, like T-168).
// It is forgotten on sign-out (AdminShell) and when the page is reloaded.

/** In-memory store of the search query. */
export interface SearchQueryStore {
  /** Last query set and not cleared (reactive), undefined when none. */
  readonly current: string | undefined;
  /** Stores a query (trimmed); an empty query clears the store. */
  set(query: string): void;
  /** Returns the stored query and clears the store (a query is run once). */
  consume(): string | undefined;
  /** Forgets the query. */
  clear(): void;
}

/** Creates a store (the application uses the shared searchQuery below). */
export function createSearchQuery(): SearchQueryStore {
  let current = $state<string | undefined>(undefined);
  return {
    get current() {
      return current;
    },
    set(query) {
      const trimmed = query.trim();
      current = trimmed === '' ? undefined : trimmed;
    },
    consume() {
      const query = current;
      current = undefined;
      return query;
    },
    clear() {
      current = undefined;
    },
  };
}

/** The search query of the running application. */
export const searchQuery: SearchQueryStore = createSearchQuery();
