// Logic of the transfer search of the administration (CLAUDE.md section 13.2; plan of step 3c,
// deviation 3): the search form of the home header and of the /search screen, and its results
// (searchTransfers, POST /admin/transfers/search). Kept out of the components so that it is unit
// tested in Node.
//
// - The query is a transfer identifier (trf_…) or a complete mail address (sender or recipient).
//   It lives in the in-memory searchQuery store (search.svelte.ts) and in the component state
//   only, never in the URL nor in a browser storage (threat model T-412): the request is a POST.
// - An auditor may not search by address (T-411, 403 read-only-role on the server): a query
//   holding "@" is refused here with an explanatory field error and never sent.
// - A transfer identifier matching exactly one transfer opens its detail screen directly.
// - For an address, the tenants with more matches than shown get a link to their transfer list
//   filtered by the address (the existing ?email= filter of that list: accepted, T-412 residual).
import type { ApiClient } from '../../shared/api/client';
import type { ErrorView } from '../../shared/api/problem';
import type { components } from '../../shared/api/schema';
import type { Translate } from '../../shared/i18n/messages';
import type { StatusVariant } from '../components/fields';
import { tenantPath } from '../shell';
import { formatWait } from './ops/common';
import { TRANSFER_FILTERS, pathWithFilters } from './ops/filters';
import { detailPath, statusView } from './ops/transfers';

/** Body of a search. */
export type TransferSearch = components['schemas']['TransferSearch'];
/** Answer of a search. */
export type SearchResult = components['schemas']['TransferSearchResult'];
/** A transfer found, with its tenant. */
export type SearchHit = SearchResult['items'][number];

/** Largest number of transfers requested (the API accepts 1 to 50). */
export const SEARCH_LIMIT = 50;

/** Longest query accepted by the API (a mail address is at most 254 characters). */
export const QUERY_MAX_LENGTH = 254;

/** Outcome of the client-side check of a query. */
export type QueryCheck = { ok: true; query: string } | { ok: false; error: string };

/**
 * Checks a query before it is sent: trimmed, not empty, at most QUERY_MAX_LENGTH characters, and
 * no address for an auditor (refused here, never sent). The format itself (identifier or complete
 * address) is checked by the server, whose field error is shown on the input (searchFailure).
 */
export function checkQuery(raw: string, auditor: boolean, t: Translate): QueryCheck {
  const query = raw.trim();
  if (query === '') {
    return { ok: false, error: t(auditor ? 'adminSearch.errors.emptyAuditor' : 'adminSearch.errors.empty') };
  }
  if (auditor && query.includes('@')) {
    return { ok: false, error: t('adminSearch.errors.auditorAddress') };
  }
  if (query.length > QUERY_MAX_LENGTH) {
    return { ok: false, error: t('fieldErrors.too-long') };
  }
  return { ok: true, query };
}

/** Runs a search (the API client is passed in, e.g. adminApi). */
export async function searchTransfers(
  api: Pick<ApiClient, 'post'>,
  query: string,
  limit: number = SEARCH_LIMIT,
): Promise<SearchResult> {
  const res = await api.post('/admin/transfers/search', { body: { q: query, limit } });
  return res.data;
}

/**
 * Path of the detail screen to open directly: a transfer identifier matching exactly one
 * transfer; undefined otherwise (the results are listed).
 */
export function directPath(result: Pick<SearchResult, 'kind' | 'items'>): string | undefined {
  const only = result.items.length === 1 ? result.items[0] : undefined;
  return result.kind === 'transfer_id' && only !== undefined
    ? detailPath(only.tenantId, only.transfer.id)
    : undefined;
}

/** A row of the result table. */
export interface SearchRow {
  /** Unique key of the row. */
  key: string;
  tenantId: string;
  tenantName: string;
  /** Primary colour of the tenant, for the decorative swatch (validated again by TenantSwatch). */
  color: unknown;
  transferId: string;
  sender: string;
  /** "3 recipients". */
  recipients: string;
  /** Creation date, formatted. */
  created: string;
  statusVariant: StatusVariant;
  statusLabel: string;
  /** The transfer is end-to-end encrypted (an extra pill, as in the transfer list). */
  e2e: boolean;
  /** Path of the detail screen of the transfer. */
  path: string;
}

/**
 * Rows of the result table, in the order of the API (newest first). colors maps a tenant id to
 * its primary colour (loadTenantColors); a tenant missing there gets the neutral swatch.
 */
export function searchRows(
  result: Pick<SearchResult, 'items'>,
  colors: ReadonlyMap<string, unknown>,
  t: Translate,
  formatDate: (iso: string) => string,
): SearchRow[] {
  return result.items.map((hit) => {
    const status = statusView(hit.transfer.status, t);
    return {
      key: `${hit.tenantId}/${hit.transfer.id}`,
      tenantId: hit.tenantId,
      tenantName: hit.tenantName,
      color: colors.get(hit.tenantId),
      transferId: hit.transfer.id,
      sender: hit.transfer.senderEmail,
      recipients: t('adminSearch.results.recipients', { count: hit.transfer.recipients.length }),
      created: formatDate(hit.transfer.createdAt),
      statusVariant: status.variant,
      statusLabel: status.label,
      e2e: hit.transfer.endToEndEncrypted === true,
      path: detailPath(hit.tenantId, hit.transfer.id),
    };
  });
}

/** A link to the transfer list of a tenant filtered by the searched address. */
export interface MoreLink {
  tenantId: string;
  label: string;
  path: string;
}

/**
 * Links "All transfers of this address in {entity}" for the tenants having more matches than
 * shown, after an address search (never for an auditor, who may not filter by address).
 */
export function moreLinks(
  result: Pick<SearchResult, 'kind' | 'tenants'>,
  query: string,
  auditor: boolean,
  t: Translate,
): MoreLink[] {
  if (result.kind !== 'email' || auditor) {
    return [];
  }
  return result.tenants
    .filter((tenant) => tenant.more)
    .map((tenant) => ({
      tenantId: tenant.tenantId,
      label: t('adminSearch.results.more', { entity: tenant.tenantName }),
      path: pathWithFilters(tenantPath(tenant.tenantId, 'transfers'), TRANSFER_FILTERS, { email: query }),
    }));
}

/** Number of transfers found ("3 transfers found."), announced and shown above the table. */
export function countText(count: number, t: Translate): string {
  return count === 0 ? t('adminSearch.results.none') : t('adminSearch.results.count', { count });
}

/** Text shown when nothing matches, by kind of query. */
export function emptyText(kind: SearchResult['kind'], t: Translate): string {
  return t(kind === 'email' ? 'adminSearch.results.emptyEmail' : 'adminSearch.results.emptyId');
}

/** A failed search: an error of the query field, or a general message. */
export type SearchFailure = { field: string } | { message: string };

/**
 * Message of a failed search:
 * - 400 validation-failed on q: an explanatory message on the input (invalid address, neither an
 *   identifier nor an address);
 * - 403 read-only-role: the auditor message on the input (normally refused before sending);
 * - 429 rate-limited: the wait before the next search (Retry-After);
 * - anything else: the general message of the error.
 */
export function searchFailure(view: ErrorView, auditor: boolean, t: Translate): SearchFailure {
  if (view.code === 'validation-failed') {
    const field = view.fields['q'];
    if (field?.code === 'invalid-email') {
      return { field: t('fieldErrors.invalid-email') };
    }
    if (field?.code === 'too-long') {
      return { field: t('fieldErrors.too-long') };
    }
    return {
      field: t(auditor ? 'adminSearch.errors.invalidFormatAuditor' : 'adminSearch.errors.invalidFormat'),
    };
  }
  if (view.code === 'read-only-role') {
    return { field: t('adminSearch.errors.auditorAddress') };
  }
  if (view.status === 429) {
    const seconds = view.retryAfterSeconds;
    return {
      message:
        seconds !== undefined && seconds > 0
          ? t('adminSearch.errors.rateLimited', { wait: formatWait(seconds, t) })
          : t('adminSearch.errors.rateLimitedNow'),
    };
  }
  return { message: view.message };
}

/**
 * Brings an error of the search input to a screen reader user (WCAG 4.1.3, RGAA 11.10). The error
 * is linked to the input (aria-describedby), which is read when the input receives the focus: when
 * the focus is elsewhere (the submit button was clicked, the query of the home header was refused
 * when the screen opened), it moves to the input. When the input already has the focus (the query
 * was sent with Enter), focusing it again says nothing, so the error is announced instead ("Error:
 * …", through say, e.g. the assertive shared announcer); likewise without an input to focus.
 * Call it once the error is rendered (after tick()), active being the element focused then.
 */
export function signalQueryError(
  input: { focus(): void } | undefined,
  active: unknown,
  error: string,
  t: Translate,
  say: (message: string) => void,
): void {
  if (input === undefined || active === input) {
    say(`${t('components.field.errorPrefix')} ${error}`);
    return;
  }
  input.focus();
}

/** Primary colours of tenants, by tenant id. */
export function tenantColors(
  tenants: readonly { id: string; primaryColor?: string | undefined }[],
): Map<string, string | undefined> {
  return new Map(tenants.map((tenant) => [tenant.id, tenant.primaryColor]));
}

/** Largest page of tenants read for their colours. */
export const COLOR_PAGE = 200;

/**
 * Colours of the tenants of the admin (first page of GET /admin/tenants, enough for the swatches
 * of the results). A failure gives an empty map: the swatches are then neutral.
 */
export async function loadTenantColors(
  api: Pick<ApiClient, 'get'>,
): Promise<Map<string, string | undefined>> {
  try {
    const res = await api.get('/admin/tenants', { params: { limit: COLOR_PAGE } });
    return tenantColors(res.data.items);
  } catch {
    return new Map();
  }
}
