import { describe, expect, it, vi } from 'vitest';
import en from '../../locales/en/adminSearch.json';
import fr from '../../locales/fr/adminSearch.json';
import type { ErrorView } from '../../shared/api/problem';
import {
  COLOR_PAGE,
  QUERY_MAX_LENGTH,
  SEARCH_LIMIT,
  checkQuery,
  countText,
  directPath,
  emptyText,
  loadTenantColors,
  moreLinks,
  searchFailure,
  searchRows,
  searchTransfers,
  signalQueryError,
  tenantColors,
  type SearchHit,
  type SearchResult,
} from './search';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

/** A message of a bundle by its dotted key (a plural group resolves through "other"). */
function message(bundle: unknown, key: string): string | undefined {
  let node: unknown = bundle;
  for (const part of key.split('.')) {
    node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
  }
  if (typeof node === 'object' && node !== null) {
    node = (node as Record<string, unknown>)['other'];
  }
  return typeof node === 'string' ? node : undefined;
}

const ID = 'trf_01JABC0000000000000000000A';

function hit(
  over: Partial<SearchHit['transfer']> = {},
  tenantId = 'ten_A',
  tenantName = 'Entity A',
): SearchHit {
  return {
    tenantId,
    tenantName,
    transfer: {
      id: ID,
      status: 'available',
      origin: 'internal',
      senderEmail: 'alice@entity-a.example.com',
      recipients: ['carol@customer.example.net', 'dave@customer.example.net'],
      fileCount: 2,
      totalBytes: 1024,
      passwordProtected: false,
      deleteAfterFirstDownload: false,
      createdAt: '2026-11-18T10:00:00Z',
      downloadCount: 0,
      ...over,
    },
  };
}

function view(over: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'General message',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...over,
  };
}

describe('checkQuery', () => {
  it('trims the query and refuses an empty one', () => {
    expect(checkQuery(`  ${ID} `, false, t)).toEqual({ ok: true, query: ID });
    expect(checkQuery('   ', false, t)).toEqual({ ok: false, error: 'adminSearch.errors.empty' });
    expect(checkQuery('', true, t)).toEqual({ ok: false, error: 'adminSearch.errors.emptyAuditor' });
  });

  it('refuses an address to an auditor before anything is sent', () => {
    expect(checkQuery('carol@customer.example.net', true, t)).toEqual({
      ok: false,
      error: 'adminSearch.errors.auditorAddress',
    });
    expect(checkQuery('carol@customer.example.net', false, t)).toEqual({
      ok: true,
      query: 'carol@customer.example.net',
    });
    expect(checkQuery(ID, true, t)).toEqual({ ok: true, query: ID });
  });

  it('refuses a query longer than an address can be', () => {
    expect(QUERY_MAX_LENGTH).toBe(254);
    expect(checkQuery('a'.repeat(254), false, t).ok).toBe(true);
    expect(checkQuery('a'.repeat(255), false, t)).toEqual({ ok: false, error: 'fieldErrors.too-long' });
  });
});

describe('searchTransfers', () => {
  it('posts the query in the body, never in the URL', async () => {
    const result: SearchResult = { kind: 'email', items: [], truncated: false, tenants: [] };
    const post = vi.fn(async () => ({ data: result, status: 200, headers: new Headers() }));
    expect(await searchTransfers({ post } as never, 'carol@customer.example.net')).toBe(result);
    expect(post).toHaveBeenCalledWith('/admin/transfers/search', {
      body: { q: 'carol@customer.example.net', limit: SEARCH_LIMIT },
    });
    expect(SEARCH_LIMIT).toBe(50);
    await searchTransfers({ post } as never, ID, 5);
    expect(post).toHaveBeenLastCalledWith('/admin/transfers/search', { body: { q: ID, limit: 5 } });
  });
});

describe('directPath', () => {
  it('opens the detail of the only transfer of an identifier', () => {
    expect(directPath({ kind: 'transfer_id', items: [hit()] })).toBe(`/tenants/ten_A/transfers/${ID}`);
  });

  it('lists the results otherwise', () => {
    expect(directPath({ kind: 'transfer_id', items: [] })).toBeUndefined();
    expect(directPath({ kind: 'email', items: [hit()] })).toBeUndefined();
    expect(directPath({ kind: 'transfer_id', items: [hit(), hit({}, 'ten_B')] })).toBeUndefined();
  });
});

describe('searchRows', () => {
  it('builds the rows in the order of the API, with the colour of their tenant', () => {
    const colors = new Map<string, unknown>([['ten_A', '#1D4ED8']]);
    const rows = searchRows(
      {
        items: [
          hit(),
          hit(
            { id: 'trf_2', status: 'expired', recipients: ['x@example.com'], endToEndEncrypted: true },
            'ten_B',
            'Entity B',
          ),
        ],
      },
      colors,
      t,
      (iso) => `D(${iso})`,
    );
    expect(rows).toEqual([
      {
        key: `ten_A/${ID}`,
        tenantId: 'ten_A',
        tenantName: 'Entity A',
        color: '#1D4ED8',
        transferId: ID,
        sender: 'alice@entity-a.example.com',
        recipients: 'adminSearch.results.recipients {"count":2}',
        created: 'D(2026-11-18T10:00:00Z)',
        statusVariant: 'ok',
        statusLabel: 'opsTransfers.status.available',
        e2e: false,
        path: `/tenants/ten_A/transfers/${ID}`,
      },
      {
        key: 'ten_B/trf_2',
        tenantId: 'ten_B',
        tenantName: 'Entity B',
        color: undefined,
        transferId: 'trf_2',
        sender: 'alice@entity-a.example.com',
        recipients: 'adminSearch.results.recipients {"count":1}',
        created: 'D(2026-11-18T10:00:00Z)',
        statusVariant: 'warning',
        statusLabel: 'opsTransfers.status.expired',
        e2e: true,
        path: '/tenants/ten_B/transfers/trf_2',
      },
    ]);
  });
});

describe('moreLinks', () => {
  const result: Pick<SearchResult, 'kind' | 'tenants'> = {
    kind: 'email',
    tenants: [
      { tenantId: 'ten_A', tenantName: 'Entity A', more: true },
      { tenantId: 'ten_B', tenantName: 'Entity B', more: false },
    ],
  };

  it('links the transfer list of the tenants with more matches, filtered by the address', () => {
    expect(moreLinks(result, 'carol@customer.example.net', false, t)).toEqual([
      {
        tenantId: 'ten_A',
        label: 'adminSearch.results.more {"entity":"Entity A"}',
        path: '/tenants/ten_A/transfers?email=carol%40customer.example.net',
      },
    ]);
  });

  it('gives nothing for an identifier or to an auditor', () => {
    expect(moreLinks({ ...result, kind: 'transfer_id' }, ID, false, t)).toEqual([]);
    expect(moreLinks(result, 'carol@customer.example.net', true, t)).toEqual([]);
  });
});

describe('texts', () => {
  it('count the transfers found and say why nothing matched', () => {
    expect(countText(0, t)).toBe('adminSearch.results.none');
    expect(countText(3, t)).toBe('adminSearch.results.count {"count":3}');
    expect(emptyText('email', t)).toBe('adminSearch.results.emptyEmail');
    expect(emptyText('transfer_id', t)).toBe('adminSearch.results.emptyId');
  });
});

describe('searchFailure', () => {
  it('shows a refused query on the input', () => {
    const invalidEmail = view({
      code: 'validation-failed',
      status: 400,
      fields: { q: { code: 'invalid-email', message: 'x' } },
    });
    expect(searchFailure(invalidEmail, false, t)).toEqual({ field: 'fieldErrors.invalid-email' });
    const tooLong = view({
      code: 'validation-failed',
      status: 400,
      fields: { q: { code: 'too-long', message: 'x' } },
    });
    expect(searchFailure(tooLong, false, t)).toEqual({ field: 'fieldErrors.too-long' });
    const format = view({
      code: 'validation-failed',
      status: 400,
      fields: { q: { code: 'invalid-format', message: 'x' } },
    });
    expect(searchFailure(format, false, t)).toEqual({ field: 'adminSearch.errors.invalidFormat' });
    expect(searchFailure(format, true, t)).toEqual({ field: 'adminSearch.errors.invalidFormatAuditor' });
    expect(searchFailure(view({ code: 'validation-failed', status: 400 }), false, t)).toEqual({
      field: 'adminSearch.errors.invalidFormat',
    });
    expect(searchFailure(view({ code: 'read-only-role', status: 403 }), true, t)).toEqual({
      field: 'adminSearch.errors.auditorAddress',
    });
  });

  it('gives the wait of the rate limit', () => {
    expect(
      searchFailure(view({ code: 'rate-limited', status: 429, retryAfterSeconds: 20 }), false, t),
    ).toEqual({
      message: 'adminSearch.errors.rateLimited {"wait":"opsTransfers.wait.seconds {\\"count\\":20}"}',
    });
    expect(searchFailure(view({ code: 'rate-limited', status: 429 }), false, t)).toEqual({
      message: 'adminSearch.errors.rateLimitedNow',
    });
  });

  it('gives the general message otherwise', () => {
    expect(searchFailure(view({ status: 500, code: 'internal' }), false, t)).toEqual({
      message: 'General message',
    });
  });
});

describe('signalQueryError', () => {
  it('moves the focus to the input when it is elsewhere (its description reads the error)', () => {
    const input = { focus: vi.fn() };
    const say = vi.fn();
    signalQueryError(input, { other: true }, 'Bad query', t, say);
    expect(input.focus).toHaveBeenCalledOnce();
    expect(say).not.toHaveBeenCalled();
    signalQueryError(input, null, 'Bad query', t, say);
    expect(input.focus).toHaveBeenCalledTimes(2);
    expect(say).not.toHaveBeenCalled();
  });

  it('announces the error when the input already has the focus (sent with Enter)', () => {
    const input = { focus: vi.fn() };
    const say = vi.fn();
    signalQueryError(input, input, 'Bad query', t, say);
    expect(input.focus).not.toHaveBeenCalled();
    expect(say).toHaveBeenCalledWith('components.field.errorPrefix Bad query');
  });

  it('announces the error without an input to focus', () => {
    const say = vi.fn();
    signalQueryError(undefined, null, 'Bad query', t, say);
    expect(say).toHaveBeenCalledWith('components.field.errorPrefix Bad query');
  });
});

describe('tenant colours', () => {
  it('maps the tenants to their colour', () => {
    expect(tenantColors([{ id: 'a', primaryColor: '#000000' }, { id: 'b' }])).toEqual(
      new Map([
        ['a', '#000000'],
        ['b', undefined],
      ]),
    );
  });

  it('reads the first page of the tenants, and an empty map on failure', async () => {
    const get = vi.fn(async () => ({
      data: { items: [{ id: 'ten_A', primaryColor: '#1D4ED8' }] },
      status: 200,
      headers: new Headers(),
    }));
    expect(await loadTenantColors({ get } as never)).toEqual(new Map([['ten_A', '#1D4ED8']]));
    expect(get).toHaveBeenCalledWith('/admin/tenants', { params: { limit: COLOR_PAGE } });
    const failing = vi.fn(async () => {
      throw new Error('network');
    });
    expect(await loadTenantColors({ get: failing } as never)).toEqual(new Map());
  });
});

describe('translations of the keys built at runtime', () => {
  it('exist in English and in French', () => {
    const keys = [
      'errors.empty',
      'errors.emptyAuditor',
      'errors.invalidFormat',
      'errors.invalidFormatAuditor',
      'form.placeholder',
      'form.placeholderAuditor',
      'form.hint',
      'form.hintAuditor',
      'results.emptyEmail',
      'results.emptyId',
    ];
    for (const key of keys) {
      expect(message(en, key), `en ${key}`).toBeTypeOf('string');
      expect(message(fr, key), `fr ${key}`).toBeTypeOf('string');
    }
  });
});
