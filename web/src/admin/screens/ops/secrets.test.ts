import { describe, expect, it } from 'vitest';
import { SECRET_FILTERS } from './filters';
import { emptyList, type PagedList } from './paging';
import {
  afterSecretDelete,
  canDeleteSecret,
  creatorKindLabel,
  dateOr,
  deliveryText,
  secretStateOptions,
  secretStateView,
  secretsResultText,
  submitSecretFilters,
  type AdminSecret,
} from './secrets';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

function secret(id: string, state: AdminSecret['state'] = 'active'): AdminSecret {
  return {
    id,
    state,
    delivery: 'link',
    readReceipt: false,
    hasFile: false,
    createdAt: '2026-11-01T10:00:00Z',
    creatorKind: 'internal',
    senderEmail: 'alice@entity-a.example.com',
  };
}

describe('filters wiring', () => {
  it('builds the path of valid filters, in the order of the spec', () => {
    expect(
      submitSecretFilters('/tenants/t1/secrets', { state: 'active', sender: ' a@example.com ' }, t),
    ).toEqual({ ok: true, path: '/tenants/t1/secrets?state=active&sender=a%40example.com' });
    expect(submitSecretFilters('/p', { state: '', sender: '' }, t)).toEqual({ ok: true, path: '/p' });
  });

  it('reports a message per invalid field and the first one', () => {
    expect(submitSecretFilters('/p', { state: 'nope', sender: 'bad' }, t)).toEqual({
      ok: false,
      first: 'state',
      errors: { state: 'fieldErrors.invalid-format', sender: 'fieldErrors.invalid-email' },
    });
  });

  it('offers every state after "any state"', () => {
    const options = secretStateOptions(t);
    expect(options[0]).toEqual({ value: '', label: 'adminSecrets.list.stateAny' });
    expect(options.slice(1).map((o) => o.value)).toEqual(SECRET_FILTERS.state.values.map((v) => v as string));
  });
});

describe('labels', () => {
  it('gives a badge per state and the raw text of an unknown one', () => {
    expect(secretStateView('active', t)).toEqual({ variant: 'ok', label: 'adminSecrets.state.active' });
    expect(secretStateView('locked', t).variant).toBe('error');
    expect(secretStateView('future', t)).toEqual({ variant: 'info', label: 'future' });
    expect(secretStateView('toString', t).label).toBe('toString');
  });

  it('describes the delivery', () => {
    expect(deliveryText({ delivery: 'link' }, t)).toBe('adminSecrets.delivery.link');
    expect(deliveryText({ delivery: 'email' }, t)).toBe('adminSecrets.delivery.email');
    expect(deliveryText({ delivery: 'email', recipient: 'b@example.com' }, t)).toContain('b@example.com');
  });

  it('labels the creator kind, raw when unknown', () => {
    expect(creatorKindLabel('api_token', t)).toBe('adminSecrets.creatorKind.api_token');
    expect(creatorKindLabel('robot', t)).toBe('robot');
  });

  it('shows a date or the fallback', () => {
    const fmt = (d: string): string => `<${d}>`;
    expect(dateOr(undefined, 'none', fmt)).toBe('none');
    expect(dateOr('', 'none', fmt)).toBe('none');
    expect(dateOr('2026-11-01', 'none', fmt)).toBe('<2026-11-01>');
  });

  it('words the result of the list', () => {
    expect(secretsResultText(3, false, t)).toContain('adminSecrets.list.loaded ');
    expect(secretsResultText(3, true, t)).toContain('adminSecrets.list.loadedMore');
  });
});

describe('deletion', () => {
  it('only deletes a pending or active secret', () => {
    expect(canDeleteSecret('pending')).toBe(true);
    expect(canDeleteSecret('active')).toBe(true);
    for (const s of ['read', 'expired', 'deleted', 'locked']) {
      expect(canDeleteSecret(s)).toBe(false);
    }
  });

  const list: PagedList<AdminSecret> = { ...emptyList<AdminSecret>(), items: [secret('a'), secret('b')] };

  it('shows the deleted state in an unfiltered list', () => {
    const out = afterSecretDelete(list, 'a', {}, '2026-11-02T00:00:00Z');
    expect(out.items[0]).toMatchObject({ id: 'a', state: 'deleted', endReason: 'deleted' });
    expect(out.items[1]).toBe(list.items[1]);
    expect(afterSecretDelete(list, 'a', { state: 'deleted' }, 'x').items[0]?.state).toBe('deleted');
  });

  it('drops the row of a list filtered on another state, ignores an unknown one', () => {
    expect(afterSecretDelete(list, 'a', { state: 'active' }, 'x').items.map((s) => s.id)).toEqual(['b']);
    expect(afterSecretDelete(list, 'zzz', {}, 'x')).toBe(list);
  });
});
