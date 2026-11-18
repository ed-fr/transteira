import { describe, expect, it } from 'vitest';
import { SECRET_FILTERS } from './filters';
import { emptyList, type PagedList } from './paging';
import {
  afterSecretDelete,
  canDeleteSecret,
  creatorKindLabel,
  creatorText,
  dateOr,
  deliveryText,
  isExpress,
  lookupErrorMessage,
  LOOKUP_MAX_LENGTH,
  lookupInput,
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

describe('express secrets', () => {
  it('tells an express secret, which may have no creator address', () => {
    expect(isExpress(secret('s'))).toBe(false);
    expect(isExpress({ express: true })).toBe(true);
    expect(creatorText({ creatorKind: 'anonymous' }, t)).toBe('adminSecrets.creatorKind.anonymous');
    expect(creatorText({ creatorKind: 'internal', senderEmail: 'a@example.com' }, t)).toBe('a@example.com');
  });
});

describe('lookup', () => {
  const token = `tts_${'A'.repeat(43)}`;

  it('refuses an empty field and a text without token', () => {
    expect(lookupInput('  ', t)).toEqual({ ok: false, message: 'adminSecrets.lookup.errors.required' });
    for (const bad of [
      'hello',
      'tts_short',
      `https://x.example.com/s/${'a'.repeat(60)}`,
      `tts_${'A'.repeat(2100)}`,
    ]) {
      expect(lookupInput(bad, t), bad).toEqual({ ok: false, message: 'adminSecrets.lookup.errors.invalid' });
    }
  });

  it('accepts a bare token or a full link and sends the token only', () => {
    expect(lookupInput(` ${token} `, t)).toEqual({ ok: true, body: { link: token } });
    const link = `https://transfer.entity-a.example.com/s/${token}`;
    expect(lookupInput(`${link}#k=secretkey`, t)).toEqual({ ok: true, body: { link: token } });
    expect(lookupInput(`#k=abc${token}`, t).ok).toBe(false);
    // A token followed by another base62 character is not a token.
    expect(lookupInput(`${token}B`, t).ok).toBe(false);
  });

  it('never sends the key of a percent-encoded or wrapped link (T-408)', () => {
    const key = 'K3yK3yK3yK3yK3yK3yK3yK3yK3yK3yK3yK3yK3yK3yK';
    const encoded = `https%3A%2F%2Ftransfer.entity-a.example.com%2Fs%2F${token}%23k%3D${key}`;
    const safeLinks = `https://eur01.safelinks.protection.outlook.com/?url=${encoded}&data=05%7C02&reserved=0`;
    for (const pasted of [encoded, safeLinks, `${encoded}#k=${key}`]) {
      const got = lookupInput(pasted, t);
      expect(got, pasted).toEqual({ ok: true, body: { link: token } });
      expect(JSON.stringify(got)).not.toContain(key);
    }
    expect(lookupInput(`${safeLinks}${'x'.repeat(LOOKUP_MAX_LENGTH)}`, t).ok).toBe(false);
  });

  it('words the failures', () => {
    expect(lookupErrorMessage({ status: 400, message: 'x' }, t)).toBe('adminSecrets.lookup.errors.invalid');
    expect(lookupErrorMessage({ status: 404, message: 'x' }, t)).toBe('adminSecrets.lookup.errors.notFound');
    expect(lookupErrorMessage({ status: 500, message: 'boom' }, t)).toBe('boom');
    expect(lookupErrorMessage({ status: undefined, message: 'net' }, t)).toBe('net');
  });
});
