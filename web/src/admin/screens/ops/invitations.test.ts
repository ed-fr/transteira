import { describe, expect, it } from 'vitest';
import en from '../../../locales/en/opsInvitations.json';
import fr from '../../../locales/fr/opsInvitations.json';
import {
  afterRevoke,
  canRevoke,
  invitationStatusView,
  isErasedIssuer,
  isRevocableStatus,
  issuerText,
  loadedText,
  statusFilterOptions,
  type Invitation,
  type Translate,
} from './invitations';
import { emptyList, receivePage, startReset, type PagedList } from './paging';

const fakeT: Translate = (key, params) => (params === undefined ? key : `${key} ${JSON.stringify(params)}`);

function lookup(bundle: unknown, key: string): unknown {
  const [area, ...path] = key.split('.');
  let node: unknown = area === 'opsInvitations' ? bundle : undefined;
  for (const part of path) {
    node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
  }
  return node;
}

/** Records the keys asked by a module and checks they exist in both languages. */
function recordingT(): { t: Translate; keys: string[] } {
  const keys: string[] = [];
  return {
    keys,
    t: (key, params) => {
      keys.push(key);
      return fakeT(key, params);
    },
  };
}

function invitation(over: Partial<Invitation> = {}): Invitation {
  return {
    id: 'inv_1',
    email: 'bob@partner.example.org',
    invitedBy: 'alice@entity-a.example.com',
    status: 'pending',
    createdAt: '2026-10-19T16:00:00Z',
    expiresAt: '2027-10-19T16:00:00Z',
    ...over,
  };
}

function listOf(...rows: Invitation[]): PagedList<Invitation> {
  const s = startReset(emptyList<Invitation>());
  return receivePage(s, s.generation, { items: rows });
}

describe('invitationStatusView', () => {
  it('maps each known status to a translated label and a variant', () => {
    expect(invitationStatusView('pending', fakeT)).toEqual({
      variant: 'info',
      label: 'opsInvitations.status.pending',
    });
    expect(invitationStatusView('used', fakeT)).toEqual({
      variant: 'ok',
      label: 'opsInvitations.status.used',
    });
    expect(invitationStatusView('expired', fakeT)).toEqual({
      variant: 'warning',
      label: 'opsInvitations.status.expired',
    });
    expect(invitationStatusView('revoked', fakeT)).toEqual({
      variant: 'error',
      label: 'opsInvitations.status.revoked',
    });
  });

  it('shows an unknown status as is with a neutral badge', () => {
    expect(invitationStatusView('suspended', fakeT)).toEqual({ variant: 'info', label: 'suspended' });
    expect(invitationStatusView('toString', fakeT)).toEqual({ variant: 'info', label: 'toString' });
  });
});

describe('erased issuer', () => {
  it('detects the GDPR pseudonym only', () => {
    expect(isErasedIssuer('erased-0123456789abcdef')).toBe(true);
    expect(isErasedIssuer('erased-0123456789ABCDEF')).toBe(false);
    expect(isErasedIssuer('erased-0123')).toBe(false);
    expect(isErasedIssuer('erased-0123456789abcdef@example.com')).toBe(false);
    expect(isErasedIssuer('alice@entity-a.example.com')).toBe(false);
  });

  it('shows "Erased address" instead of the pseudonym', () => {
    expect(issuerText('erased-0123456789abcdef', fakeT)).toBe('opsInvitations.erasedIssuer');
    expect(issuerText('alice@entity-a.example.com', fakeT)).toBe('alice@entity-a.example.com');
  });
});

describe('revocation', () => {
  it('offers it for pending and used invitations only', () => {
    expect(isRevocableStatus('pending')).toBe(true);
    expect(isRevocableStatus('used')).toBe(true);
    expect(isRevocableStatus('expired')).toBe(false);
    expect(isRevocableStatus('revoked')).toBe(false);
    expect(isRevocableStatus('unknown')).toBe(false);
  });

  it('is not offered once the expiry date has passed', () => {
    const now = Date.parse('2026-11-01T00:00:00Z');
    expect(canRevoke(invitation(), now)).toBe(true);
    expect(canRevoke(invitation({ status: 'used' }), now)).toBe(true);
    expect(canRevoke(invitation({ expiresAt: '2026-10-31T00:00:00Z' }), now)).toBe(false);
    expect(canRevoke(invitation({ status: 'revoked' }), now)).toBe(false);
    expect(canRevoke(invitation({ expiresAt: 'not a date' }), now)).toBe(true);
    expect(canRevoke(invitation({ expiresAt: '2999-01-01T00:00:00Z' }))).toBe(true);
  });

  it('marks the row revoked in an unfiltered or "revoked" list', () => {
    const state = listOf(invitation(), invitation({ id: 'inv_2' }));
    const next = afterRevoke(state, 'inv_1', {});
    expect(next.items.map((r) => r.status)).toEqual(['revoked', 'pending']);
    expect(afterRevoke(state, 'inv_1', { status: 'revoked' }).items[0]?.status).toBe('revoked');
    expect(afterRevoke(state, 'inv_9', {})).toBe(state);
  });

  it('removes the row from a list filtered on another status', () => {
    const state = listOf(invitation(), invitation({ id: 'inv_2' }));
    expect(afterRevoke(state, 'inv_1', { status: 'pending' }).items.map((r) => r.id)).toEqual(['inv_2']);
  });
});

describe('filter options and result text', () => {
  it('lists "all" then each status', () => {
    const options = statusFilterOptions(fakeT);
    expect(options.map((o) => o.value)).toEqual(['', 'pending', 'used', 'expired', 'revoked']);
    expect(options[0]?.label).toBe('opsInvitations.filters.allStatuses');
  });

  it('counts the loaded invitations', () => {
    expect(loadedText(3, false, fakeT)).toBe('opsInvitations.loaded {"count":3}');
    expect(loadedText(50, true, fakeT)).toBe('opsInvitations.loadedMore {"count":50}');
  });
});

describe('message keys', () => {
  it('exist in English and French', () => {
    const rec = recordingT();
    for (const s of ['pending', 'used', 'expired', 'revoked']) {
      invitationStatusView(s, rec.t);
    }
    issuerText('erased-0123456789abcdef', rec.t);
    statusFilterOptions(rec.t);
    loadedText(1, false, rec.t);
    loadedText(1, true, rec.t);
    expect(rec.keys.length).toBeGreaterThan(0);
    for (const key of rec.keys) {
      expect(lookup(en, key), key).toBeDefined();
      expect(lookup(fr, key), key).toBeDefined();
    }
  });
});
