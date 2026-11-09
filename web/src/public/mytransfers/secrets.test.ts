import { describe, expect, it } from 'vitest';
import { ApiProblem } from '../../shared/api/client';
import {
  canDeleteMySecret,
  markSecretDeleted,
  secretDeleteFailure,
  secretDeliveryKey,
  secretListSilent,
  secretStateKey,
  type MySecret,
} from './secrets';

const problem = (status: number): ApiProblem =>
  new ApiProblem(status, { type: 'x', title: 'x', status } as never);

function secret(id: string, state: MySecret['state'] = 'active'): MySecret {
  return {
    id,
    state,
    delivery: 'link',
    readReceipt: false,
    hasFile: false,
    createdAt: '2026-11-01T10:00:00Z',
  };
}

describe('labels', () => {
  it('maps states and deliveries to keys', () => {
    expect(secretStateKey('read')).toBe('myTransfers.secrets.state.read');
    expect(secretStateKey('future')).toBe('myTransfers.secrets.state.unknown');
    expect(secretDeliveryKey('email')).toBe('myTransfers.secrets.delivery.email');
    expect(secretDeliveryKey('link')).toBe('myTransfers.secrets.delivery.link');
  });
});

describe('deletion', () => {
  it('only offers it before the secret ends', () => {
    expect(canDeleteMySecret(secret('a', 'pending'))).toBe(true);
    expect(canDeleteMySecret(secret('a', 'active'))).toBe(true);
    expect(canDeleteMySecret(secret('a', 'read'))).toBe(false);
    expect(canDeleteMySecret(secret('a', 'locked'))).toBe(false);
  });

  it('marks only the deleted row', () => {
    const out = markSecretDeleted([secret('a'), secret('b')], 'a', '2026-11-02T00:00:00Z');
    expect(out[0]).toMatchObject({ state: 'deleted', endReason: 'deleted', endedAt: '2026-11-02T00:00:00Z' });
    expect(out[1]?.state).toBe('active');
  });

  it('classifies the failures', () => {
    expect(secretDeleteFailure(problem(401))).toBe('session-expired');
    expect(secretDeleteFailure(problem(404))).toBe('gone');
    expect(secretDeleteFailure(problem(500))).toBe('error');
    expect(secretDeleteFailure(new Error('network'))).toBe('error');
  });
});

describe('loading', () => {
  it('stays silent only when the tenant does not offer secrets', () => {
    expect(secretListSilent(problem(404))).toBe(true);
    expect(
      secretListSilent(
        new ApiProblem(403, { type: 'x', title: 'x', status: 403, code: 'secrets-disabled' } as never),
      ),
    ).toBe(true);
    expect(secretListSilent(problem(403))).toBe(false);
    expect(secretListSilent(problem(500))).toBe(false);
    expect(secretListSilent(new Error('network'))).toBe(false);
  });
});
