import { describe, expect, it } from 'vitest';
import { ApiProblem } from '../../../shared/api/client';
import type { AdminMe } from '../../auth/machine';
import {
  SETUP_ITEM_ORDER,
  cameFromSetup,
  canForce,
  completionBody,
  completionFailure,
  itemLabelKey,
  itemPath,
  missingRequired,
  orderItems,
  remainingMarkers,
  setupPath,
  tenantsInSetup,
  type TenantSetupItem,
} from './setup';

const me = (role: AdminMe['role']): AdminMe =>
  ({
    id: 'a',
    username: 'u',
    email: 'u@example.com',
    role,
    totpEnabled: true,
    tenants: [],
    csrfToken: 'c',
  }) as AdminMe;

function problem(status: number, code: string, errors?: { field: string; code: string }[]): ApiProblem {
  return new ApiProblem(status, { type: 'about:blank', title: 't', status, code, errors } as never);
}

describe('checklist order', () => {
  it('orders the known items and keeps unknown ones last, as received', () => {
    const items = [
      { key: 'future_b', required: false, done: false },
      { key: 'mail_templates', required: false, done: false },
      { key: 'branding_logo', required: true, done: true },
      { key: 'future_a', required: true, done: false },
      { key: 'smtp', required: true, done: false },
    ] as unknown as TenantSetupItem[];
    expect(orderItems(items).map((i) => i.key)).toEqual([
      'branding_logo',
      'smtp',
      'mail_templates',
      'future_b',
      'future_a',
    ]);
    expect(items[0]?.key).toBe('future_b');
  });

  it('lists the required items not done, in order', () => {
    const items = [
      { key: 'smtp', required: true, done: false },
      { key: 'branding_logo', required: false, done: false },
      { key: 'branding_colors', required: true, done: false },
      { key: 'internal_domains', required: true, done: true },
    ] as TenantSetupItem[];
    expect(missingRequired(items).map((i) => i.key)).toEqual(['branding_colors', 'smtp']);
  });

  it('declares the eight items of the contract', () => {
    expect(SETUP_ITEM_ORDER).toHaveLength(8);
    expect(itemLabelKey('smtp')).toBe('setup.items.smtp.label');
  });
});

describe('links to the configuration screens', () => {
  it('points each known item to its screen with the way back', () => {
    expect(itemPath('t1', 'branding_logo')).toBe('/tenants/t1/branding?from=setup');
    expect(itemPath('t1', 'branding_colors')).toBe('/tenants/t1/branding?from=setup');
    expect(itemPath('t1', 'smtp')).toBe('/tenants/t1/smtp?from=setup');
    expect(itemPath('t1', 'internal_networks')).toBe('/tenants/t1/network?from=setup');
    expect(itemPath('t1', 'internal_domains')).toBe('/tenants/t1/network?from=setup');
    expect(itemPath('t1', 'legal_notice')).toBe('/tenants/t1/legal?from=setup');
    expect(itemPath('t1', 'privacy_policy')).toBe('/tenants/t1/legal?from=setup');
    expect(itemPath('t1', 'mail_templates')).toBe('/tenants/t1/templates?from=setup');
    expect(itemPath('t1', 'something_new')).toBeUndefined();
    expect(setupPath('a/b')).toBe('/tenants/a%2Fb/setup');
  });

  it('recognises a navigation coming from the wizard', () => {
    expect(cameFromSetup('?from=setup')).toBe(true);
    expect(cameFromSetup('?x=1&from=setup')).toBe(true);
    expect(cameFromSetup('?from=other')).toBe(false);
    expect(cameFromSetup('')).toBe(false);
  });
});

describe('completion', () => {
  it('sends force only for a super admin who asked for it', () => {
    expect(completionBody({ force: true, mailTemplatesReviewed: true, me: me('super_admin') })).toEqual({
      force: true,
      mailTemplatesReviewed: true,
    });
    expect(completionBody({ force: false, mailTemplatesReviewed: false, me: me('super_admin') })).toEqual({
      mailTemplatesReviewed: false,
    });
    expect(completionBody({ force: true, mailTemplatesReviewed: true, me: me('delegated_admin') })).toEqual({
      mailTemplatesReviewed: true,
    });
    expect(completionBody({ force: true, mailTemplatesReviewed: false, me: undefined })).toEqual({
      mailTemplatesReviewed: false,
    });
    expect(canForce(me('super_admin'))).toBe(true);
    expect(canForce(me('delegated_admin'))).toBe(false);
    expect(canForce(undefined)).toBe(false);
  });

  it('maps the completion errors', () => {
    expect(
      completionFailure(
        problem(409, 'setup-incomplete', [
          { field: 'smtp', code: 'not-done' },
          { field: 'x', code: 'other' },
          { field: 'legal_notice', code: 'not-done' },
        ]),
      ),
    ).toEqual({ kind: 'incomplete', missing: ['smtp', 'legal_notice'] });
    expect(completionFailure(problem(409, 'setup-incomplete'))).toEqual({ kind: 'incomplete', missing: [] });
    expect(completionFailure(problem(409, 'setup-already-complete'))).toEqual({ kind: 'already-complete' });
    expect(completionFailure(problem(403, 'forbidden'))).toEqual({ kind: 'forbidden' });
    expect(completionFailure(problem(503, 'tenant-in-setup'))).toEqual({ kind: 'other' });
    expect(completionFailure(new Error('x'))).toEqual({ kind: 'other' });
  });
});

describe('placeholders of a proposed text', () => {
  it('finds the case-sensitive prefix of both languages, escaped or not', () => {
    const text =
      'a [À compléter : adresse] b [To complete: DPO] c [A compléter : x] d [à compléter : y] e \\[À compléter]';
    expect(remainingMarkers(text)).toEqual(['[À compléter', '[To complete', '\\[À compléter']);
  });

  it('finds nothing in a completed text or in an ordinary link', () => {
    expect(remainingMarkers('Contact : [mail](mailto:dpo@example.com)')).toEqual([]);
    expect(remainingMarkers('')).toEqual([]);
  });
});

describe('tenants in setup', () => {
  it('keeps the tenants in the setup state', () => {
    expect(
      tenantsInSetup([{ setupState: 'setup' }, { setupState: 'active' }, {}]).map((t) => t.setupState),
    ).toEqual(['setup']);
  });
});
