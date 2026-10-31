// Logic of the tenant setup wizard ("Mise en service", API 1.2), kept out of the components so
// that it is unit tested in Node: ordering of the checklist (unknown future items last), the
// existing screen that configures each item, the completion body (force reserved to the super
// admin), the mapping of the completion errors, and the detection of the placeholders left in a
// proposed legal text.
import { ApiProblem } from '../../../shared/api/client';
import type { components } from '../../../shared/api/schema';
import type { AdminMe } from '../../auth/machine';
import { tenantPath, type TenantSection } from '../../shell';

/** Setup state and checklist of a tenant. */
export type TenantSetup = components['schemas']['TenantSetup'];
/** One item of the checklist. */
export type TenantSetupItem = components['schemas']['TenantSetupItem'];
/** Body of the completion. */
export type TenantSetupCompletion = components['schemas']['TenantSetupCompletion'];

/** Query string added to the links of the wizard so that the screens offer a way back. */
export const FROM_SETUP = 'from=setup';

/** Items known to this interface, in the order of the wizard. */
export const SETUP_ITEM_ORDER = [
  'branding_logo',
  'branding_colors',
  'smtp',
  'internal_networks',
  'internal_domains',
  'legal_notice',
  'privacy_policy',
  'mail_templates',
] as const;

/** Screen (section of the tenant) that configures each known item. */
const ITEM_SECTION: Record<(typeof SETUP_ITEM_ORDER)[number], TenantSection> = {
  branding_logo: 'branding',
  branding_colors: 'branding',
  smtp: 'smtp',
  internal_networks: 'network',
  internal_domains: 'network',
  legal_notice: 'legal',
  privacy_policy: 'legal',
  mail_templates: 'templates',
};

function isKnown(key: string): key is (typeof SETUP_ITEM_ORDER)[number] {
  return (SETUP_ITEM_ORDER as readonly string[]).includes(key);
}

/** Items in wizard order: the known ones in their order, then the unknown ones as received. */
export function orderItems(items: readonly TenantSetupItem[]): TenantSetupItem[] {
  const rank = (key: string): number => {
    const at = (SETUP_ITEM_ORDER as readonly string[]).indexOf(key);
    return at === -1 ? SETUP_ITEM_ORDER.length : at;
  };
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => rank(a.item.key) - rank(b.item.key) || a.index - b.index)
    .map(({ item }) => item);
}

/** Translation key of the label of an item; callers fall back to the raw key when unknown. */
export function itemLabelKey(key: string): string {
  return `setup.items.${key}.label`;
}

/** Translation key of the explanation of an item. */
export function itemHintKey(key: string): string {
  return `setup.items.${key}.hint`;
}

/** Application path of the screen configuring an item (with the way back), undefined if unknown. */
export function itemPath(tenantId: string, key: string): string | undefined {
  return isKnown(key) ? `${tenantPath(tenantId, ITEM_SECTION[key])}?${FROM_SETUP}` : undefined;
}

/** Required items not done yet. */
export function missingRequired(items: readonly TenantSetupItem[]): TenantSetupItem[] {
  return orderItems(items).filter((item) => item.required && !item.done);
}

/** Reports whether a query string (with its "?") comes from the wizard. */
export function cameFromSetup(search: string): boolean {
  return new URLSearchParams(search).get('from') === 'setup';
}

/** Reports whether the admin is a super admin (the only role allowed to force the opening). */
export function canForce(me: AdminMe | undefined): boolean {
  return me?.role === 'super_admin';
}

/** Body of the completion; force is only ever sent by a super admin that asked for it. */
export function completionBody(opts: {
  force: boolean;
  mailTemplatesReviewed: boolean;
  me: AdminMe | undefined;
}): TenantSetupCompletion {
  return {
    ...(opts.force && canForce(opts.me) ? { force: true } : {}),
    mailTemplatesReviewed: opts.mailTemplatesReviewed,
  };
}

/** Outcome of a failed completion. */
export type CompletionFailure =
  | { kind: 'incomplete'; missing: string[] }
  | { kind: 'already-complete' }
  | { kind: 'forbidden' }
  | { kind: 'other' };

/** Maps the error of POST .../setup/complete (409 setup-incomplete, 409 setup-already-complete, 403). */
export function completionFailure(err: unknown): CompletionFailure {
  if (err instanceof ApiProblem) {
    if (err.status === 409 && err.code === 'setup-incomplete') {
      const missing = (err.errors ?? [])
        .filter((e) => e.code === 'not-done')
        .map((e) => e.field)
        .filter((field): field is string => typeof field === 'string');
      return { kind: 'incomplete', missing };
    }
    if (err.status === 409 && err.code === 'setup-already-complete') {
      return { kind: 'already-complete' };
    }
    if (err.status === 403) {
      return { kind: 'forbidden' };
    }
  }
  return { kind: 'other' };
}

/**
 * Marker left in a proposed text, as the server counts it: the case-sensitive prefix "[À compléter"
 * or "[To complete" (also when the bracket is escaped, "\\[À compléter").
 */
const MARKER = /\\?\[(?:À compléter|To complete)/gu;

/** Placeholders still present in a Markdown text (the server remains authoritative). */
export function remainingMarkers(markdown: string): string[] {
  return markdown.match(MARKER) ?? [];
}

/** Wizard link of a tenant. */
export function setupPath(tenantId: string): string {
  return tenantPath(tenantId, 'setup');
}

/** Tenants of a list that are still being set up. */
export function tenantsInSetup<T extends { setupState?: string | undefined }>(tenants: readonly T[]): T[] {
  return tenants.filter((tenant) => tenant.setupState === 'setup');
}
