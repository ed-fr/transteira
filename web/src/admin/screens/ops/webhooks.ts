// Logic of the webhook screens (CLAUDE.md section 12.4), shared by the tenant webhooks
// (/tenants/:id/webhooks) and the instance-wide webhooks (/system/webhooks), kept out of the
// components so that it is unit tested in Node:
// - the event types each scope may subscribe to (tenant events for a tenant, system events for
//   the instance; webhook.test is never subscribable), their labels and canonical order;
// - client-side checks of the URL (https: or http:, no user information, at most 2048
//   characters; the server applies the network guard and stays authoritative);
// - creation body and merge patch (only the changed fields; an empty URL in the edit form keeps
//   the sealed one, which the API never returns);
// - display of the status (enabled, disabled, suspended by the circuit breaker), of the last
//   delivery and of the outcome of a test (coarse error category only);
// - mapping of the API errors (409 limit of 20 webhooks, url-not-allowed on /url, 429 on the
//   creations and URL changes and on the test button, with Retry-After).
// The signing secret of a generic webhook never goes through this module except to be dropped
// from the webhook kept in the list (withoutSecret).
import {
  webhookErrorCategoryValues,
  webhookEventTypeValues,
  webhookKindValues,
  type components,
} from '../../../shared/api/schema';
import type { ErrorView } from '../../../shared/api/problem';
import type { Translate } from '../../../shared/i18n/messages';
import type { StatusVariant } from '../../components/fields';
import {
  summaryFromFields,
  type FieldRef,
  type SubmitOutcome,
  type SummaryError,
} from '../../components/form';
import { buildPatch } from '../../forms/patch';
import { codePointLength } from './filters';

/** A webhook as listed (never its URL in full nor its secret). */
export type Webhook = components['schemas']['Webhook'];
/** A webhook with its signing secret (creation of a generic webhook, rotation). */
export type WebhookWithSecret = components['schemas']['WebhookWithSecret'];
/** Body of the creation of a webhook. */
export type WebhookCreate = components['schemas']['WebhookCreate'];
/** Merge patch of a webhook. */
export type WebhookUpdate = components['schemas']['WebhookUpdate'];
/** Kind of a webhook (teams, slack, generic). */
export type WebhookKind = components['schemas']['WebhookKind'];
/** Event type delivered to webhooks. */
export type WebhookEventType = components['schemas']['WebhookEventType'];
/** Outcome of the latest delivery attempt. */
export type WebhookDelivery = components['schemas']['WebhookDelivery'];
/** Outcome of a test delivery. */
export type WebhookTestResult = components['schemas']['WebhookTestResult'];
/** Coarse cause of a failed delivery. */
export type WebhookErrorCategory = components['schemas']['WebhookErrorCategory'];

/** Owner of a set of webhooks: one tenant, or the instance (super admin). */
export type WebhookScope = 'tenant' | 'system';

/** Maximum number of webhooks per tenant, and for the instance. */
export const MAX_WEBHOOKS = 20;
/** Maximum length of a webhook name. */
export const WEBHOOK_NAME_MAX = 100;
/** Maximum length of a webhook URL. */
export const WEBHOOK_URL_MAX = 2048;
/** Number of tests allowed per hour, per administrator (and tenant). */
export const WEBHOOK_TESTS_PER_HOUR = 10;
/** Number of creations and URL changes allowed per hour, per administrator (and tenant). */
export const WEBHOOK_URL_CHANGES_PER_HOUR = 30;

/** Kinds of webhooks, in display order. */
export const WEBHOOK_KINDS: readonly WebhookKind[] = webhookKindValues;

/** Events a tenant webhook may subscribe to, in display order. */
export const TENANT_WEBHOOK_EVENTS: readonly WebhookEventType[] = [
  'virus.detected',
  'abuse.threshold_exceeded',
  'abuse.unusual_activity',
  'abuse.reported',
  'quota.warning',
  'quota.reached',
];

/** Events an instance-wide webhook may subscribe to, in display order. */
export const SYSTEM_WEBHOOK_EVENTS: readonly WebhookEventType[] = [
  'disk.alert_raised',
  'disk.alert_cleared',
  'antivirus.alert_raised',
  'antivirus.alert_cleared',
  'maintenance.enabled',
  'maintenance.disabled',
  'master_key.rotation_completed',
  'master_key.rotation_failed',
];

/** Events a webhook of scope may subscribe to. */
export function webhookEvents(scope: WebhookScope): readonly WebhookEventType[] {
  return scope === 'system' ? SYSTEM_WEBHOOK_EVENTS : TENANT_WEBHOOK_EVENTS;
}

// ---- Labels -------------------------------------------------------------------------------------

/** Reports whether value is an event type of this version of the specification. */
export function isKnownEvent(value: string): value is WebhookEventType {
  return (webhookEventTypeValues as readonly string[]).includes(value);
}

/** Label of an event type: translated when known, the raw code otherwise. */
export function eventLabel(event: string, t: Translate): string {
  return isKnownEvent(event) ? t(`opsWebhooks.events.${event}`) : event;
}

/** Label of a kind: translated when known, the raw code otherwise. */
export function kindLabel(kind: string, t: Translate): string {
  return (WEBHOOK_KINDS as readonly string[]).includes(kind) ? t(`opsWebhooks.kinds.${kind}`) : kind;
}

/** Label of an error category: translated when known, the raw code otherwise. */
export function categoryLabel(category: string, t: Translate): string {
  return (webhookErrorCategoryValues as readonly string[]).includes(category)
    ? t(`opsWebhooks.categories.${category}`)
    : category;
}

/**
 * Sorts events in the order of the specification (unknown ones last, alphabetically), without
 * duplicates: the canonical form compared by the merge patch and sent to the API.
 */
export function sortEvents(events: readonly string[]): WebhookEventType[] {
  const rank = (e: string): number => {
    const i = (webhookEventTypeValues as readonly string[]).indexOf(e);
    return i < 0 ? Number.MAX_SAFE_INTEGER : i;
  };
  return [...new Set(events)].sort(
    (a, b) => rank(a) - rank(b) || (a < b ? -1 : a > b ? 1 : 0),
  ) as WebhookEventType[];
}

/** Adds or removes an event of a selection (the checkboxes of the form). */
export function toggleEvent(
  events: readonly WebhookEventType[],
  event: WebhookEventType,
  on: boolean,
): WebhookEventType[] {
  const rest = events.filter((e) => e !== event);
  return on ? sortEvents([...rest, event]) : rest;
}

/** Sorts webhooks for display: by name, then by creation date. */
export function sortWebhooks(webhooks: readonly Webhook[]): Webhook[] {
  return [...webhooks].sort(
    (a, b) => a.name.localeCompare(b.name) || Date.parse(a.createdAt) - Date.parse(b.createdAt),
  );
}

/** The webhook without its secret, as kept in the list after a creation or a rotation. */
export function withoutSecret(webhook: WebhookWithSecret): Webhook {
  const copy: WebhookWithSecret = { ...webhook };
  delete copy.secret;
  return copy;
}

/** Signing secret of an answer, or "" when none was returned. */
export function secretOf(webhook: WebhookWithSecret): string {
  return webhook.secret ?? '';
}

/** Reports whether the secret of a webhook can be rotated (generic kind only). */
export function canRotate(webhook: Pick<Webhook, 'kind'>): boolean {
  return webhook.kind === 'generic';
}

// ---- Status ---------------------------------------------------------------------------------------

/** Status of a webhook at a given instant. */
export type WebhookStatus = 'enabled' | 'disabled' | 'suspended';

/** End of the suspension by the circuit breaker when it is still running at now, else undefined. */
export function circuitOpenUntil(webhook: Pick<Webhook, 'circuitOpenUntil'>, now: Date): string | undefined {
  const until = webhook.circuitOpenUntil;
  if (until === undefined || until === null) {
    return undefined;
  }
  const at = Date.parse(until);
  return !Number.isNaN(at) && at > now.getTime() ? until : undefined;
}

/** Status of webhook at now: disabled first, then suspended while the circuit breaker is open. */
export function webhookStatus(
  webhook: Pick<Webhook, 'enabled' | 'circuitOpenUntil'>,
  now: Date,
): WebhookStatus {
  if (!webhook.enabled) {
    return 'disabled';
  }
  return circuitOpenUntil(webhook, now) !== undefined ? 'suspended' : 'enabled';
}

/** Badge of a status (the label always says the status, never the colour alone). */
export function statusView(status: WebhookStatus): { variant: StatusVariant; key: string } {
  switch (status) {
    case 'enabled':
      return { variant: 'ok', key: 'opsWebhooks.status.enabled' };
    case 'suspended':
      return { variant: 'warning', key: 'opsWebhooks.status.suspended' };
    default:
      return { variant: 'missing', key: 'opsWebhooks.status.disabled' };
  }
}

/** Badge of the last delivery: none yet, success or failure. */
export function deliveryView(delivery: WebhookDelivery | null | undefined): {
  variant: StatusVariant;
  key: string;
} {
  if (delivery === undefined || delivery === null) {
    return { variant: 'info', key: 'opsWebhooks.delivery.never' };
  }
  return delivery.success
    ? { variant: 'ok', key: 'opsWebhooks.delivery.success' }
    : { variant: 'error', key: 'opsWebhooks.delivery.failure' };
}

/**
 * Details of a delivery or test outcome: the HTTP status when there was an answer, else the
 * coarse cause, then the duration ("HTTP 200 · 182 ms", "Timeout · 10,002 ms").
 */
export function outcomeDetail(
  outcome: Pick<WebhookDelivery, 'httpStatus' | 'errorCategory' | 'durationMs'>,
  t: Translate,
): string {
  const parts: string[] = [];
  if (outcome.httpStatus !== undefined) {
    parts.push(t('opsWebhooks.delivery.httpStatus', { status: outcome.httpStatus }));
  } else if (outcome.errorCategory !== undefined) {
    parts.push(categoryLabel(outcome.errorCategory, t));
  }
  parts.push(t('opsWebhooks.delivery.duration', { ms: outcome.durationMs }));
  return parts.join(' · ');
}

/** Message of the outcome of a test delivery (shown in a live region next to the button). */
export function testResultMessage(
  name: string,
  result: WebhookTestResult,
  t: Translate,
): { severity: 'success' | 'error'; text: string } {
  const detail = outcomeDetail(result, t);
  if (result.success) {
    return { severity: 'success', text: t('opsWebhooks.test.success', { name, detail }) };
  }
  const cause =
    result.errorCategory !== undefined
      ? categoryLabel(result.errorCategory, t)
      : t('opsWebhooks.categories.unknown');
  return { severity: 'error', text: t('opsWebhooks.test.failure', { name, cause, detail }) };
}

/** Message of a test refused by the API: 429 (with the wait when known), 404, or the general one. */
export function testErrorMessage(view: ErrorView, t: Translate): string {
  if (view.status === 429 || view.code === 'rate-limited') {
    const seconds = view.retryAfterSeconds;
    if (seconds !== undefined && seconds > 0) {
      return t('opsWebhooks.test.rateLimitedRetry', {
        max: WEBHOOK_TESTS_PER_HOUR,
        minutes: Math.max(1, Math.ceil(seconds / 60)),
      });
    }
    return t('opsWebhooks.test.rateLimited', { max: WEBHOOK_TESTS_PER_HOUR });
  }
  if (view.status === 404) {
    return t('opsWebhooks.errors.notFound');
  }
  return view.message;
}

// ---- URL --------------------------------------------------------------------------------------------

/** Reasons for which a URL is refused before it is sent. */
export type UrlError = 'required' | 'invalid' | 'scheme' | 'credentials' | 'too-long';

/**
 * Checks a webhook URL: an absolute http: or https: URL (the URL parser requires a host for
 * these schemes), without user information, at most 2048 characters. Whether http: and the
 * resolved address are allowed is decided by the server (network guard, url-not-allowed).
 */
export function checkWebhookUrl(input: string): UrlError | undefined {
  const s = input.trim();
  if (s === '') {
    return 'required';
  }
  if (s.length > WEBHOOK_URL_MAX) {
    return 'too-long';
  }
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return 'invalid';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return 'scheme';
  }
  if (url.username !== '' || url.password !== '') {
    return 'credentials';
  }
  return undefined;
}

const URL_ERROR_KEYS: Record<UrlError, string> = {
  required: 'fieldErrors.required',
  invalid: 'opsWebhooks.errors.urlInvalid',
  scheme: 'opsWebhooks.errors.urlScheme',
  credentials: 'opsWebhooks.errors.urlCredentials',
  'too-long': 'opsWebhooks.errors.urlTooLong',
};

// ---- Forms ------------------------------------------------------------------------------------------

/** Fields of the creation and edition forms. */
export interface WebhookForm {
  name: string;
  kind: WebhookKind;
  /** Full URL; in the edition form, empty keeps the current (sealed) URL. */
  url: string;
  events: WebhookEventType[];
  enabled: boolean;
}

/** Empty creation form: a generic webhook, enabled, without events. */
export function emptyWebhookForm(): WebhookForm {
  return { name: '', kind: 'generic', url: '', events: [], enabled: true };
}

/** Reports whether the creation form holds something typed or chosen. */
export function createFormTouched(form: WebhookForm): boolean {
  const empty = emptyWebhookForm();
  return (
    form.name.trim() !== '' ||
    form.url.trim() !== '' ||
    form.events.length > 0 ||
    form.kind !== empty.kind ||
    form.enabled !== empty.enabled
  );
}

/** Edition form of a webhook (the URL is never returned: the field starts empty). */
export function editFormFrom(webhook: Webhook): WebhookForm {
  return {
    name: webhook.name,
    kind: webhook.kind,
    url: '',
    events: sortEvents(webhook.events),
    enabled: webhook.enabled,
  };
}

/** Body of the creation. */
export function createBody(form: WebhookForm): WebhookCreate {
  return {
    name: form.name.trim(),
    kind: form.kind,
    url: form.url.trim(),
    events: sortEvents(form.events),
    enabled: form.enabled,
  };
}

/**
 * Merge patch of an edited webhook: only the fields that changed, and the URL when a new one was
 * typed. The kind cannot be changed.
 */
export function buildWebhookPatch(webhook: Webhook, form: WebhookForm): WebhookUpdate {
  const original = { name: webhook.name, events: sortEvents(webhook.events), enabled: webhook.enabled };
  const edited = { name: form.name.trim(), events: sortEvents(form.events), enabled: form.enabled };
  const patch: WebhookUpdate = buildPatch(original, edited, ['name', 'events', 'enabled']);
  const url = form.url.trim();
  if (url !== '') {
    patch.url = url;
  }
  return patch;
}

/** The fields of the webhook forms, for the error summary (keys are the API field names). */
export interface WebhookFields {
  name: FieldRef;
  kind?: FieldRef;
  url: FieldRef;
  events: FieldRef;
  enabled?: FieldRef;
}

function push(
  out: SummaryError[],
  ref: FieldRef | undefined,
  key: string | undefined,
  t: Translate,
  params?: Record<string, string | number>,
): void {
  if (ref !== undefined && key !== undefined) {
    out.push({ id: ref.id, label: ref.label, message: t(key, params) });
  }
}

/**
 * Client-side validation of a form: name (required, at most 100 characters), URL (required on
 * creation, checked when typed), events (at least one, all of the scope).
 */
export function validateWebhookForm(
  form: WebhookForm,
  fields: WebhookFields,
  t: Translate,
  options: { scope: WebhookScope; creating: boolean },
): SummaryError[] {
  const out: SummaryError[] = [];
  const name = form.name.trim();
  if (name === '') {
    push(out, fields.name, 'fieldErrors.required', t);
  } else if (codePointLength(name) > WEBHOOK_NAME_MAX) {
    push(out, fields.name, 'opsWebhooks.errors.nameTooLong', t, { max: WEBHOOK_NAME_MAX });
  }
  if (options.creating || form.url.trim() !== '') {
    const urlError = checkWebhookUrl(form.url);
    push(out, fields.url, urlError === undefined ? undefined : URL_ERROR_KEYS[urlError], t, {
      max: WEBHOOK_URL_MAX,
    });
  }
  const allowed = webhookEvents(options.scope);
  if (form.events.length === 0) {
    push(out, fields.events, 'opsWebhooks.errors.eventsRequired', t);
  } else if (form.events.some((e) => !allowed.includes(e))) {
    push(out, fields.events, 'opsWebhooks.errors.eventNotAllowed', t);
  }
  return out;
}

// ---- Errors -----------------------------------------------------------------------------------------

/**
 * Outcome of a failed creation or edition: the limit of 20 webhooks on a 409, the limit of 30
 * creations and URL changes per hour on a 429 (with the wait when known), "not found" on a
 * 404, field errors on their fields (url-not-allowed on the URL, /events/<i> on the events),
 * with a general message when some cannot be placed, otherwise the general message.
 */
export function webhookErrorOutcome(view: ErrorView, fields: WebhookFields, t: Translate): SubmitOutcome {
  if (view.status === 409 || view.code === 'state-conflict') {
    return { ok: false, message: t('opsWebhooks.errors.limit', { max: MAX_WEBHOOKS }) };
  }
  if (view.status === 429 || view.code === 'rate-limited') {
    const seconds = view.retryAfterSeconds;
    if (seconds !== undefined && seconds > 0) {
      return {
        ok: false,
        message: t('opsWebhooks.errors.rateLimitedRetry', {
          max: WEBHOOK_URL_CHANGES_PER_HOUR,
          minutes: Math.max(1, Math.ceil(seconds / 60)),
        }),
      };
    }
    return {
      ok: false,
      message: t('opsWebhooks.errors.rateLimited', { max: WEBHOOK_URL_CHANGES_PER_HOUR }),
    };
  }
  if (view.status === 404) {
    return { ok: false, message: t('opsWebhooks.errors.notFound') };
  }
  if (view.code === 'validation-failed') {
    const refs: Record<string, FieldRef> = {};
    for (const [key, ref] of Object.entries(fields) as [string, FieldRef | undefined][]) {
      if (ref !== undefined) {
        refs[key] = ref;
      }
    }
    const { errors, unmatched } = summaryFromFields(view.fields, refs);
    if (errors.length > 0 && unmatched.length === 0) {
      return { ok: false, errors };
    }
    return { ok: false, message: view.message, errors };
  }
  return { ok: false, message: view.message };
}

/** Message of a failed deletion or rotation (the dialog stays open and shows it). */
export function actionErrorMessage(view: ErrorView, t: Translate): string {
  return view.status === 404 ? t('opsWebhooks.errors.notFound') : view.message;
}

// ---- Tenant setting -----------------------------------------------------------------------------------

/** The tenant setting of the webhook payloads, as read on the tenant. */
export function includesAddresses(tenant: { webhookIncludeAddresses?: boolean }): boolean {
  return tenant.webhookIncludeAddresses ?? false;
}

/** Merge patch of the tenant for the "include addresses" switch: empty when unchanged. */
export function includeAddressesPatch(
  tenant: { webhookIncludeAddresses?: boolean },
  value: boolean,
): { webhookIncludeAddresses?: boolean } {
  return includesAddresses(tenant) === value ? {} : { webhookIncludeAddresses: value };
}
