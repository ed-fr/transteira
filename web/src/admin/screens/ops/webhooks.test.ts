import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  webhookErrorCategoryValues,
  webhookEventTypeValues,
  webhookKindValues,
} from '../../../shared/api/schema';
import en from '../../../locales/en/opsWebhooks.json';
import fr from '../../../locales/fr/opsWebhooks.json';
import {
  MAX_WEBHOOKS,
  SYSTEM_WEBHOOK_EVENTS,
  TENANT_WEBHOOK_EVENTS,
  WEBHOOK_NAME_MAX,
  WEBHOOK_URL_CHANGES_PER_HOUR,
  WEBHOOK_URL_MAX,
  actionErrorMessage,
  buildWebhookPatch,
  canRotate,
  categoryLabel,
  checkWebhookUrl,
  circuitOpenUntil,
  createBody,
  createFormTouched,
  deliveryView,
  editFormFrom,
  emptyWebhookForm,
  eventLabel,
  includeAddressesPatch,
  includesAddresses,
  isKnownEvent,
  kindLabel,
  outcomeDetail,
  secretOf,
  sortEvents,
  sortWebhooks,
  statusView,
  testErrorMessage,
  testResultMessage,
  toggleEvent,
  validateWebhookForm,
  webhookErrorOutcome,
  webhookEvents,
  webhookStatus,
  withoutSecret,
  type Webhook,
  type WebhookForm,
  type WebhookStatus,
} from './webhooks';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const fields = {
  name: { id: 'name', label: 'Name' },
  url: { id: 'url', label: 'URL' },
  events: { id: 'events-0', label: 'Events' },
  enabled: { id: 'enabled', label: 'Enabled' },
};

const NOW = new Date('2026-10-27T10:00:00Z');

function webhook(over: Partial<Webhook> = {}): Webhook {
  return {
    id: 'whk_1',
    name: 'Security team channel',
    kind: 'teams',
    urlHint: 'https://entity-a.webhook.example.com',
    events: ['virus.detected', 'abuse.reported'],
    enabled: true,
    hasSecret: false,
    createdBy: 'admin.entity-a',
    createdAt: '2026-10-20T08:00:00Z',
    updatedAt: '2026-10-20T08:00:00Z',
    lastDelivery: null,
    circuitOpenUntil: null,
    ...over,
  };
}

function view(over: Partial<ErrorView> = {}): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'general',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...over,
  };
}

function form(over: Partial<WebhookForm> = {}): WebhookForm {
  return { ...emptyWebhookForm(), ...over };
}

function hasKey(bundle: unknown, key: string): boolean {
  const parts = key.replace(/^opsWebhooks\./, '').split('.');
  let node: unknown = bundle;
  for (const p of parts) {
    if (typeof node !== 'object' || node === null || !Object.hasOwn(node, p)) {
      return false;
    }
    node = (node as Record<string, unknown>)[p];
  }
  return typeof node === 'string';
}

describe('events', () => {
  it('splits the subscribable events between the tenant and the system scopes', () => {
    const all = [...TENANT_WEBHOOK_EVENTS, ...SYSTEM_WEBHOOK_EVENTS];
    expect(new Set(all).size).toBe(all.length);
    // Every event of the specification is offered once, except the test event.
    expect([...all].sort()).toEqual(webhookEventTypeValues.filter((e) => e !== 'webhook.test').sort());
    expect(webhookEvents('tenant')).toBe(TENANT_WEBHOOK_EVENTS);
    expect(webhookEvents('system')).toBe(SYSTEM_WEBHOOK_EVENTS);
    expect(TENANT_WEBHOOK_EVENTS.every((e) => /^(virus|abuse|quota)\./.test(e))).toBe(true);
  });

  it('labels known events and shows unknown ones raw', () => {
    expect(isKnownEvent('quota.reached')).toBe(true);
    expect(isKnownEvent('future.event')).toBe(false);
    expect(eventLabel('quota.reached', t)).toBe('opsWebhooks.events.quota.reached');
    expect(eventLabel('future.event', t)).toBe('future.event');
  });

  it('sorts events in the order of the specification, unknown last, without duplicates', () => {
    expect(sortEvents(['quota.reached', 'zz.b', 'virus.detected', 'zz.a', 'quota.reached'])).toEqual([
      'virus.detected',
      'quota.reached',
      'zz.a',
      'zz.b',
    ]);
    expect(sortEvents(['zz.a', 'zz.a'])).toEqual(['zz.a']);
  });

  it('toggles an event of a selection', () => {
    expect(toggleEvent(['quota.reached'], 'virus.detected', true)).toEqual([
      'virus.detected',
      'quota.reached',
    ]);
    expect(toggleEvent(['virus.detected', 'quota.reached'], 'virus.detected', false)).toEqual([
      'quota.reached',
    ]);
    expect(toggleEvent(['virus.detected'], 'virus.detected', true)).toEqual(['virus.detected']);
  });
});

describe('labels', () => {
  it('labels kinds and error categories, raw when unknown', () => {
    expect(kindLabel('slack', t)).toBe('opsWebhooks.kinds.slack');
    expect(kindLabel('pager', t)).toBe('pager');
    expect(categoryLabel('tls', t)).toBe('opsWebhooks.categories.tls');
    expect(categoryLabel('quantum', t)).toBe('quantum');
  });

  it('has every key used by the module in both languages', () => {
    const keys = [
      ...webhookEventTypeValues.map((e) => `events.${e}`),
      ...webhookKindValues.map((k) => `kinds.${k}`),
      ...webhookKindValues.map((k) => `form.kind.hints.${k}`),
      ...webhookErrorCategoryValues.map((c) => `categories.${c}`),
      'categories.unknown',
      'status.enabled',
      'status.disabled',
      'status.suspended',
      'delivery.never',
      'delivery.success',
      'delivery.failure',
      'delivery.httpStatus',
      'delivery.duration',
      'test.success',
      'test.failure',
      'test.rateLimited',
      'test.rateLimitedRetry',
      'errors.nameTooLong',
      'errors.urlInvalid',
      'errors.urlScheme',
      'errors.urlCredentials',
      'errors.urlTooLong',
      'errors.eventsRequired',
      'errors.eventNotAllowed',
      'errors.limit',
      'errors.notFound',
    ];
    for (const key of keys) {
      expect(hasKey(en, key), `en ${key}`).toBe(true);
      expect(hasKey(fr, key), `fr ${key}`).toBe(true);
    }
  });
});

describe('list', () => {
  it('sorts by name, then by creation date', () => {
    const rows = sortWebhooks([
      webhook({ id: 'b', name: 'SIEM', createdAt: '2026-10-21T00:00:00Z' }),
      webhook({ id: 'a', name: 'Alerts' }),
      webhook({ id: 'c', name: 'SIEM', createdAt: '2026-10-20T00:00:00Z' }),
    ]);
    expect(rows.map((r) => r.id)).toEqual(['a', 'c', 'b']);
  });

  it('drops the secret from the webhook kept in the list', () => {
    const withSecret = { ...webhook({ kind: 'generic', hasSecret: true }), secret: 'whsec_EXAMPLE' };
    const kept = withoutSecret(withSecret);
    expect('secret' in kept).toBe(false);
    expect(kept.id).toBe('whk_1');
    // The answer itself is not changed.
    expect(withSecret.secret).toBe('whsec_EXAMPLE');
    expect(secretOf(withSecret)).toBe('whsec_EXAMPLE');
    expect(secretOf(webhook())).toBe('');
  });

  it('rotates the secret of generic webhooks only', () => {
    expect(canRotate({ kind: 'generic' })).toBe(true);
    expect(canRotate({ kind: 'teams' })).toBe(false);
    expect(canRotate({ kind: 'slack' })).toBe(false);
  });
});

describe('status', () => {
  it('reports the circuit breaker only while it is open', () => {
    expect(circuitOpenUntil(webhook(), NOW)).toBeUndefined();
    expect(circuitOpenUntil(webhook({ circuitOpenUntil: '2026-10-27T10:15:00Z' }), NOW)).toBe(
      '2026-10-27T10:15:00Z',
    );
    expect(circuitOpenUntil(webhook({ circuitOpenUntil: '2026-10-27T09:59:00Z' }), NOW)).toBeUndefined();
    expect(circuitOpenUntil(webhook({ circuitOpenUntil: 'not a date' }), NOW)).toBeUndefined();
    expect(circuitOpenUntil({} as Webhook, NOW)).toBeUndefined();
  });

  it.each<[Partial<Webhook>, WebhookStatus]>([
    [{}, 'enabled'],
    [{ enabled: false }, 'disabled'],
    [{ enabled: false, circuitOpenUntil: '2026-10-27T10:15:00Z' }, 'disabled'],
    [{ circuitOpenUntil: '2026-10-27T10:15:00Z' }, 'suspended'],
  ])('status of %j is %s', (over, status) => {
    expect(webhookStatus(webhook(over), NOW)).toBe(status);
  });

  it('gives each status a badge', () => {
    expect(statusView('enabled')).toEqual({ variant: 'ok', key: 'opsWebhooks.status.enabled' });
    expect(statusView('suspended')).toEqual({ variant: 'warning', key: 'opsWebhooks.status.suspended' });
    expect(statusView('disabled')).toEqual({ variant: 'missing', key: 'opsWebhooks.status.disabled' });
  });

  it('gives the last delivery a badge', () => {
    expect(deliveryView(null)).toEqual({ variant: 'info', key: 'opsWebhooks.delivery.never' });
    expect(deliveryView(undefined).key).toBe('opsWebhooks.delivery.never');
    expect(deliveryView({ at: 'x', success: true, durationMs: 1 })).toEqual({
      variant: 'ok',
      key: 'opsWebhooks.delivery.success',
    });
    expect(deliveryView({ at: 'x', success: false, durationMs: 1 })).toEqual({
      variant: 'error',
      key: 'opsWebhooks.delivery.failure',
    });
  });

  it('details an outcome by HTTP status, else by cause, then duration', () => {
    expect(outcomeDetail({ httpStatus: 502, errorCategory: 'http_status', durationMs: 40 }, t)).toBe(
      'opsWebhooks.delivery.httpStatus {"status":502} · opsWebhooks.delivery.duration {"ms":40}',
    );
    expect(outcomeDetail({ errorCategory: 'timeout', durationMs: 10002 }, t)).toBe(
      'opsWebhooks.categories.timeout · opsWebhooks.delivery.duration {"ms":10002}',
    );
    expect(outcomeDetail({ durationMs: 3 }, t)).toBe('opsWebhooks.delivery.duration {"ms":3}');
  });
});

describe('test button', () => {
  it('describes a successful and a failed test', () => {
    expect(testResultMessage('SIEM', { success: true, httpStatus: 200, durationMs: 182 }, t)).toEqual({
      severity: 'success',
      text: 'opsWebhooks.test.success {"name":"SIEM","detail":"opsWebhooks.delivery.httpStatus {\\"status\\":200} · opsWebhooks.delivery.duration {\\"ms\\":182}"}',
    });
    const ko = testResultMessage('SIEM', { success: false, errorCategory: 'dns', durationMs: 5 }, t);
    expect(ko.severity).toBe('error');
    expect(ko.text).toContain('opsWebhooks.test.failure');
    expect(ko.text).toContain('"cause":"opsWebhooks.categories.dns"');
    const unknown = testResultMessage('SIEM', { success: false, durationMs: 5 }, t);
    expect(unknown.text).toContain('"cause":"opsWebhooks.categories.unknown"');
  });

  it('explains the rate limit, with the wait when known', () => {
    expect(testErrorMessage(view({ status: 429, retryAfterSeconds: 125 }), t)).toBe(
      'opsWebhooks.test.rateLimitedRetry {"max":10,"minutes":3}',
    );
    expect(testErrorMessage(view({ code: 'rate-limited', retryAfterSeconds: 10 }), t)).toBe(
      'opsWebhooks.test.rateLimitedRetry {"max":10,"minutes":1}',
    );
    expect(testErrorMessage(view({ status: 429 }), t)).toBe('opsWebhooks.test.rateLimited {"max":10}');
    expect(testErrorMessage(view({ status: 429, retryAfterSeconds: 0 }), t)).toBe(
      'opsWebhooks.test.rateLimited {"max":10}',
    );
    expect(testErrorMessage(view({ status: 404 }), t)).toBe('opsWebhooks.errors.notFound');
    expect(testErrorMessage(view({ status: 500 }), t)).toBe('general');
  });
});

describe('URL', () => {
  it.each([
    ['https://hooks.example.com/transteira', undefined],
    ['  http://192.0.2.10:8080/hook  ', undefined],
    ['', 'required'],
    ['   ', 'required'],
    ['not a url', 'invalid'],
    ['ftp://hooks.example.com/', 'scheme'],
    ['mailto:alerts@example.com', 'scheme'],
    ['https://user:secret@hooks.example.com/', 'credentials'],
    ['https://user@hooks.example.com/', 'credentials'],
    [`https://hooks.example.com/${'a'.repeat(WEBHOOK_URL_MAX)}`, 'too-long'],
  ])('checks %s', (input, expected) => {
    expect(checkWebhookUrl(input)).toBe(expected);
  });

  it('refuses an http URL without a host', () => {
    expect(checkWebhookUrl('http:')).toBe('invalid');
  });
});

describe('forms', () => {
  it('starts with an enabled generic webhook without events', () => {
    expect(emptyWebhookForm()).toEqual({ name: '', kind: 'generic', url: '', events: [], enabled: true });
  });

  it.each<[Partial<WebhookForm>, boolean]>([
    [{}, false],
    [{ name: ' x ' }, true],
    [{ url: 'https://' }, true],
    [{ events: ['virus.detected'] }, true],
    [{ kind: 'slack' }, true],
    [{ enabled: false }, true],
    [{ name: '   ' }, false],
  ])('creation form %j touched: %s', (over, touched) => {
    expect(createFormTouched(form(over))).toBe(touched);
  });

  it('builds the edition form without the URL', () => {
    expect(editFormFrom(webhook({ events: ['abuse.reported', 'virus.detected'] }))).toEqual({
      name: 'Security team channel',
      kind: 'teams',
      url: '',
      events: ['virus.detected', 'abuse.reported'],
      enabled: true,
    });
  });

  it('builds the creation body, trimmed and in canonical order', () => {
    expect(
      createBody(
        form({
          name: ' SIEM ',
          url: ' https://siem.example.com/hooks ',
          events: ['quota.reached', 'virus.detected'],
          enabled: false,
        }),
      ),
    ).toEqual({
      name: 'SIEM',
      kind: 'generic',
      url: 'https://siem.example.com/hooks',
      events: ['virus.detected', 'quota.reached'],
      enabled: false,
    });
  });

  it('patches only the changed fields, and the URL when one is typed', () => {
    const w = webhook({ events: ['abuse.reported', 'virus.detected'] });
    expect(buildWebhookPatch(w, editFormFrom(w))).toEqual({});
    // Same events in another order: no change.
    expect(
      buildWebhookPatch(w, { ...editFormFrom(w), events: ['abuse.reported', 'virus.detected'] }),
    ).toEqual({});
    expect(
      buildWebhookPatch(w, {
        ...editFormFrom(w),
        name: ' Renamed ',
        url: ' https://new.example.com/x ',
        events: ['quota.warning'],
        enabled: false,
      }),
    ).toEqual({
      name: 'Renamed',
      url: 'https://new.example.com/x',
      events: ['quota.warning'],
      enabled: false,
    });
  });
});

describe('validation', () => {
  const ok = form({ name: 'SIEM', url: 'https://siem.example.com/', events: ['virus.detected'] });

  it('accepts a complete form', () => {
    expect(validateWebhookForm(ok, fields, t, { scope: 'tenant', creating: true })).toEqual([]);
  });

  it('requires a name, a URL on creation and at least one event', () => {
    const errors = validateWebhookForm(form(), fields, t, { scope: 'tenant', creating: true });
    expect(errors.map((e) => [e.id, e.message.split(' ')[0]])).toEqual([
      ['name', 'fieldErrors.required'],
      ['url', 'fieldErrors.required'],
      ['events-0', 'opsWebhooks.errors.eventsRequired'],
    ]);
  });

  it('keeps the URL optional on edition, checked when typed', () => {
    expect(validateWebhookForm({ ...ok, url: '' }, fields, t, { scope: 'tenant', creating: false })).toEqual(
      [],
    );
    const errors = validateWebhookForm({ ...ok, url: 'ftp://x.example.com' }, fields, t, {
      scope: 'tenant',
      creating: false,
    });
    expect(errors).toEqual([
      { id: 'url', label: 'URL', message: `opsWebhooks.errors.urlScheme {"max":${WEBHOOK_URL_MAX}}` },
    ]);
  });

  it.each([
    ['not a url', 'opsWebhooks.errors.urlInvalid'],
    ['https://u:p@x.example.com', 'opsWebhooks.errors.urlCredentials'],
    [`https://x.example.com/${'a'.repeat(WEBHOOK_URL_MAX)}`, 'opsWebhooks.errors.urlTooLong'],
  ])('reports the URL %s', (url, key) => {
    const errors = validateWebhookForm({ ...ok, url }, fields, t, { scope: 'tenant', creating: true });
    expect(errors[0]?.message.startsWith(key)).toBe(true);
  });

  it('limits the name length', () => {
    const errors = validateWebhookForm({ ...ok, name: 'n'.repeat(WEBHOOK_NAME_MAX + 1) }, fields, t, {
      scope: 'tenant',
      creating: true,
    });
    expect(errors).toEqual([
      { id: 'name', label: 'Name', message: `opsWebhooks.errors.nameTooLong {"max":${WEBHOOK_NAME_MAX}}` },
    ]);
  });

  it('refuses an event of the other scope', () => {
    const tenant = validateWebhookForm({ ...ok, events: ['disk.alert_raised'] }, fields, t, {
      scope: 'tenant',
      creating: true,
    });
    expect(tenant[0]?.message).toBe('opsWebhooks.errors.eventNotAllowed');
    const system = validateWebhookForm({ ...ok, events: ['disk.alert_raised'] }, fields, t, {
      scope: 'system',
      creating: true,
    });
    expect(system).toEqual([]);
  });
});

describe('errors', () => {
  it('reports the limit of webhooks on a 409', () => {
    expect(webhookErrorOutcome(view({ status: 409, code: 'state-conflict' }), fields, t)).toEqual({
      ok: false,
      message: `opsWebhooks.errors.limit {"max":${MAX_WEBHOOKS}}`,
    });
    expect(webhookErrorOutcome(view({ code: 'state-conflict' }), fields, t).ok).toBe(false);
  });

  it('reports the limit of creations and URL changes on a 429, with the wait when known', () => {
    expect(webhookErrorOutcome(view({ status: 429, retryAfterSeconds: 125 }), fields, t)).toEqual({
      ok: false,
      message: `opsWebhooks.errors.rateLimitedRetry {"max":${WEBHOOK_URL_CHANGES_PER_HOUR},"minutes":3}`,
    });
    expect(webhookErrorOutcome(view({ code: 'rate-limited', retryAfterSeconds: 10 }), fields, t)).toEqual({
      ok: false,
      message: `opsWebhooks.errors.rateLimitedRetry {"max":${WEBHOOK_URL_CHANGES_PER_HOUR},"minutes":1}`,
    });
    expect(webhookErrorOutcome(view({ status: 429 }), fields, t)).toEqual({
      ok: false,
      message: `opsWebhooks.errors.rateLimited {"max":${WEBHOOK_URL_CHANGES_PER_HOUR}}`,
    });
    expect(webhookErrorOutcome(view({ status: 429, retryAfterSeconds: 0 }), fields, t)).toEqual({
      ok: false,
      message: `opsWebhooks.errors.rateLimited {"max":${WEBHOOK_URL_CHANGES_PER_HOUR}}`,
    });
    expect(WEBHOOK_URL_CHANGES_PER_HOUR).toBe(30);
  });

  it('reports a missing webhook', () => {
    expect(webhookErrorOutcome(view({ status: 404 }), fields, t)).toEqual({
      ok: false,
      message: 'opsWebhooks.errors.notFound',
    });
  });

  it('places field errors on their fields (url-not-allowed, events)', () => {
    const outcome = webhookErrorOutcome(
      view({
        code: 'validation-failed',
        status: 400,
        fields: {
          url: { code: 'url-not-allowed', message: 'not allowed' },
          'events.1': { code: 'not-allowed', message: 'bad event' },
        },
      }),
      fields,
      t,
    );
    expect(outcome).toEqual({
      ok: false,
      errors: [
        { id: 'url', label: 'URL', message: 'not allowed' },
        { id: 'events-0', label: 'Events', message: 'bad event' },
      ],
    });
  });

  it('adds the general message when a field error cannot be placed', () => {
    const outcome = webhookErrorOutcome(
      view({
        code: 'validation-failed',
        status: 400,
        fields: {
          kind: { code: 'invalid', message: 'bad kind' },
          name: { code: 'too-long', message: 'long' },
        },
      }),
      { ...fields, enabled: undefined },
      t,
    );
    expect(outcome).toEqual({
      ok: false,
      message: 'general',
      errors: [{ id: 'name', label: 'Name', message: 'long' }],
    });
  });

  it('shows the general message otherwise', () => {
    expect(webhookErrorOutcome(view({ status: 500 }), fields, t)).toEqual({ ok: false, message: 'general' });
  });

  it('explains a failed deletion or rotation', () => {
    expect(actionErrorMessage(view({ status: 404 }), t)).toBe('opsWebhooks.errors.notFound');
    expect(actionErrorMessage(view({ status: 403 }), t)).toBe('general');
  });
});

describe('tenant setting', () => {
  it('reads the address setting, off by default', () => {
    expect(includesAddresses({})).toBe(false);
    expect(includesAddresses({ webhookIncludeAddresses: true })).toBe(true);
  });

  it('patches the setting only when it changes', () => {
    expect(includeAddressesPatch({}, false)).toEqual({});
    expect(includeAddressesPatch({}, true)).toEqual({ webhookIncludeAddresses: true });
    expect(includeAddressesPatch({ webhookIncludeAddresses: true }, false)).toEqual({
      webhookIncludeAddresses: false,
    });
  });
});
