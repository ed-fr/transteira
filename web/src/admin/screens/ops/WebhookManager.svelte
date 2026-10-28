<script lang="ts">
  // Webhooks of a tenant (/admin/tenants/{id}/webhooks) or of the instance (/admin/system/webhooks,
  // super admin), CLAUDE.md section 12.4; the screens TenantWebhooks and SystemWebhooks only set
  // the scope and the title (the help topic follows the scope).
  // - table: name and URL hint (scheme and host: the URL is sealed and never returned), kind,
  //   events, status (enabled, disabled, suspended by the circuit breaker until a date), last
  //   delivery (success or failure, HTTP status or coarse cause, duration, date);
  // - per webhook: Test (one synchronous delivery; the outcome is announced in a live region,
  //   10 tests per hour, 429 with the wait; a test changes neither the last delivery nor the
  //   suspension), Edit (WebhookFormDialog, merge patch), Rotate the
  //   secret (generic kind, confirmation), Delete (confirmation);
  // - creation in WebhookFormDialog, limited to 20 webhooks.
  // The signing secret of a generic webhook (creation, rotation) is shown once in SecretOnceModal:
  // it lives only in this component's state, is cleared when the modal closes and when the screen
  // goes away, and is never kept in the list, put in the URL, stored, logged or announced.
  import { onDestroy, tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, HelpIcon, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import SecretOnceModal from '../../components/SecretOnceModal.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import type { Navigation } from '../types';
  import WebhookFormDialog from './WebhookFormDialog.svelte';
  import {
    MAX_WEBHOOKS,
    canRotate,
    circuitOpenUntil,
    actionErrorMessage,
    deliveryView,
    eventLabel,
    kindLabel,
    outcomeDetail,
    secretOf,
    sortEvents,
    sortWebhooks,
    statusView,
    testErrorMessage,
    testResultMessage,
    webhookStatus,
    withoutSecret,
    type Webhook,
    type WebhookCreate,
    type WebhookScope,
    type WebhookUpdate,
    type WebhookWithSecret,
  } from './webhooks';
  import type { Snippet } from 'svelte';

  interface Props {
    /** Tenant webhooks or instance-wide webhooks. */
    scope: WebhookScope;
    /** Tenant of the webhooks (scope "tenant"). */
    tenantId?: string;
    /** Title of the screen (level-1 heading). */
    title: string;
    /** Introduction under the heading. */
    intro: string;
    /** Router helpers. */
    nav: Navigation;
    /** Extra content under the introduction (e.g. the address setting of the tenant). */
    notice?: Snippet;
  }

  let { scope, tenantId = '', title, intro, nav, notice }: Props = $props();

  let webhooks = $state.raw<Webhook[]>([]);
  let now = $state.raw(new Date());
  let loading = $state(true);
  let loadError = $state('');
  let heading = $state<HTMLHeadingElement | undefined>();

  // Creation and edition.
  let formOpen = $state(false);
  let editing = $state.raw<Webhook | undefined>(undefined);
  // Test.
  let testing = $state('');
  let testOutcome = $state.raw<{ severity: 'success' | 'error'; text: string; seq: number } | undefined>(
    undefined,
  );
  let testSeq = 0;
  // Rotation and deletion.
  let rotating = $state.raw<Webhook | undefined>(undefined);
  let rotateOpen = $state(false);
  let deleting = $state.raw<Webhook | undefined>(undefined);
  let deleteOpen = $state(false);
  let deleted = false;
  // The signing secret, shown once: kept aside until the dialog that produced it has closed (and
  // returned the focus to its opener), then shown in SecretOnceModal.
  let pendingSecret: { webhook: WebhookWithSecret; titleKey: string } | undefined;
  let secret = $state('');
  let secretTitle = $state('');
  let secretOpen = $state(false);

  const rows = $derived(sortWebhooks(webhooks));
  const atLimit = $derived(webhooks.length >= MAX_WEBHOOKS);

  // ---- API, by scope ------------------------------------------------------------------------------

  async function apiList(): Promise<Webhook[]> {
    if (scope === 'system') {
      return (await adminApi.get('/admin/system/webhooks')).data;
    }
    return (await adminApi.get('/admin/tenants/{tenantId}/webhooks', { path: { tenantId } })).data;
  }

  async function apiCreate(body: WebhookCreate): Promise<WebhookWithSecret> {
    if (scope === 'system') {
      return (await adminApi.post('/admin/system/webhooks', { body })).data;
    }
    return (await adminApi.post('/admin/tenants/{tenantId}/webhooks', { path: { tenantId }, body })).data;
  }

  async function apiUpdate(webhookId: string, body: WebhookUpdate): Promise<WebhookWithSecret> {
    if (scope === 'system') {
      return (await adminApi.patch('/admin/system/webhooks/{webhookId}', { path: { webhookId }, body })).data;
    }
    return (
      await adminApi.patch('/admin/tenants/{tenantId}/webhooks/{webhookId}', {
        path: { tenantId, webhookId },
        body,
      })
    ).data;
  }

  async function apiDelete(webhookId: string): Promise<void> {
    if (scope === 'system') {
      await adminApi.delete('/admin/system/webhooks/{webhookId}', { path: { webhookId } });
      return;
    }
    await adminApi.delete('/admin/tenants/{tenantId}/webhooks/{webhookId}', {
      path: { tenantId, webhookId },
    });
  }

  async function apiTest(webhookId: string) {
    if (scope === 'system') {
      return (await adminApi.post('/admin/system/webhooks/{webhookId}/test', { path: { webhookId } })).data;
    }
    return (
      await adminApi.post('/admin/tenants/{tenantId}/webhooks/{webhookId}/test', {
        path: { tenantId, webhookId },
      })
    ).data;
  }

  // ---- Screen -------------------------------------------------------------------------------------

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const list = await apiList();
      now = new Date();
      webhooks = list;
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  // Reload when the tenant changes; the loader itself (adminApi reads the locale) is untracked.
  $effect(() => {
    void tenantId;
    untrack(() => void load());
  });

  function replace(updated: Webhook): void {
    webhooks = webhooks.some((w) => w.id === updated.id)
      ? webhooks.map((w) => (w.id === updated.id ? updated : w))
      : [...webhooks, updated];
  }

  function showSecret(webhook: WebhookWithSecret, titleKey: string): void {
    const value = secretOf(webhook);
    if (value === '') {
      return;
    }
    secretTitle = t(titleKey, { name: webhook.name });
    secret = value;
    secretOpen = true;
  }

  function startCreate(): void {
    editing = undefined;
    formOpen = true;
  }

  function startEdit(webhook: Webhook): void {
    editing = webhook;
    formOpen = true;
  }

  function saved(webhook: WebhookWithSecret, created: boolean): void {
    now = new Date();
    replace(withoutSecret(webhook));
    announce(t(created ? 'opsWebhooks.form.created' : 'opsWebhooks.form.saved'));
    if (created) {
      pendingSecret = { webhook, titleKey: 'opsWebhooks.secret.createdTitle' };
    }
  }

  /** Shows the secret kept aside, once the dialog that produced it has closed. */
  function showPendingSecret(): void {
    const pending = pendingSecret;
    pendingSecret = undefined;
    if (pending !== undefined) {
      showSecret(pending.webhook, pending.titleKey);
    }
  }

  async function test(webhook: Webhook): Promise<void> {
    if (testing !== '') {
      return;
    }
    testing = webhook.id;
    let outcome: { severity: 'success' | 'error'; text: string };
    try {
      outcome = testResultMessage(webhook.name, await apiTest(webhook.id), t);
    } catch (err) {
      outcome = { severity: 'error', text: testErrorMessage(describeError(i18n, err), t) };
    } finally {
      testing = '';
    }
    testSeq += 1;
    // A test is not a delivery: the API changes neither the last delivery nor the circuit
    // breaker, so the list stays as it is and the outcome is shown only in this alert.
    testOutcome = { ...outcome, seq: testSeq };
  }

  function startRotate(webhook: Webhook): void {
    rotating = webhook;
    rotateOpen = true;
  }

  async function rotate(): Promise<string | void> {
    const webhook = rotating;
    if (webhook === undefined) {
      return;
    }
    let res: WebhookWithSecret;
    try {
      res = await apiUpdate(webhook.id, { rotateSecret: true });
    } catch (err) {
      return actionErrorMessage(describeError(i18n, err), t);
    }
    replace(withoutSecret(res));
    announce(t('opsWebhooks.rotate.done', { name: res.name }));
    // The confirmation closes first; the secret then opens in its own dialog.
    pendingSecret = { webhook: res, titleKey: 'opsWebhooks.secret.rotatedTitle' };
  }

  function startDelete(webhook: Webhook): void {
    deleting = webhook;
    deleted = false;
    deleteOpen = true;
  }

  async function remove(): Promise<string | void> {
    const webhook = deleting;
    if (webhook === undefined) {
      return;
    }
    try {
      await apiDelete(webhook.id);
    } catch (err) {
      return actionErrorMessage(describeError(i18n, err), t);
    }
    webhooks = webhooks.filter((w) => w.id !== webhook.id);
    deleted = true;
    announce(t('opsWebhooks.delete.done', { name: webhook.name }));
  }

  async function deleteClosed(): Promise<void> {
    // The buttons of the row are gone: the focus goes back to the page heading.
    if (deleted) {
      deleted = false;
      await tick();
      heading?.focus();
    }
  }

  function secretClosed(): void {
    secret = '';
  }

  onDestroy(() => {
    secret = '';
  });

  const date = (value: string): string => formatDate(value, { dateStyle: 'medium', timeStyle: 'short' });
</script>

{#snippet nameCell(row: Webhook)}
  <span class="tt-break">{row.name}</span>
  <code class="tt-webhooks__hint tt-break">{row.urlHint}</code>
{/snippet}

{#snippet kindCell(row: Webhook)}
  {kindLabel(row.kind, t)}
{/snippet}

{#snippet eventsCell(row: Webhook)}
  <ul class="tt-list-plain tt-webhooks__values">
    {#each sortEvents(row.events) as event (event)}
      <li>{eventLabel(event, t)}</li>
    {/each}
  </ul>
{/snippet}

{#snippet statusCell(row: Webhook)}
  {@const view = statusView(webhookStatus(row, now))}
  {@const until = row.enabled ? circuitOpenUntil(row, now) : undefined}
  <StatusBadge variant={view.variant} label={t(view.key)} />
  {#if until !== undefined}
    <span class="tt-webhooks__when">{t('opsWebhooks.list.suspendedUntil', { date: date(until) })}</span>
  {/if}
{/snippet}

{#snippet deliveryCell(row: Webhook)}
  {@const view = deliveryView(row.lastDelivery)}
  <StatusBadge variant={view.variant} label={t(view.key)} />
  {#if row.lastDelivery}
    <span class="tt-webhooks__when">{outcomeDetail(row.lastDelivery, t)}</span>
    <span class="tt-webhooks__when">{date(row.lastDelivery.at)}</span>
  {/if}
{/snippet}

{#snippet actionsCell(row: Webhook)}
  <div class="tt-cluster">
    <Button
      variant="secondary"
      small
      loading={testing === row.id}
      loadingLabel={t('opsWebhooks.list.testing')}
      disabled={testing !== '' && testing !== row.id}
      onclick={() => void test(row)}
    >
      {t('opsWebhooks.list.test')}<span class="visually-hidden"> {row.name}</span>
    </Button>
    <Button variant="secondary" small onclick={() => startEdit(row)}>
      {t('opsWebhooks.list.edit')}<span class="visually-hidden"> {row.name}</span>
    </Button>
    {#if canRotate(row)}
      <Button variant="secondary" small onclick={() => startRotate(row)}>
        {t('opsWebhooks.list.rotate')}<span class="visually-hidden"> {row.name}</span>
      </Button>
    {/if}
    <Button variant="danger" small onclick={() => startDelete(row)}>
      {t('opsWebhooks.list.delete')}<span class="visually-hidden"> {row.name}</span>
    </Button>
  </div>
{/snippet}

<div class="tt-title-row">
  <h1 tabindex="-1" bind:this={heading}>{title}</h1>
  <!-- Literal topics: src/help/guides.test.ts checks them against the routes and the guides. -->
  {#if scope === 'system'}
    <HelpIcon topic="system-webhooks" {title} {nav} />
  {:else}
    <HelpIcon topic="tenant-webhooks" {title} {nav} />
  {/if}
</div>
<p>{intro}</p>
{#if notice}{@render notice()}{/if}

<p>
  <Button onclick={startCreate} disabled={loading || loadError !== '' || atLimit}>
    {t('opsWebhooks.list.create')}
  </Button>
</p>
{#if atLimit}
  <Alert severity="info" live={false}>{t('opsWebhooks.errors.limit', { max: MAX_WEBHOOKS })}</Alert>
{/if}

<!-- Outcome of the last test: re-inserted at each test so that it is announced every time. -->
{#key testOutcome?.seq}
  {#if testOutcome !== undefined}
    <Alert severity={testOutcome.severity} ondismiss={() => (testOutcome = undefined)}>
      <p>{testOutcome.text}</p>
    </Alert>
  {/if}
{/key}

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsWebhooks.list.caption')}
    captionHidden
    {rows}
    key={(row) => row.id}
    {loading}
    emptyText={t('opsWebhooks.list.empty')}
    columns={[
      { id: 'name', header: t('opsWebhooks.list.columns.name'), cell: nameCell, rowHeader: true },
      { id: 'kind', header: t('opsWebhooks.list.columns.kind'), cell: kindCell },
      { id: 'events', header: t('opsWebhooks.list.columns.events'), cell: eventsCell },
      { id: 'status', header: t('opsWebhooks.list.columns.status'), cell: statusCell },
      { id: 'delivery', header: t('opsWebhooks.list.columns.delivery'), cell: deliveryCell },
      { id: 'actions', header: t('opsWebhooks.list.columns.actions'), cell: actionsCell, headerHidden: true },
    ]}
  />
{/if}

<WebhookFormDialog
  bind:open={formOpen}
  {scope}
  webhook={editing}
  create={apiCreate}
  update={apiUpdate}
  onsaved={saved}
  onclose={showPendingSecret}
  addGuard={(guard) => nav.addGuard(guard)}
/>

<ConfirmDialog
  bind:open={rotateOpen}
  title={t('opsWebhooks.rotate.title', { name: rotating?.name ?? '' })}
  text={t('opsWebhooks.rotate.text')}
  confirmLabel={t('opsWebhooks.rotate.confirm')}
  danger
  onconfirm={rotate}
  onclose={showPendingSecret}
/>

<ConfirmDialog
  bind:open={deleteOpen}
  title={t('opsWebhooks.delete.title', { name: deleting?.name ?? '' })}
  text={t('opsWebhooks.delete.text')}
  confirmLabel={t('opsWebhooks.delete.confirm')}
  busyLabel={t('admin.common.deleting')}
  danger
  onconfirm={remove}
  onclose={() => void deleteClosed()}
/>

{#if secret !== ''}
  <SecretOnceModal
    bind:open={secretOpen}
    title={secretTitle}
    {secret}
    text={t('opsWebhooks.secret.text')}
    secretLabel={t('opsWebhooks.secret.label')}
    addGuard={(guard) => nav.addGuard(guard)}
    onclose={secretClosed}
  />
{/if}

<style>
  .tt-webhooks__values {
    margin: 0;
  }

  .tt-webhooks__hint,
  .tt-webhooks__when {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
