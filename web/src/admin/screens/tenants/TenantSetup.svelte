<script lang="ts">
  // Setup wizard of a tenant ("Mise en service", API 1.2): the checklist of GET
  // /admin/tenants/{id}/setup in order, each item with its state written out (done / to do,
  // required / optional, never colour alone) and a link to the existing screen configuring it
  // (carrying ?from=setup so that the screen offers a way back). The mail templates item is a
  // checkbox sent as mailTemplatesReviewed at completion. "Finish setup" is enabled when the
  // API says the setup can be completed; a 409 setup-incomplete lists the missing items. The
  // super admin alone can force the opening, after a confirmation. When the tenant is active
  // the checklist is shown for information. Version 2.0: internal ranges and domains that no admin
  // ever saved (written by a configuration import) are listed with a "Confirm" button that saves
  // them unchanged (PUT /admin/tenants/{id}/network): until then the network items stay to do.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Checkbox, Spinner } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { setupStates } from '../../setupStates.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    canForce,
    completionBody,
    completionFailure,
    itemHintKey,
    itemLabelKey,
    itemPath,
    missingRequired,
    orderItems,
    type TenantSetup,
  } from './setup';
  import { awaitsReview, reviewPending, type NetworkRules } from './network';

  type View =
    { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; setup: TenantSetup };

  let { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const uid = $props.id();
  let view = $state<View>({ kind: 'loading' });
  let reviewed = $state(false);
  let completing = $state(false);
  let forceOpen = $state(false);
  let missing = $state<string[] | undefined>(undefined);
  let result = $state<{ severity: 'success' | 'error' | 'info'; text: string } | undefined>(undefined);
  let resultElement = $state<HTMLDivElement | undefined>();
  // Imported rules waiting for a confirmation, undefined when there is nothing to confirm.
  let pendingRules = $state.raw<NetworkRules | undefined>(undefined);
  let confirming = $state(false);
  let ticket = 0;

  const me = $derived(adminSession.me);
  const active = $derived(view.kind === 'ready' && view.setup.setupState === 'active');
  const items = $derived(view.kind === 'ready' ? orderItems(view.setup.items) : []);
  const missingNow = $derived(view.kind === 'ready' ? missingRequired(view.setup.items) : []);

  /** Label of an item; an item this interface does not know is shown with its raw key. */
  function labelOf(key: string): string {
    const k = itemLabelKey(key);
    return i18n.has(k) ? t(k) : key;
  }

  function hintOf(key: string): string | undefined {
    const k = itemHintKey(key);
    return i18n.has(k) ? t(k) : undefined;
  }

  /** Loads the checklist; a silent reload keeps the current view (and the focus) meanwhile. */
  async function load(silent = false): Promise<void> {
    const mine = ++ticket;
    if (!silent) {
      view = { kind: 'loading' };
    }
    try {
      const { data } = await adminApi.get('/admin/tenants/{tenantId}/setup', { path: { tenantId } });
      const rules = reviewPending(data)
        ? (await adminApi.get('/admin/tenants/{tenantId}/network', { path: { tenantId } })).data
        : undefined;
      if (mine === ticket) {
        view = { kind: 'ready', setup: data };
        pendingRules = awaitsReview(data, rules) ? rules : undefined;
        setupStates.set(tenantId, data.setupState);
      }
    } catch (err) {
      if (mine === ticket) {
        view = { kind: 'error', message: describeError(i18n, err).message };
      }
    }
  }

  $effect(() => {
    void tenantId;
    void load();
  });

  async function show(severity: 'success' | 'error' | 'info', text: string): Promise<void> {
    result = { severity, text };
    await tick();
    resultElement?.focus();
  }

  async function complete(force: boolean): Promise<void> {
    completing = true;
    missing = undefined;
    result = undefined;
    try {
      const { data } = await adminApi.post('/admin/tenants/{tenantId}/setup/complete', {
        path: { tenantId },
        body: completionBody({ force, mailTemplatesReviewed: reviewed, me }),
      });
      view = { kind: 'ready', setup: data };
      setupStates.set(tenantId, data.setupState);
      await show('success', t('setup.wizard.completed'));
    } catch (err) {
      const failure = completionFailure(err);
      if (failure.kind === 'incomplete') {
        const keys = failure.missing;
        await load(true);
        missing = keys;
        await show('error', t('setup.wizard.incompleteTitle'));
      } else if (failure.kind === 'already-complete') {
        await load(true);
        await show('info', t('setup.wizard.alreadyComplete'));
      } else if (failure.kind === 'forbidden') {
        await show('error', t('setup.wizard.forbidden'));
      } else {
        await show('error', describeError(i18n, err).message);
      }
    } finally {
      completing = false;
    }
  }

  /** Confirms the imported network rules by saving them unchanged. */
  async function confirmNetwork(rules: NetworkRules): Promise<void> {
    confirming = true;
    result = undefined;
    missing = undefined;
    try {
      await adminApi.put('/admin/tenants/{tenantId}/network', { path: { tenantId }, body: rules });
      await load(true);
      await show('success', t('setup.wizard.networkReview.confirmed'));
    } catch (err) {
      await show('error', describeError(i18n, err).message);
    } finally {
      confirming = false;
    }
  }

  async function confirmForce(): Promise<void> {
    await complete(true);
  }
</script>

<h1 tabindex="-1">{t('setup.wizard.title')}</h1>

{#if view.kind === 'loading'}
  <Spinner label={t('setup.wizard.loading')} />
{:else if view.kind === 'error'}
  <Alert severity="error">
    <p>{view.message}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('setup.wizard.retry')}</Button>
  </Alert>
{:else}
  <p>
    <StatusBadge
      variant={active ? 'ok' : 'warning'}
      label={active ? t('setup.state.active') : t('setup.state.setup')}
    />
  </p>
  <p>{active ? t('setup.wizard.introActive') : t('setup.wizard.intro')}</p>

  {#if result !== undefined}
    <Alert severity={result.severity} bind:element={resultElement}>
      <p>{result.text}</p>
      {#if missing !== undefined && missing.length > 0}
        <p>{t('setup.wizard.incompleteText')}</p>
        <ul>
          {#each missing as key (key)}
            <li>{labelOf(key)}</li>
          {/each}
        </ul>
      {/if}
    </Alert>
  {/if}

  {#if pendingRules !== undefined && !active}
    {@const rules = pendingRules}
    <Alert severity="warning" live={false} title={t('setup.wizard.networkReview.title')}>
      <p>{t('setup.wizard.networkReview.text')}</p>
      <h3 class="tt-setup__review-title">{labelOf('internal_networks')}</h3>
      {#if rules.internalCidrs.length > 0}
        <ul>
          {#each rules.internalCidrs as cidr (cidr)}
            <li class="tt-break">{cidr}</li>
          {/each}
        </ul>
      {:else}
        <p>{t('setup.wizard.networkReview.none')}</p>
      {/if}
      <h3 class="tt-setup__review-title">{labelOf('internal_domains')}</h3>
      {#if rules.internalDomains.length > 0}
        <ul>
          {#each rules.internalDomains as domain (domain)}
            <li class="tt-break">{domain}</li>
          {/each}
        </ul>
      {:else}
        <p>{t('setup.wizard.networkReview.none')}</p>
      {/if}
      <p>{t('setup.wizard.networkReview.edit')}</p>
      <div class="tt-setup__actions">
        <Button
          loading={confirming}
          loadingLabel={t('setup.wizard.networkReview.confirming')}
          onclick={() => void confirmNetwork(rules)}
        >
          {t('setup.wizard.networkReview.confirm')}
        </Button>
      </div>
    </Alert>
  {/if}

  <h2 id="{uid}-list">{t('setup.wizard.listLabel')}</h2>
  <ol class="tt-setup__list" aria-labelledby="{uid}-list">
    {#each items as item (item.key)}
      {@const path = itemPath(tenantId, item.key)}
      {@const hint = hintOf(item.key)}
      <li class="tt-setup__item">
        <div class="tt-setup__head">
          <span class="tt-setup__label tt-break">{labelOf(item.key)}</span>
          <StatusBadge
            variant={item.done ? 'ok' : item.required ? 'warning' : 'info'}
            label={item.done ? t('setup.wizard.done') : t('setup.wizard.todo')}
          />
          <span class="tt-setup__required">
            {item.required ? t('setup.wizard.required') : t('setup.wizard.optional')}
          </span>
        </div>
        {#if hint !== undefined}
          <p class="tt-setup__hint">{hint}</p>
        {/if}
        {#if item.key === 'mail_templates' && !active}
          <Checkbox
            label={t('setup.wizard.reviewed')}
            hint={t('setup.wizard.reviewedHint')}
            bind:checked={reviewed}
          />
        {/if}
        {#if path !== undefined}
          <p>
            <a
              href={nav.href(path)}
              use:nav.link
              aria-label={t('setup.wizard.configureItem', { item: labelOf(item.key) })}
            >
              {t('setup.wizard.configure')}
            </a>
          </p>
        {/if}
      </li>
    {/each}
  </ol>

  {#if !active}
    {#if !view.setup.canComplete && missingNow.length > 0}
      <p id="{uid}-missing">{t('setup.wizard.canCompleteNo')}</p>
      <ul>
        {#each missingNow as item (item.key)}
          <li>{labelOf(item.key)}</li>
        {/each}
      </ul>
    {/if}
    <div class="tt-setup__actions">
      <Button
        disabled={!view.setup.canComplete}
        aria-describedby={!view.setup.canComplete && missingNow.length > 0 ? `${uid}-missing` : undefined}
        loading={completing}
        loadingLabel={t('setup.wizard.completing')}
        onclick={() => void complete(false)}
      >
        {t('setup.wizard.complete')}
      </Button>
      {#if canForce(me)}
        <Button variant="danger" disabled={completing} onclick={() => (forceOpen = true)}>
          {t('setup.wizard.force.action')}
        </Button>
      {/if}
    </div>
    {#if canForce(me)}
      <p class="tt-setup__hint">{t('setup.wizard.force.hint')}</p>
    {/if}
    <ConfirmDialog
      bind:open={forceOpen}
      title={t('setup.wizard.force.title')}
      text={t('setup.wizard.force.text')}
      confirmLabel={t('setup.wizard.force.confirm')}
      danger
      onconfirm={confirmForce}
    />
  {/if}
{/if}

<style>
  .tt-setup__list {
    margin: 0 0 var(--tt-space-4);
    padding-left: var(--tt-space-5);
  }

  .tt-setup__item {
    margin-bottom: var(--tt-space-4);
  }

  .tt-setup__head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2) var(--tt-space-3);
  }

  .tt-setup__label {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-setup__required,
  .tt-setup__hint {
    color: var(--tt-muted);
  }

  .tt-setup__hint {
    margin: var(--tt-space-1) 0;
  }

  .tt-setup__review-title {
    margin: var(--tt-space-3) 0 var(--tt-space-1);
    font-size: inherit;
  }

  .tt-setup__actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
  }
</style>
