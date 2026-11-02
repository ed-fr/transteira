<script lang="ts">
  // Provisioning tokens (super admin; CLAUDE.md section 2, version 1.2; GET/POST
  // /admin/provisioning-tokens, DELETE /admin/provisioning-tokens/{tokenId}). A provisioning
  // token lets a managed service provider create entities through the API, within a bounded
  // scope:
  // - table: name, prefix (ttp_xxxx…), allowed ranges, allowed FQDN suffixes, tenants created
  //   out of the maximum, quota and per-transfer caps, creation (date and admin identifier), last
  //   use, expiry, status badge; revoked tokens stay listed;
  // - creation in a dialog: the form, the volume the token commits (tenants x quota, shown
  //   before confirming) and the re-confirmation by a TOTP or recovery code of the super admin;
  //   on success the secret is shown once in SecretOnceModal;
  // - revocation of an active token after typing its exact name.
  // Threat model T-167: the secret lives only in this component's state, is cleared when its modal
  // closes and when the screen goes away, and is never put in the URL, in storage, in a log or in
  // an announcement. The typed confirmation code is cleared at each submit, when the dialog
  // closes and when the screen goes away.
  // The system sub-navigation is rendered by App.svelte.
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Dialog, HelpIcon, TextField, announce } from '../../../shared/components';
  import { formatDate, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ByteSizeField from '../../components/ByteSizeField.svelte';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import SecretOnceModal from '../../components/SecretOnceModal.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import type { AdminScreenProps } from '../types';
  import {
    MAX_CIDRS,
    MAX_SUFFIXES,
    NAME_MAX,
    TRANSFER_CAP_MAX,
    committedBytes,
    createBody,
    createErrorOutcome,
    emptyCreateForm,
    isManageable,
    parseMaxTenants,
    parseRange,
    parseSuffix,
    prefixLabel,
    rangeLineMessage,
    revokeErrorMessage,
    sortTokens,
    statusView,
    suffixLineMessage,
    tenantsText,
    todayInput,
    tokenStatus,
    validateCreate,
    type ProvisioningToken,
  } from './provisioningTokens';

  let { params: _params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    name: `${uid}-name`,
    cidrs: `${uid}-cidrs`,
    suffixes: `${uid}-suffixes`,
    tenants: `${uid}-tenants`,
    quota: `${uid}-quota`,
    transfer: `${uid}-transfer`,
    expiry: `${uid}-expiry`,
    code: `${uid}-code`,
  };

  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);
  const date = (value: string): string => formatDate(value, { dateStyle: 'medium', timeStyle: 'short' });

  // ---- List ----
  let tokens = $state.raw<ProvisioningToken[]>([]);
  let now = $state.raw(new Date());
  let loading = $state(true);
  let loadError = $state('');
  let heading = $state<HTMLHeadingElement | undefined>();
  const rows = $derived(sortTokens(tokens, now));

  /** Loads the list; a silent reload keeps the current list displayed (no loading state). */
  async function load(silent = false): Promise<void> {
    if (!silent) {
      loading = true;
    }
    loadError = '';
    try {
      const res = await adminApi.get('/admin/provisioning-tokens');
      now = new Date();
      tokens = res.data;
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      if (!silent) {
        loading = false;
      }
    }
  }

  // ---- Creation ----
  let createOpen = $state(false);
  let form = $state(emptyCreateForm());
  let errors = $state<SummaryError[]>([]);
  // The secret of the created token, shown once (T-167).
  let secret = $state('');
  let secretTitle = $state('');
  let secretOpen = $state(false);

  const fields = $derived({
    name: { id: ids.name, label: t('sysProvisioning.form.name.label') },
    allowedCidrs: { id: ids.cidrs, label: t('sysProvisioning.form.cidrs.label') },
    allowedFqdnSuffixes: { id: ids.suffixes, label: t('sysProvisioning.form.suffixes.label') },
    maxTenants: { id: ids.tenants, label: t('sysProvisioning.form.maxTenants.label') },
    maxStorageQuotaBytes: { id: ids.quota, label: t('sysProvisioning.form.quota.label') },
    maxTransferBytes: { id: ids.transfer, label: t('sysProvisioning.form.transfer.label') },
    expiresAt: { id: ids.expiry, label: t('sysProvisioning.form.expiry.label') },
    code: {
      id: ids.code,
      label: form.mode === 'totp' ? t('adminAuth.totp.code.label') : t('adminAuth.totp.recoveryCode.label'),
    },
  });
  const minDate = $derived(todayInput(new Date()));
  const committed = $derived(committedBytes(parseMaxTenants(form.maxTenants), form.maxStorageQuotaBytes));

  function openCreate(): void {
    form = emptyCreateForm();
    errors = [];
    createOpen = true;
  }

  function createClosed(): void {
    form.code = '';
  }

  async function switchMode(): Promise<void> {
    form.mode = form.mode === 'totp' ? 'recovery' : 'totp';
    form.code = '';
    await tick();
    document.getElementById(ids.code)?.focus();
  }

  async function submit(): Promise<SubmitOutcome> {
    const body = createBody(form);
    const sent = { cidrText: form.cidrText, suffixText: form.suffixText };
    // The code is not kept once the request is built, whatever the answer.
    form.code = '';
    try {
      const res = await adminApi.post('/admin/provisioning-tokens', { body });
      secretTitle = t('sysProvisioning.secret.title', { name: res.data.name });
      secret = res.data.token;
      createOpen = false;
      secretOpen = true;
      void load(true);
      return { ok: true, message: t('sysProvisioning.form.created') };
    } catch (err) {
      return createErrorOutcome(describeError(i18n, err), fields, sent, t);
    }
  }

  function secretClosed(): void {
    secret = '';
    announce(t('sysProvisioning.secret.closed'));
    void tick().then(() => heading?.focus());
  }

  // ---- Revocation ----
  let revoking = $state.raw<ProvisioningToken | undefined>(undefined);
  let revokeOpen = $state(false);
  let revoked = false;

  function startRevoke(token: ProvisioningToken): void {
    revoking = token;
    revoked = false;
    revokeOpen = true;
  }

  async function revoke(): Promise<string | void> {
    const token = revoking;
    if (token === undefined) {
      return;
    }
    try {
      await adminApi.delete('/admin/provisioning-tokens/{tokenId}', { path: { tokenId: token.id } });
    } catch (err) {
      return revokeErrorMessage(describeError(i18n, err), t);
    }
    revoked = true;
    announce(t('sysProvisioning.revoke.done', { name: token.name }));
    // Reload to show the revocation date recorded by the server.
    void load(true);
  }

  async function revokeClosed(): Promise<void> {
    // The Revoke button of the row is gone: the focus goes back to the page heading.
    if (revoked) {
      revoked = false;
      await tick();
      heading?.focus();
    }
  }

  onMount(() => {
    void load();
  });

  onDestroy(() => {
    secret = '';
    form.code = '';
  });
</script>

{#snippet nameCell(row: ProvisioningToken)}
  <span class="tt-break">{row.name}</span>
{/snippet}

{#snippet prefixCell(row: ProvisioningToken)}
  <code>{prefixLabel(row.prefix)}</code>
{/snippet}

{#snippet cidrsCell(row: ProvisioningToken)}
  <ul class="tt-list-plain tt-prov__values">
    {#each row.allowedCidrs as cidr (cidr)}
      <li><code>{cidr}</code></li>
    {/each}
  </ul>
{/snippet}

{#snippet suffixesCell(row: ProvisioningToken)}
  <ul class="tt-list-plain tt-prov__values">
    {#each row.allowedFqdnSuffixes as suffix (suffix)}
      <li><code class="tt-break">{suffix}</code></li>
    {/each}
  </ul>
{/snippet}

{#snippet tenantsCell(row: ProvisioningToken)}
  {tenantsText(row)}
{/snippet}

{#snippet capsCell(row: ProvisioningToken)}
  <ul class="tt-list-plain tt-prov__values">
    <li>{t('sysProvisioning.list.quotaCap', { size: formatBytes(row.maxStorageQuotaBytes) })}</li>
    <li>
      {row.maxTransferBytes === null || row.maxTransferBytes === undefined
        ? t('sysProvisioning.list.transferNoCap')
        : t('sysProvisioning.list.transferCap', { size: formatBytes(row.maxTransferBytes) })}
    </li>
  </ul>
{/snippet}

{#snippet createdCell(row: ProvisioningToken)}
  {t('sysProvisioning.list.createdBy', { date: date(row.createdAt), admin: row.createdBy })}
{/snippet}

{#snippet lastUsedCell(row: ProvisioningToken)}
  {row.lastUsedAt ? date(row.lastUsedAt) : t('sysProvisioning.list.neverUsed')}
{/snippet}

{#snippet expiresCell(row: ProvisioningToken)}
  {row.expiresAt ? date(row.expiresAt) : t('sysProvisioning.list.noExpiry')}
{/snippet}

{#snippet statusCell(row: ProvisioningToken)}
  {@const view = statusView(tokenStatus(row, now))}
  <StatusBadge variant={view.variant} label={t(view.key)} />
  {#if row.revokedAt}
    <span class="tt-prov__when">{date(row.revokedAt)}</span>
  {/if}
{/snippet}

{#snippet actionsCell(row: ProvisioningToken)}
  {#if isManageable(row, now)}
    <Button variant="danger" onclick={() => startRevoke(row)}>
      {t('sysProvisioning.list.revoke')}<span class="visually-hidden"> {row.name}</span>
    </Button>
  {/if}
{/snippet}

<div class="tt-title-row">
  <h1 tabindex="-1" bind:this={heading}>{t('adminSystem.provisioning.title')}</h1>
  <HelpIcon topic="system-provisioning" title={t('adminSystem.provisioning.title')} {nav} />
</div>
<p>{t('adminSystem.provisioning.intro')}</p>

<p>
  <Button onclick={openCreate}>{t('sysProvisioning.list.create')}</Button>
</p>

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('sysProvisioning.list.caption')}
    captionHidden
    {rows}
    key={(row) => row.id}
    {loading}
    emptyText={t('sysProvisioning.list.empty')}
    columns={[
      { id: 'name', header: t('sysProvisioning.list.columns.name'), cell: nameCell, rowHeader: true },
      { id: 'prefix', header: t('sysProvisioning.list.columns.prefix'), cell: prefixCell },
      { id: 'cidrs', header: t('sysProvisioning.list.columns.cidrs'), cell: cidrsCell },
      { id: 'suffixes', header: t('sysProvisioning.list.columns.suffixes'), cell: suffixesCell },
      { id: 'tenants', header: t('sysProvisioning.list.columns.tenants'), cell: tenantsCell },
      { id: 'caps', header: t('sysProvisioning.list.columns.caps'), cell: capsCell },
      { id: 'created', header: t('sysProvisioning.list.columns.created'), cell: createdCell },
      { id: 'lastUsed', header: t('sysProvisioning.list.columns.lastUsed'), cell: lastUsedCell },
      { id: 'expires', header: t('sysProvisioning.list.columns.expires'), cell: expiresCell },
      { id: 'status', header: t('sysProvisioning.list.columns.status'), cell: statusCell },
      {
        id: 'actions',
        header: t('sysProvisioning.list.columns.actions'),
        cell: actionsCell,
        headerHidden: true,
      },
    ]}
  />
  {#if !loading && tokens.length > 0}
    <p class="tt-text-sm tt-text-muted">{t('sysProvisioning.list.lastUsedNote')}</p>
  {/if}
{/if}

<Dialog bind:open={createOpen} title={t('sysProvisioning.form.title')} onclose={createClosed}>
  <FormSection
    title={t('sysProvisioning.form.legend')}
    as="fieldset"
    intro={t('sysProvisioning.form.intro')}
    validate={() => validateCreate(form, fields, t, new Date())}
    onsubmit={submit}
    saveLabel={t('sysProvisioning.form.submit')}
    savingLabel={t('admin.common.creating')}
    bind:errors
  >
    <TextField
      id={ids.name}
      label={t('sysProvisioning.form.name.label')}
      hint={t('sysProvisioning.form.name.hint')}
      bind:value={form.name}
      required
      maxlength={NAME_MAX}
      autocomplete="off"
      error={errorFor(errors, ids.name)}
    />

    <LineListEditor
      id={ids.cidrs}
      label={t('sysProvisioning.form.cidrs.label')}
      hint={t('sysProvisioning.form.cidrs.hint')}
      bind:value={form.cidrText}
      parse={parseRange}
      max={MAX_CIDRS}
      required
      rows={3}
      message={(e) => {
        const m = rangeLineMessage(e);
        return t(m.key, m.params);
      }}
      error={errorFor(errors, ids.cidrs)}
    />

    <LineListEditor
      id={ids.suffixes}
      label={t('sysProvisioning.form.suffixes.label')}
      hint={t('sysProvisioning.form.suffixes.hint')}
      bind:value={form.suffixText}
      parse={parseSuffix}
      max={MAX_SUFFIXES}
      required
      rows={3}
      message={(e) => {
        const m = suffixLineMessage(e);
        return t(m.key, m.params);
      }}
      error={errorFor(errors, ids.suffixes)}
    />

    <TextField
      id={ids.tenants}
      label={t('sysProvisioning.form.maxTenants.label')}
      hint={t('sysProvisioning.form.maxTenants.hint')}
      type="number"
      min="1"
      inputmode="numeric"
      bind:value={form.maxTenants}
      required
      error={errorFor(errors, ids.tenants)}
    />

    <ByteSizeField
      id={ids.quota}
      label={t('sysProvisioning.form.quota.label')}
      hint={t('sysProvisioning.form.quota.hint')}
      defaultUnit="TiB"
      required
      error={errorFor(errors, ids.quota)}
      bind:bytes={form.maxStorageQuotaBytes}
    />

    <ByteSizeField
      id={ids.transfer}
      label={t('sysProvisioning.form.transfer.label')}
      hint={t('sysProvisioning.form.transfer.hint')}
      max={TRANSFER_CAP_MAX}
      error={errorFor(errors, ids.transfer)}
      bind:bytes={form.maxTransferBytes}
    />

    <TextField
      id={ids.expiry}
      label={t('sysProvisioning.form.expiry.label')}
      hint={t('sysProvisioning.form.expiry.hint')}
      type="date"
      min={minDate}
      bind:value={form.expiry}
      error={errorFor(errors, ids.expiry)}
    />

    <Alert severity="info" live={false}>
      {#if committed === null}
        {t('sysProvisioning.form.committed.unknown')}
      {:else if committed === 'large'}
        {t('sysProvisioning.form.committed.large')}
      {:else}
        {t('sysProvisioning.form.committed.value', { size: formatBytes(committed) })}
      {/if}
      {t('sysProvisioning.form.committed.note')}
    </Alert>

    <p class="tt-text-muted tt-text-sm">
      {form.mode === 'totp' ? t('sysProvisioning.form.confirm') : t('sysProvisioning.form.confirmRecovery')}
    </p>
    {#if form.mode === 'totp'}
      <TextField
        id={ids.code}
        label={t('adminAuth.totp.code.label')}
        hint={t('adminAuth.totp.code.hint')}
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern="[0-9]*"
        maxlength={6}
        spellcheck={false}
        required
        error={errorFor(errors, ids.code)}
        bind:value={form.code}
      />
    {:else}
      <TextField
        id={ids.code}
        label={t('adminAuth.totp.recoveryCode.label')}
        hint={t('adminAuth.totp.recoveryCode.hint')}
        autocomplete="off"
        autocapitalize="off"
        spellcheck={false}
        maxlength={64}
        required
        error={errorFor(errors, ids.code)}
        bind:value={form.code}
      />
    {/if}
    <Button variant="link" onclick={() => void switchMode()}>
      {form.mode === 'totp' ? t('adminAuth.totp.useRecovery') : t('adminAuth.totp.useTotp')}
    </Button>
  </FormSection>
</Dialog>

{#if secret !== ''}
  <SecretOnceModal
    bind:open={secretOpen}
    title={secretTitle}
    {secret}
    text={t('sysProvisioning.secret.text')}
    secretLabel={t('sysProvisioning.secret.label')}
    addGuard={(guard) => nav.addGuard(guard)}
    onclose={secretClosed}
  />
{/if}

<ConfirmDialog
  bind:open={revokeOpen}
  title={t('sysProvisioning.revoke.title', { name: revoking?.name ?? '' })}
  text={t('sysProvisioning.revoke.text')}
  confirmLabel={t('sysProvisioning.revoke.confirm')}
  confirmText={revoking?.name ?? ''}
  danger
  onconfirm={revoke}
  onclose={() => void revokeClosed()}
/>

<style>
  .tt-prov__values {
    margin: 0;
  }

  .tt-prov__when {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
