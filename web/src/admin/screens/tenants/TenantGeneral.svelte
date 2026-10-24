<script lang="ts">
  // General settings of a tenant (GET and PATCH /admin/tenants/{id}, merge patch built by
  // buildPatch: only the changed fields allowed to the role, never null).
  // - Super admin: every field (name, FQDN, language, quota, ceiling and size per transfer).
  //   Lowering the ceiling below the saved size per transfer, without editing that size, lowers
  //   it too on the server (limitFollowsCeiling): the size field says so instead of an error.
  // - Delegated admin: the default language and the size per transfer, at most the ceiling set
  //   by the super admin; the other settings are shown as text with an explanatory note.
  // - A tenant being deleted shows a banner and accepts no change, except resuming the deletion.
  // - Deletion (super admin): the name must be typed exactly (DELETE ?confirm=<name>); a 500
  //   leaves the tenant "deleting", completed later by the periodic cleanup.
  // The admin profile is reloaded after a rename and after a deletion (it lists the tenants).
  // The tenant sub-navigation (components/TenantNav.svelte) is rendered by App.svelte above
  // every /tenants/:id/... screen: it is not rendered again here.
  import { onMount, tick } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, RadioGroup, Spinner, TextField, announce } from '../../../shared/components';
  import { formatNumber, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ByteSizeField from '../../components/ByteSizeField.svelte';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { MAX_TRANSFER_BYTES, formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import NotFound from '../NotFound.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    TENANT_LANGUAGES,
    changesProfile,
    deletionResumes,
    editableFields,
    formFromTenant,
    isDirty,
    languageLabel,
    limitFollowsCeiling,
    quotaUsage,
    statusView,
    tenantFailure,
    tenantPatch,
    validateTenantForm,
    type SizeField,
    type Tenant,
    type TenantFieldRefs,
    type TenantForm,
  } from './tenants';

  // Sizes are shown with the binary units of the size fields (MiB, GiB, TiB).
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  let { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    name: `${uid}-name`,
    fqdn: `${uid}-fqdn`,
    defaultLanguage: `${uid}-language`,
    storageQuotaBytes: `${uid}-quota`,
    maxTransferCeiling: `${uid}-ceiling`,
    maxTransferBytes: `${uid}-max`,
  };

  const tenantId = $derived(params['id'] ?? '');
  const role = $derived(adminSession.me?.role);
  const isSuper = $derived(role === 'super_admin');
  const fields = $derived(editableFields(role));

  let tenant = $state.raw<Tenant | undefined>(undefined);
  let form = $state<TenantForm | undefined>(undefined);
  let loading = $state(true);
  let notFound = $state(false);
  let loadError = $state('');
  let errors = $state<SummaryError[]>([]);
  let inputs: Partial<Record<SizeField, HTMLInputElement>> = $state({});

  // Deletion.
  let deleteOpen = $state(false);
  let deleted = $state(false);
  let deleteMessage = $state('');
  const deleting = $derived(tenant?.status === 'deleting');
  const dirty = $derived(
    !deleted && tenant !== undefined && form !== undefined && isDirty(tenant, form, role),
  );
  // Ceiling of the size per transfer: the edited one for the super admin, else the saved one.
  const ceiling = $derived(
    isSuper
      ? Math.min(form?.maxTransferCeiling ?? MAX_TRANSFER_BYTES, MAX_TRANSFER_BYTES)
      : (tenant?.maxTransferCeiling ?? MAX_TRANSFER_BYTES),
  );

  // A super admin lowering the ceiling below the saved limit: the server lowers the limit too.
  const followsCeiling = $derived(
    tenant !== undefined && form !== undefined && limitFollowsCeiling(tenant, form, role),
  );

  const refs = $derived<TenantFieldRefs>({
    name: { id: ids.name, label: t('adminTenants.fields.name.label') },
    fqdn: { id: ids.fqdn, label: t('adminTenants.fields.fqdn.label') },
    defaultLanguage: { id: ids.defaultLanguage, label: t('adminTenants.fields.defaultLanguage.label') },
    storageQuotaBytes: { id: ids.storageQuotaBytes, label: t('adminTenants.fields.storageQuota.label') },
    maxTransferCeiling: {
      id: ids.maxTransferCeiling,
      label: t('adminTenants.fields.maxTransferCeiling.label'),
    },
    maxTransferBytes: { id: ids.maxTransferBytes, label: t('adminTenants.fields.maxTransfer.label') },
  });

  const languageOptions = $derived(
    TENANT_LANGUAGES.map((code) => ({ value: code, label: languageLabel(code, locale.current) })),
  );

  function show(next: Tenant): void {
    tenant = next;
    form = formFromTenant(next);
  }

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    notFound = false;
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}', { path: { tenantId } });
      show(res.data);
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 404) {
        notFound = true;
      } else {
        loadError = describeError(i18n, err).message;
      }
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
  });

  function isEmpty(input: HTMLInputElement | undefined): boolean {
    return input === undefined || input.value.trim() === '';
  }

  /** Error to show on a size field: a null size with a typed value shows the field's own error. */
  function sizeError(field: SizeField, bytes: number | null | undefined): string | undefined {
    if (bytes === null && !isEmpty(inputs[field])) {
      return undefined;
    }
    return errorFor(errors, ids[field]);
  }

  function validate(): SummaryError[] {
    if (form === undefined) {
      return [];
    }
    return validateTenantForm(
      form,
      {
        fields,
        ceiling,
        limitFollowsCeiling: followsCeiling,
        empty: {
          storageQuotaBytes: isEmpty(inputs.storageQuotaBytes),
          maxTransferCeiling: isEmpty(inputs.maxTransferCeiling),
          maxTransferBytes: isEmpty(inputs.maxTransferBytes),
        },
      },
      refs,
      t,
      formatBytes,
    );
  }

  async function save(): Promise<SubmitOutcome> {
    if (tenant === undefined || form === undefined) {
      return { ok: false, message: t('errors.unknown') };
    }
    const patch = tenantPatch(tenant, form, role);
    if (Object.keys(patch).length === 0) {
      return { ok: true, message: t('admin.common.noChanges') };
    }
    try {
      const res = await adminApi.patch('/admin/tenants/{tenantId}', { path: { tenantId }, body: patch });
      show(res.data);
      if (changesProfile(patch)) {
        await adminSession.refreshMe().catch(() => undefined);
      }
      return { ok: true, message: t('adminTenants.general.saved') };
    } catch (err) {
      return tenantFailure(describeError(i18n, err), refs, t);
    }
  }

  async function remove(): Promise<string | void> {
    if (tenant === undefined) {
      return t('errors.unknown');
    }
    const name = tenant.name;
    deleteMessage = '';
    try {
      await adminApi.delete('/admin/tenants/{tenantId}', { path: { tenantId }, params: { confirm: name } });
    } catch (err) {
      const view = describeError(i18n, err);
      if (!deletionResumes(view)) {
        return view.message;
      }
      // The tenant stays "deleting"; the cleanup task (or a new attempt) completes the deletion.
      tenant = { ...tenant, status: 'deleting' };
      deleteMessage = t('adminTenants.general.delete.resumes');
      await adminSession.refreshMe().catch(() => undefined);
      return;
    }
    deleted = true;
    await tick();
    await adminSession.refreshMe().catch(() => undefined);
    await nav.navigate('/tenants');
    announce(t('adminTenants.general.delete.done', { name }));
  }

  function storageText(current: Tenant): string {
    const usage = quotaUsage(current);
    return t('adminTenants.general.storage', {
      used: formatBytes(usage.used),
      quota: formatBytes(usage.quota),
      percent: formatNumber(usage.percent, { maximumFractionDigits: 1 }),
    });
  }
</script>

{#if notFound}
  <NotFound {params} {nav} />
{:else}
  <h1 tabindex="-1">{t('adminTenants.general.title')}</h1>

  {#if loading}
    <p><Spinner showLabel /></p>
  {:else if loadError !== ''}
    <Alert severity="error">
      <p>{loadError}</p>
      <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
    </Alert>
  {:else if tenant !== undefined && form !== undefined}
    {@const status = statusView(tenant.status)}
    <p>
      <StatusBadge variant={status.variant} label={t(status.key)} />
    </p>
    <p>{storageText(tenant)}</p>

    {#if deleting}
      <Alert severity="warning" live={false}>{t('adminTenants.general.deletingBanner')}</Alert>
    {/if}
    {#if deleteMessage !== ''}
      <Alert severity="error">{deleteMessage}</Alert>
    {/if}

    {#if !isSuper}
      <Alert severity="info" live={false}>{t('adminTenants.general.delegatedNote')}</Alert>
      <dl class="tt-dl">
        <dt>{t('adminTenants.fields.name.label')}</dt>
        <dd>{tenant.name}</dd>
        <dt>{t('adminTenants.fields.fqdn.label')}</dt>
        <dd>{tenant.fqdn}</dd>
        <dt>{t('adminTenants.fields.storageQuota.label')}</dt>
        <dd>{formatBytes(tenant.storageQuotaBytes)}</dd>
        <dt>{t('adminTenants.fields.maxTransferCeiling.label')}</dt>
        <dd>{formatBytes(tenant.maxTransferCeiling)}</dd>
      </dl>
    {/if}

    <FormSection
      title={t('adminTenants.general.legend')}
      as="fieldset"
      {dirty}
      addGuard={(guard) => nav.addGuard(guard)}
      {validate}
      onsubmit={save}
      bind:errors
      disabled={deleting}
      successMessage={t('adminTenants.general.saved')}
    >
      {#if isSuper}
        <TextField
          id={ids.name}
          label={t('adminTenants.fields.name.label')}
          hint={t('adminTenants.fields.name.hint')}
          required
          maxlength={200}
          autocomplete="off"
          disabled={deleting}
          error={errorFor(errors, ids.name)}
          bind:value={form.name}
        />
        <TextField
          id={ids.fqdn}
          label={t('adminTenants.fields.fqdn.label')}
          hint={t('adminTenants.fields.fqdn.hint')}
          required
          maxlength={253}
          autocomplete="off"
          spellcheck={false}
          autocapitalize="none"
          disabled={deleting}
          error={errorFor(errors, ids.fqdn)}
          bind:value={form.fqdn}
        />
      {/if}
      <RadioGroup
        name={ids.defaultLanguage}
        legend={t('adminTenants.fields.defaultLanguage.label')}
        hint={t('adminTenants.fields.defaultLanguage.hint')}
        options={languageOptions}
        inline
        required
        disabled={deleting}
        error={errorFor(errors, ids.defaultLanguage)}
        bind:value={form.defaultLanguage}
      />
      {#if isSuper}
        <ByteSizeField
          id={ids.storageQuotaBytes}
          label={t('adminTenants.fields.storageQuota.label')}
          hint={t('adminTenants.fields.storageQuota.hint')}
          defaultUnit="TiB"
          required
          error={sizeError('storageQuotaBytes', form.storageQuotaBytes)}
          bind:element={inputs.storageQuotaBytes}
          bind:bytes={form.storageQuotaBytes}
        />
        <ByteSizeField
          id={ids.maxTransferCeiling}
          label={t('adminTenants.fields.maxTransferCeiling.label')}
          hint={t('adminTenants.fields.maxTransferCeiling.hint')}
          max={MAX_TRANSFER_BYTES}
          required
          error={sizeError('maxTransferCeiling', form.maxTransferCeiling)}
          bind:element={inputs.maxTransferCeiling}
          bind:bytes={form.maxTransferCeiling}
        />
      {/if}
      <ByteSizeField
        id={ids.maxTransferBytes}
        label={t('adminTenants.fields.maxTransfer.label')}
        hint={followsCeiling
          ? t('adminTenants.fields.maxTransfer.followsCeiling', { ceiling: formatBytes(ceiling) })
          : t('adminTenants.fields.maxTransfer.hintCeiling', { ceiling: formatBytes(ceiling) })}
        required
        error={sizeError('maxTransferBytes', form.maxTransferBytes)}
        bind:element={inputs.maxTransferBytes}
        bind:bytes={form.maxTransferBytes}
      />
    </FormSection>

    {#if isSuper}
      <section aria-labelledby="{uid}-delete">
        <h2 id="{uid}-delete">{t('adminTenants.general.delete.title')}</h2>
        <p>{t('adminTenants.general.delete.text')}</p>
        <Button
          variant="danger"
          onclick={() => {
            deleteOpen = true;
          }}
        >
          {t('adminTenants.general.delete.action')}
        </Button>
      </section>
      <ConfirmDialog
        bind:open={deleteOpen}
        title={t('adminTenants.general.delete.confirmTitle', { name: tenant.name })}
        text={t('adminTenants.general.delete.confirmText')}
        danger
        confirmText={tenant.name}
        confirmLabel={t('adminTenants.general.delete.confirmAction')}
        busyLabel={t('admin.common.deleting')}
        onconfirm={remove}
      />
    {/if}
  {/if}
{/if}
