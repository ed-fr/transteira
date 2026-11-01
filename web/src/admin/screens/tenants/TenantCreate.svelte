<script lang="ts">
  // Creation of a tenant by the super admin (POST /admin/tenants): name, FQDN, default
  // language, storage quota, ceiling of the size per transfer (at most 20 GiB) and size per
  // transfer (at most the ceiling). An FQDN already used (409) or equal to an admin host (400 on
  // /fqdn with the field code reserved-host) is reported on the field with a dedicated message,
  // any other FQDN refusal with the message of its code (tenantFailure). On success the admin profile is reloaded (it lists the
  // tenants) and the setup wizard of the new tenant is shown: a tenant is always created in the
  // setup state (setupState: "setup") and stays closed to deposits until the wizard is completed.
  // Optionally the first delegated administrator is created in the same request (since API 1.2):
  // its activation link is mailed (default) or shown once to copy; the result is then shown
  // before going to the tenant. Without system SMTP (503) nothing is created and the form keeps
  // its values, so that the copy delivery can be chosen. The background image is chosen among the
  // library (GET /admin/background-presets), after the size fields; it is sent only when it is
  // not the default (backgroundPreset). If the library cannot be loaded, an informative alert is
  // shown and the entity is created with the default background (changeable later in Branding).
  import { tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Checkbox, RadioGroup, Spinner, TextField, announce } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ActivationLinkPanel from '../../components/ActivationLinkPanel.svelte';
  import BackgroundPresetPicker from '../../components/BackgroundPresetPicker.svelte';
  import { DEFAULT_PRESET, type PresetItem } from '../../components/backgroundPresets';
  import ByteSizeField from '../../components/ByteSizeField.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import InvitationFields from '../../components/InvitationFields.svelte';
  import InvitationSent from '../../components/InvitationSent.svelte';
  import { MAX_TRANSFER_BYTES, formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { asInvitationLanguage, type ActivationLink } from '../admins/admins';
  import type { AdminScreenProps } from '../types';
  import { setupPath } from './setup';
  import {
    TENANT_FIELDS,
    TENANT_LANGUAGES,
    createBody,
    delegatedLanguage,
    emptyDelegatedForm,
    emptyForm,
    languageLabel,
    tenantFailure,
    validateDelegated,
    validateTenantForm,
    type DelegatedFieldRefs,
    type Language,
    type TenantCreated,
    type TenantFieldRefs,
  } from './tenants';

  // Sizes are shown with the binary units of the size fields (MiB, GiB, TiB).
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  let { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    name: `${uid}-name`,
    fqdn: `${uid}-fqdn`,
    defaultLanguage: `${uid}-language`,
    storageQuotaBytes: `${uid}-quota`,
    maxTransferCeiling: `${uid}-ceiling`,
    maxTransferBytes: `${uid}-max`,
    delegatedEnabled: `${uid}-delegated-enabled`,
    delegatedUsername: `${uid}-delegated-username`,
    delegatedEmail: `${uid}-delegated-email`,
    invitation: `${uid}-invitation`,
  };

  const initialLanguage: Language = TENANT_LANGUAGES.includes(locale.current as Language)
    ? (locale.current as Language)
    : 'en';
  let form = $state(emptyForm(initialLanguage));
  let errors = $state<SummaryError[]>([]);
  let delegated = $state(emptyDelegatedForm());
  let presets = $state.raw<PresetItem[]>([]);
  let presetsStatus = $state<'loading' | 'ready' | 'error'>('loading');
  let backgroundChoice = $state(DEFAULT_PRESET);
  let created = $state(false);
  // Result shown instead of the form when an administrator was created with the tenant.
  let result = $state<{ tenant: TenantCreated; link: ActivationLink | undefined; email: string } | undefined>(
    undefined,
  );
  let inputs: Partial<
    Record<'storageQuotaBytes' | 'maxTransferCeiling' | 'maxTransferBytes', HTMLInputElement>
  > = $state({});
  const dirty = $derived(
    !created &&
      (form.name.trim() !== '' ||
        form.fqdn.trim() !== '' ||
        delegated.enabled ||
        backgroundChoice !== DEFAULT_PRESET),
  );

  $effect(() => {
    void loadPresets();
  });

  async function loadPresets(): Promise<void> {
    try {
      const res = await adminApi.get('/admin/background-presets');
      presets = res.data.items;
      presetsStatus = 'ready';
    } catch {
      presetsStatus = 'error';
    }
  }

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

  const delegatedRefs = $derived<DelegatedFieldRefs>({
    username: { id: ids.delegatedUsername, label: t('adminTenants.create.delegated.username') },
    email: { id: ids.delegatedEmail, label: t('adminTenants.create.delegated.email') },
  });

  const languageOptions = $derived(
    TENANT_LANGUAGES.map((code) => ({ value: code, label: languageLabel(code, locale.current) })),
  );

  function isEmpty(input: HTMLInputElement | undefined): boolean {
    return input === undefined || input.value.trim() === '';
  }

  /** Error to show on a size field: a null size with a typed value shows the field's own error. */
  function sizeError(field: keyof typeof inputs, bytes: number | null): string | undefined {
    if (bytes === null && !isEmpty(inputs[field])) {
      return undefined;
    }
    return errorFor(errors, ids[field]);
  }

  function validate(): SummaryError[] {
    const own = validateTenantForm(
      form,
      {
        fields: TENANT_FIELDS,
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
    return [...own, ...validateDelegated(delegated, delegatedRefs, t)];
  }

  async function open(id: string): Promise<void> {
    result = undefined;
    await nav.navigate(setupPath(id));
  }

  async function submit(): Promise<SubmitOutcome> {
    const body = createBody(form, delegated, backgroundChoice);
    if (body === undefined) {
      return { ok: false, errors: validate() };
    }
    try {
      const res = await adminApi.post('/admin/tenants', { body });
      created = true;
      await tick();
      await adminSession.refreshMe().catch(() => undefined);
      const invited = res.data.delegatedAdmin;
      if (invited !== undefined) {
        // Show the link (or the confirmation) before leaving: the link is shown only once.
        result = {
          tenant: res.data,
          link:
            invited.invitationDelivery === 'copy' && invited.activationUrl !== undefined
              ? { url: invited.activationUrl, expiresAt: invited.activationExpiresAt }
              : undefined,
          email: delegated.email.trim(),
        };
        return { ok: true, message: t('adminTenants.create.created', { name: res.data.name }) };
      }
      await nav.navigate(setupPath(res.data.id));
      announce(t('adminTenants.create.created', { name: res.data.name }));
      return { ok: true, message: t('adminTenants.create.created', { name: res.data.name }) };
    } catch (err) {
      return tenantFailure(
        describeError(i18n, err),
        refs,
        t,
        delegated.enabled ? { refs: delegatedRefs } : undefined,
      );
    }
  }
</script>

<h1 tabindex="-1">{t('adminTenants.create.title')}</h1>

{#if result !== undefined}
  <Alert severity="success">{t('adminTenants.create.created', { name: result.tenant.name })}</Alert>
  {#if result.link !== undefined}
    <ActivationLinkPanel
      link={result.link}
      username={delegated.username.trim()}
      addGuard={(guard) => nav.addGuard(guard)}
      ondone={() => void open(result?.tenant.id ?? '')}
    />
  {:else}
    <InvitationSent
      email={result.email}
      expiresAt={result.tenant.delegatedAdmin?.activationExpiresAt ?? ''}
      doneLabel={t('adminTenants.create.delegated.continue')}
      ondone={() => void open(result?.tenant.id ?? '')}
    />
  {/if}
{:else}
  <FormSection
    title={t('adminTenants.create.legend')}
    as="fieldset"
    intro={t('adminTenants.create.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    {validate}
    onsubmit={submit}
    bind:errors
    saveLabel={t('adminTenants.create.submit')}
    savingLabel={t('admin.common.creating')}
  >
    <TextField
      id={ids.name}
      label={t('adminTenants.fields.name.label')}
      hint={t('adminTenants.fields.name.hint')}
      required
      maxlength={200}
      autocomplete="off"
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
      error={errorFor(errors, ids.fqdn)}
      bind:value={form.fqdn}
    />
    <RadioGroup
      name={ids.defaultLanguage}
      legend={t('adminTenants.fields.defaultLanguage.label')}
      hint={t('adminTenants.fields.defaultLanguage.hint')}
      options={languageOptions}
      inline
      required
      error={errorFor(errors, ids.defaultLanguage)}
      bind:value={form.defaultLanguage}
    />
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
    <ByteSizeField
      id={ids.maxTransferBytes}
      label={t('adminTenants.fields.maxTransfer.label')}
      hint={t('adminTenants.fields.maxTransfer.hintCeiling', {
        ceiling: formatBytes(form.maxTransferCeiling ?? MAX_TRANSFER_BYTES),
      })}
      required
      error={sizeError('maxTransferBytes', form.maxTransferBytes)}
      bind:element={inputs.maxTransferBytes}
      bind:bytes={form.maxTransferBytes}
    />
    {#if presetsStatus === 'loading'}
      <p><Spinner label={t('admin.common.loading')} showLabel /></p>
    {:else if presetsStatus === 'error'}
      <Alert severity="info">{t('adminTenants.create.background.loadError')}</Alert>
    {:else}
      <BackgroundPresetPicker
        items={presets}
        legend={t('adminTenants.create.background.legend')}
        hint={t('adminTenants.create.background.hint')}
        bind:choice={backgroundChoice}
      />
    {/if}
    <fieldset class="tt-delegated">
      <legend>{t('adminTenants.create.delegated.legend')}</legend>
      <Checkbox
        id={ids.delegatedEnabled}
        label={t('adminTenants.create.delegated.enable')}
        hint={t('adminTenants.create.delegated.enableHint')}
        bind:checked={delegated.enabled}
      />
      {#if delegated.enabled}
        <TextField
          id={ids.delegatedUsername}
          label={t('adminTenants.create.delegated.username')}
          hint={t('adminAccounts.form.username.hint')}
          required
          autocomplete="off"
          autocapitalize="none"
          spellcheck={false}
          maxlength={64}
          error={errorFor(errors, ids.delegatedUsername)}
          bind:value={delegated.username}
        />
        <TextField
          id={ids.delegatedEmail}
          type="email"
          label={t('adminTenants.create.delegated.email')}
          required
          autocomplete="off"
          error={errorFor(errors, ids.delegatedEmail)}
          bind:value={delegated.email}
        />
        <InvitationFields
          idPrefix={ids.invitation}
          bind:delivery={delegated.delivery}
          bind:language={
            () => delegatedLanguage(delegated, form.defaultLanguage),
            (value) => (delegated.language = asInvitationLanguage(value, form.defaultLanguage))
          }
        />
      {/if}
    </fieldset>
  </FormSection>
{/if}

<style>
  .tt-delegated {
    margin: var(--tt-space-4) 0 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }

  .tt-delegated legend {
    padding: 0;
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }
</style>
