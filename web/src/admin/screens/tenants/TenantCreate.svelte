<script lang="ts">
  // Creation of a tenant by the super admin (POST /admin/tenants): name, FQDN, default
  // language, storage quota, ceiling of the size per transfer (at most 20 GiB) and size per
  // transfer (at most the ceiling). An FQDN already used (409) or equal to an admin host (400 on
  // /fqdn with the field code reserved-host) is reported on the field with a dedicated message,
  // any other FQDN refusal with the message of its code (tenantFailure). On success the admin profile is reloaded (it lists the
  // tenants) and the general settings of the new tenant are shown.
  import { tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { RadioGroup, TextField, announce } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ByteSizeField from '../../components/ByteSizeField.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { MAX_TRANSFER_BYTES, formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    TENANT_FIELDS,
    TENANT_LANGUAGES,
    createBody,
    emptyForm,
    languageLabel,
    tenantFailure,
    validateTenantForm,
    type Language,
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
  };

  const initialLanguage: Language = TENANT_LANGUAGES.includes(locale.current as Language)
    ? (locale.current as Language)
    : 'en';
  let form = $state(emptyForm(initialLanguage));
  let errors = $state<SummaryError[]>([]);
  let created = $state(false);
  let inputs: Partial<
    Record<'storageQuotaBytes' | 'maxTransferCeiling' | 'maxTransferBytes', HTMLInputElement>
  > = $state({});
  const dirty = $derived(!created && (form.name.trim() !== '' || form.fqdn.trim() !== ''));

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
    return validateTenantForm(
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
  }

  async function submit(): Promise<SubmitOutcome> {
    const body = createBody(form);
    if (body === undefined) {
      return { ok: false, errors: validate() };
    }
    try {
      const res = await adminApi.post('/admin/tenants', { body });
      created = true;
      await tick();
      await adminSession.refreshMe().catch(() => undefined);
      await nav.navigate(tenantPath(res.data.id, 'general'));
      announce(t('adminTenants.create.created', { name: res.data.name }));
      return { ok: true, message: t('adminTenants.create.created', { name: res.data.name }) };
    } catch (err) {
      return tenantFailure(describeError(i18n, err), refs, t);
    }
  }
</script>

<h1 tabindex="-1">{t('adminTenants.create.title')}</h1>

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
</FormSection>
