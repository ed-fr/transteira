<script lang="ts">
  // Creation of a tenant from an exported configuration (POST /admin/tenants/import), super admin
  // only. Two entries, one screen:
  // - /tenants/import: the configuration is read from a JSON file chosen with a file picker
  //   (32 MiB at most; a file that is not JSON is refused with a clear message);
  // - /tenants/import?from=<tenantId> ("Duplicate" in the list): the screen fetches the export of
  //   that tenant itself, branding files included, and the storage quota of the source is
  //   proposed.
  // The name, the FQDN and the storage quota are entered; the first delegated administrator is
  // optional, as in TenantCreate. The server validates the configuration strictly: 422
  // import-invalid gives the JSON pointer of the first error, shown as "Error in the file at
  // <location>"; 409 is an FQDN already used (on the FQDN field). On success the setup wizard of
  // the new tenant is shown (an imported tenant is created in the setup state), after the
  // activation link of the administrator when one was created.
  import { onMount, tick, untrack } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Checkbox, Spinner, TextField, announce } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ActivationLinkPanel from '../../components/ActivationLinkPanel.svelte';
  import ByteSizeField from '../../components/ByteSizeField.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import InvitationFields from '../../components/InvitationFields.svelte';
  import InvitationSent from '../../components/InvitationSent.svelte';
  import { formatBytes as formatBinaryBytes } from '../../forms/bytes';
  import { asInvitationLanguage, type ActivationLink } from '../admins/admins';
  import type { AdminScreenProps } from '../types';
  import { setupPath } from './setup';
  import {
    MAX_IMPORT_FILE_BYTES,
    configFileMessage,
    configFileTooLarge,
    configLanguage,
    duplicateSource,
    emptyImportForm,
    importBody,
    importFailure,
    parseConfigText,
    webhookCount,
    type TenantConfigExport,
  } from './tenantTransfer';
  import {
    TENANT_LANGUAGES,
    delegatedLanguage,
    emptyDelegatedForm,
    validateDelegated,
    validateTenantForm,
    type DelegatedFieldRefs,
    type Language,
    type Tenant,
    type TenantCreated,
    type TenantFieldRefs,
  } from './tenants';

  // Sizes are shown with the binary units of the size fields (MiB, GiB, TiB).
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  let { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    file: `${uid}-file`,
    name: `${uid}-name`,
    fqdn: `${uid}-fqdn`,
    storageQuotaBytes: `${uid}-quota`,
    delegatedEnabled: `${uid}-delegated-enabled`,
    delegatedUsername: `${uid}-delegated-username`,
    delegatedEmail: `${uid}-delegated-email`,
    invitation: `${uid}-invitation`,
  };

  // The source tenant of a duplication, read once: the screen is kept when only the query changes.
  const source = untrack(() => duplicateSource(nav.current.search));
  const fallbackLanguage: Language = TENANT_LANGUAGES.includes(locale.current as Language)
    ? (locale.current as Language)
    : 'en';

  let form = $state(emptyImportForm());
  let errors = $state<SummaryError[]>([]);
  let delegated = $state(emptyDelegatedForm());
  let config = $state.raw<TenantConfigExport | undefined>(undefined);
  let sourceTenant = $state.raw<Tenant | undefined>(undefined);
  // Loading of the source tenant (duplication only).
  let loading = $state(source !== undefined);
  let loadError = $state('');
  // File mode: the chosen file name, and why it is refused.
  let fileName = $state('');
  let fileError = $state('');
  let quotaInput: HTMLInputElement | undefined = $state();
  let created = $state(false);
  let result = $state<{ tenant: TenantCreated; link: ActivationLink | undefined; email: string } | undefined>(
    undefined,
  );

  const dirty = $derived(
    !created &&
      (form.name.trim() !== '' ||
        form.fqdn.trim() !== '' ||
        delegated.enabled ||
        (source === undefined && config !== undefined)),
  );

  const refs = $derived<TenantFieldRefs>({
    name: { id: ids.name, label: t('adminTenants.fields.name.label') },
    fqdn: { id: ids.fqdn, label: t('adminTenants.fields.fqdn.label') },
    storageQuotaBytes: { id: ids.storageQuotaBytes, label: t('adminTenants.fields.storageQuota.label') },
  });
  const delegatedRefs = $derived<DelegatedFieldRefs>({
    username: { id: ids.delegatedUsername, label: t('adminTenants.create.delegated.username') },
    email: { id: ids.delegatedEmail, label: t('adminTenants.create.delegated.email') },
  });
  const fileRef = $derived({ id: ids.file, label: t('adminTenants.import.file.label') });
  const hooks = $derived(webhookCount(config));

  onMount(() => {
    if (source !== undefined) {
      void loadSource(source);
    }
  });

  /** Loads the tenant to duplicate and its export (with the branding files). */
  async function loadSource(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const [tenant, exported] = await Promise.all([
        adminApi.get('/admin/tenants/{tenantId}', { path: { tenantId: id } }),
        adminApi.get('/admin/tenants/{tenantId}/export', {
          path: { tenantId: id },
          params: { includeBranding: true },
        }),
      ]);
      sourceTenant = tenant.data;
      config = exported.data;
      form.storageQuotaBytes = tenant.data.storageQuotaBytes;
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  /** Reads the chosen file: size first, then the JSON text. */
  async function onFile(event: Event): Promise<void> {
    const file = (event.currentTarget as HTMLInputElement).files?.[0];
    config = undefined;
    fileName = '';
    fileError = '';
    if (file === undefined) {
      return;
    }
    if (configFileTooLarge(file.size)) {
      fileError = configFileMessage('too-large', t);
      return;
    }
    let text: string;
    try {
      text = await file.text();
    } catch {
      fileError = t('adminTenants.import.file.errors.unreadable');
      return;
    }
    const parsed = parseConfigText(text);
    if (!parsed.ok) {
      fileError = configFileMessage(parsed.problem, t);
      return;
    }
    config = parsed.config;
    fileName = file.name;
    errors = errors.filter((e) => e.id !== ids.file);
    announce(t('adminTenants.import.file.loaded', { name: file.name }));
  }

  function isEmpty(input: HTMLInputElement | undefined): boolean {
    return input === undefined || input.value.trim() === '';
  }

  function validate(): SummaryError[] {
    const own: SummaryError[] = [];
    if (source === undefined && config === undefined) {
      own.push({
        id: ids.file,
        label: fileRef.label,
        message: fileError !== '' ? fileError : t('adminTenants.import.file.errors.required'),
      });
    }
    own.push(
      ...validateTenantForm(
        { ...form, defaultLanguage: 'en', maxTransferBytes: 0, maxTransferCeiling: 0 },
        { fields: ['name', 'fqdn', 'storageQuotaBytes'], empty: { storageQuotaBytes: isEmpty(quotaInput) } },
        refs,
        t,
        formatBytes,
      ),
      ...validateDelegated(delegated, delegatedRefs, t),
    );
    return own;
  }

  async function open(id: string): Promise<void> {
    result = undefined;
    await nav.navigate(setupPath(id));
  }

  async function submit(): Promise<SubmitOutcome> {
    const language = configLanguage(config, fallbackLanguage);
    const body = config === undefined ? undefined : importBody(form, config, delegated, language);
    if (body === undefined) {
      return { ok: false, errors: validate() };
    }
    try {
      const res = await adminApi.post('/admin/tenants/import', { body });
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
      const rawField = err instanceof ApiProblem ? err.errors?.[0]?.field : undefined;
      return importFailure(describeError(i18n, err), rawField, refs, t, {
        // In duplication the file is not chosen by the user: the error is a general message.
        file: source === undefined ? fileRef : undefined,
        delegatedRefs: delegated.enabled ? delegatedRefs : undefined,
      });
    }
  }
</script>

<h1 tabindex="-1">
  {sourceTenant === undefined
    ? t('adminTenants.import.title')
    : t('adminTenants.import.titleDuplicate', { name: sourceTenant.name })}
</h1>

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
{:else if loading}
  <p><Spinner label={t('admin.common.loading')} showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">
    <p>{t('adminTenants.import.loadError')}</p>
    <p>{loadError}</p>
  </Alert>
{:else}
  <p>
    {sourceTenant === undefined
      ? t('adminTenants.import.intro')
      : t('adminTenants.import.introDuplicate', { name: sourceTenant.name })}
  </p>
  <FormSection
    title={t('adminTenants.import.legend')}
    as="fieldset"
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    {validate}
    onsubmit={submit}
    bind:errors
    saveLabel={t('adminTenants.import.submit')}
    savingLabel={t('admin.common.creating')}
  >
    {#if source === undefined}
      <div class="tt-file">
        <label for={ids.file}>{t('adminTenants.import.file.label')}</label>
        <p class="tt-file__hint" id="{ids.file}-hint">{t('adminTenants.import.file.hint')}</p>
        <input
          id={ids.file}
          type="file"
          accept=".json,application/json"
          aria-describedby="{ids.file}-hint{fileError !== '' || errorFor(errors, ids.file) !== undefined
            ? ` ${ids.file}-error`
            : ''}"
          aria-invalid={fileError !== '' || errorFor(errors, ids.file) !== undefined ? 'true' : undefined}
          data-max-bytes={MAX_IMPORT_FILE_BYTES}
          onchange={(event) => void onFile(event)}
        />
        {#if fileError !== '' || errorFor(errors, ids.file) !== undefined}
          <p class="tt-file__error" id="{ids.file}-error">{fileError || errorFor(errors, ids.file)}</p>
        {:else if fileName !== ''}
          <p role="status">{t('adminTenants.import.file.loaded', { name: fileName })}</p>
        {/if}
      </div>
    {/if}
    {#if hooks > 0}
      <Alert severity="info" live={false}>{t('adminTenants.import.webhooks', { count: hooks })}</Alert>
    {/if}
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
    <ByteSizeField
      id={ids.storageQuotaBytes}
      label={t('adminTenants.fields.storageQuota.label')}
      hint={t('adminTenants.fields.storageQuota.hint')}
      defaultUnit="TiB"
      required
      error={errorFor(errors, ids.storageQuotaBytes)}
      bind:element={quotaInput}
      bind:bytes={form.storageQuotaBytes}
    />
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
            () => delegatedLanguage(delegated, configLanguage(config, fallbackLanguage)),
            (value) =>
              (delegated.language = asInvitationLanguage(value, configLanguage(config, fallbackLanguage)))
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

  .tt-file {
    margin-bottom: var(--tt-space-4);
  }

  .tt-file label {
    display: block;
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-file__hint {
    margin: var(--tt-space-1) 0;
  }

  .tt-file__error {
    margin: var(--tt-space-1) 0 0;
    color: var(--tt-danger);
    font-weight: var(--tt-font-weight-bold);
    font-size: var(--tt-font-size-sm);
  }
</style>
