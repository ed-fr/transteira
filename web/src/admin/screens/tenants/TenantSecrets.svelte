<script lang="ts">
  // One-time secrets settings of a tenant (version 2.1, CLAUDE.md section 22.1): GET/PUT
  // /admin/tenants/{id}/secret-settings. The module switch, the offered durations (checkboxes
  // from the catalogue) and the preselected one, the optional small file (size 1 to 25 MiB) and
  // the e-mail delivery with its passphrase rule. The PUT replaces every setting. Client-side
  // validation mirrors the specification, the server field errors are mapped to the fields.
  // An auditor has no access (403 read-only-role, shown as a load error).
  // The tenant sub-navigation is rendered by App.svelte.
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Checkbox, HelpIcon, Spinner, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import type { AdminScreenProps } from '../types';
  import {
    MAX_FILE_MIB,
    MIN_FILE_MIB,
    SECRET_DURATIONS,
    secretDraftChanged,
    secretSettingsBody,
    toDraft,
    toggleDuration,
    validateSecretSettings,
    type SecretDuration,
    type SecretSettings,
    type SecretSettingsDraft,
  } from './secretSettings';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    durations: `${uid}-durations`,
    defaultDuration: `${uid}-default`,
    fileMaxBytes: `${uid}-file`,
  };

  let loading = $state(true);
  let loadError = $state('');
  let saved = $state.raw<SecretSettingsDraft | undefined>(undefined);
  let draft = $state<SecretSettingsDraft>({
    enabled: true,
    durations: [],
    defaultDuration: '',
    fileAllowed: true,
    fileMibText: '10',
    emailAllowed: true,
    emailRequiresPassphrase: false,
  });
  let errors = $state<SummaryError[]>([]);

  const tenantId = $derived(params['id'] ?? '');
  const fields = $derived({
    durations: { id: ids.durations, label: t('adminSecrets.settings.durations.label') },
    defaultDuration: { id: ids.defaultDuration, label: t('adminSecrets.settings.defaultDuration.label') },
    fileMaxBytes: { id: ids.fileMaxBytes, label: t('adminSecrets.settings.fileMaxBytes.label') },
  });
  const dirty = $derived(saved !== undefined && secretDraftChanged(saved, draft));
  const defaultOptions = $derived(
    draft.durations.map((d) => ({ value: d, label: t(`adminSecrets.duration.${d}`) })),
  );

  function show(settings: SecretSettings): void {
    const next = toDraft(settings);
    saved = next;
    draft = { ...next, durations: [...next.durations] };
  }

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/secret-settings', { path: { tenantId: id } });
      show(res.data);
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load(tenantId);
  });

  function toggle(duration: SecretDuration, on: boolean): void {
    draft = { ...draft, ...toggleDuration(draft, duration, on) };
  }

  async function save(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/secret-settings', {
        path: { tenantId },
        body: secretSettingsBody(draft),
      });
      show(res.data);
      return { ok: true, message: t('adminSecrets.settings.saved') };
    } catch (err) {
      const view = describeError(i18n, err);
      const mapped = summaryFromFields(view.fields, fields);
      const message = mapped.errors.length === 0 || mapped.unmatched.length > 0 ? view.message : undefined;
      return message === undefined
        ? { ok: false, errors: mapped.errors }
        : { ok: false, errors: mapped.errors, message };
    }
  }
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminTenants.secrets.title')}</h1>
  <HelpIcon topic="tenant-secrets" title={t('adminTenants.secrets.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">{loadError}</Alert>
{:else}
  <FormSection
    title={t('adminSecrets.settings.form.title')}
    intro={t('adminTenants.secrets.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    validate={() => validateSecretSettings(draft, fields, t)}
    onsubmit={save}
    bind:errors
  >
    <Checkbox
      label={t('adminSecrets.settings.enabled.label')}
      hint={t('adminSecrets.settings.enabled.hint')}
      bind:checked={draft.enabled}
    />

    <fieldset
      class="tt-secrets__group"
      id={ids.durations}
      tabindex="-1"
      aria-describedby={errorFor(errors, ids.durations) === undefined ? undefined : `${ids.durations}-error`}
    >
      <legend>{t('adminSecrets.settings.durations.label')}</legend>
      <p class="tt-text-sm tt-text-muted">{t('adminSecrets.settings.durations.hint')}</p>
      <div class="tt-secrets__inline">
        {#each SECRET_DURATIONS as duration (duration)}
          <Checkbox
            label={t(`adminSecrets.duration.${duration}`)}
            checked={draft.durations.includes(duration)}
            onchange={(e) => toggle(duration, e.currentTarget.checked)}
          />
        {/each}
      </div>
      {#if errorFor(errors, ids.durations)}
        <p class="tt-text-danger" id="{ids.durations}-error">{errorFor(errors, ids.durations)}</p>
      {/if}
    </fieldset>

    <SelectField
      id={ids.defaultDuration}
      label={t('adminSecrets.settings.defaultDuration.label')}
      hint={t('adminSecrets.settings.defaultDuration.hint')}
      options={defaultOptions}
      bind:value={draft.defaultDuration}
      error={errorFor(errors, ids.defaultDuration)}
    />

    <Checkbox
      label={t('adminSecrets.settings.fileAllowed.label')}
      hint={t('adminSecrets.settings.fileAllowed.hint')}
      bind:checked={draft.fileAllowed}
    />
    <TextField
      id={ids.fileMaxBytes}
      label={t('adminSecrets.settings.fileMaxBytes.label')}
      hint={t('adminSecrets.settings.fileMaxBytes.hint', { min: MIN_FILE_MIB, max: MAX_FILE_MIB })}
      inputmode="decimal"
      autocomplete="off"
      bind:value={draft.fileMibText}
      error={errorFor(errors, ids.fileMaxBytes)}
    />

    <Checkbox
      label={t('adminSecrets.settings.emailAllowed.label')}
      hint={t('adminSecrets.settings.emailAllowed.hint')}
      bind:checked={draft.emailAllowed}
    />
    <Checkbox
      label={t('adminSecrets.settings.emailRequiresPassphrase.label')}
      hint={t('adminSecrets.settings.emailRequiresPassphrase.hint')}
      disabled={!draft.emailAllowed}
      bind:checked={draft.emailRequiresPassphrase}
    />
  </FormSection>
{/if}

<style>
  .tt-secrets__group {
    margin: 0 0 var(--tt-space-4);
    padding: 0;
    border: 0;
  }

  .tt-secrets__inline {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-4);
  }
</style>
