<script lang="ts">
  // System settings (super admin): GET and PATCH /admin/system/settings (merge patch of the
  // changed fields only; logic in settings.ts).
  // - Disk alert threshold, edited as a percentage from 50 to 99 (sent as a ratio); a stored
  //   value that is not a whole percentage is shown exactly (e.g. 85.5).
  // - Optional alert address, not verified by the server: it must be typed twice when it
  //   changes; emptying it sends null (no alert mail, the alert stays visible in the overview
  //   and in the audit log).
  // The system sub-navigation is rendered by App.svelte.
  import { onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Spinner, TextField } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { EMAIL_MAX_LENGTH } from '../../../shared/validation/email';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { systemPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    ALERT_HYSTERESIS_POINTS,
    MAX_THRESHOLD_PERCENT,
    MIN_THRESHOLD_PERCENT,
    decimalSeparator,
    engineDisabled,
    engineLabel,
    emailChanged,
    emailRemoved,
    formFromSettings,
    isSettingsDirty,
    settingsFailure,
    settingsPatch,
    validateSettingsForm,
    type SettingsFieldRefs,
    type SettingsForm,
    type SystemSettings,
  } from './settings';

  let { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    diskAlertThreshold: `${uid}-threshold`,
    alertEmail: `${uid}-email`,
    emailConfirm: `${uid}-email-confirm`,
  };

  let settings = $state.raw<SystemSettings | undefined>(undefined);
  let form = $state<SettingsForm | undefined>(undefined);
  let loading = $state(true);
  let loadError = $state('');
  let errors = $state<SummaryError[]>([]);

  const separator = $derived(decimalSeparator(locale.current));
  // Compared parsed: switching the language (decimal separator) does not make the form dirty.
  const dirty = $derived(settings !== undefined && form !== undefined && isSettingsDirty(settings, form));
  const changing = $derived(settings !== undefined && form !== undefined && emailChanged(settings, form));
  const removing = $derived(settings !== undefined && form !== undefined && emailRemoved(settings, form));

  const refs = $derived<SettingsFieldRefs>({
    diskAlertThreshold: { id: ids.diskAlertThreshold, label: t('sysSettings.threshold.label') },
    alertEmail: { id: ids.alertEmail, label: t('sysSettings.email.label') },
    emailConfirm: { id: ids.emailConfirm, label: t('sysSettings.email.confirmLabel') },
  });

  function show(next: SystemSettings): void {
    settings = next;
    form = formFromSettings(next, separator);
  }

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/system/settings');
      show(res.data);
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
  });

  function validate(): SummaryError[] {
    return settings === undefined || form === undefined ? [] : validateSettingsForm(settings, form, refs, t);
  }

  async function save(): Promise<SubmitOutcome> {
    if (settings === undefined || form === undefined) {
      return { ok: false, message: t('errors.unknown') };
    }
    const patch = settingsPatch(settings, form);
    if (Object.keys(patch).length === 0) {
      return { ok: true, message: t('admin.common.noChanges') };
    }
    try {
      const res = await adminApi.patch('/admin/system/settings', { body: patch });
      show(res.data);
      return { ok: true, message: t('sysSettings.saved') };
    } catch (err) {
      return settingsFailure(describeError(i18n, err), refs, t);
    }
  }
</script>

<h1 tabindex="-1">{t('adminSystem.settings.title')}</h1>
<p>{t('adminSystem.settings.intro')}</p>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else if settings !== undefined && form !== undefined}
  <FormSection
    title={t('sysSettings.form.title')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    {validate}
    onsubmit={save}
    bind:errors
    successMessage={t('sysSettings.saved')}
  >
    <TextField
      id={ids.diskAlertThreshold}
      label={t('sysSettings.threshold.label')}
      hint={t('sysSettings.threshold.hint', {
        min: MIN_THRESHOLD_PERCENT,
        max: MAX_THRESHOLD_PERCENT,
        points: ALERT_HYSTERESIS_POINTS,
      })}
      inputmode="decimal"
      required
      maxlength={6}
      autocomplete="off"
      error={errorFor(errors, ids.diskAlertThreshold)}
      bind:value={form.threshold}
    />

    <TextField
      id={ids.alertEmail}
      type="email"
      label={t('sysSettings.email.label')}
      hint={t('sysSettings.email.hint')}
      maxlength={EMAIL_MAX_LENGTH}
      autocomplete="off"
      spellcheck={false}
      autocapitalize="none"
      error={errorFor(errors, ids.alertEmail)}
      bind:value={form.email}
    />
    <Alert severity="warning" live={false}>{t('sysSettings.email.unverified')}</Alert>

    {#if changing}
      <TextField
        id={ids.emailConfirm}
        type="email"
        label={t('sysSettings.email.confirmLabel')}
        hint={t('sysSettings.email.confirmHint')}
        required
        maxlength={EMAIL_MAX_LENGTH}
        autocomplete="off"
        spellcheck={false}
        autocapitalize="none"
        error={errorFor(errors, ids.emailConfirm)}
        bind:value={form.emailConfirm}
      />
    {/if}
    {#if removing}
      <Alert severity="info" live={false}>{t('sysSettings.email.removing')}</Alert>
    {/if}
  </FormSection>

  {#if settings.antivirusEngine !== undefined}
    <section aria-labelledby="{uid}-antivirus" data-testid="antivirus-engine">
      <h2 id="{uid}-antivirus">{t('sysSettings.antivirus.title')}</h2>
      <dl class="tt-dl">
        <dt>{t('sysSettings.antivirus.engineLabel')}</dt>
        <dd>
          <StatusBadge
            variant={engineDisabled(settings.antivirusEngine) ? 'warning' : 'ok'}
            label={engineLabel(settings.antivirusEngine, t)}
          />
        </dd>
      </dl>
      <p class="tt-text-muted">{t('sysSettings.antivirus.hint')}</p>
      {#if engineDisabled(settings.antivirusEngine)}
        <Alert severity="warning" live={false}>{t('sysSettings.antivirus.disabledWarning')}</Alert>
      {/if}
    </section>
  {/if}

  <section aria-labelledby="{uid}-smtp">
    <h2 id="{uid}-smtp">{t('sysSettings.smtp.title')}</h2>
    <p>{t('sysSettings.smtp.text', { host: 'TT_SYSTEM_SMTP_HOST', from: 'TT_SYSTEM_SMTP_FROM' })}</p>
    <p><a href={nav.href(systemPath('overview'))} use:nav.link>{t('sysSettings.overviewLink')}</a></p>
  </section>
{/if}
