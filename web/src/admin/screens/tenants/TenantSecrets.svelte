<script lang="ts">
  // One-time secrets settings of a tenant (version 2.1, CLAUDE.md section 22.1): GET/PUT
  // /admin/tenants/{id}/secret-settings. The module switch, the offered durations (checkboxes
  // from the catalogue) and the preselected one, the optional small file (size 1 to 25 MiB) and
  // the e-mail delivery with its passphrase rule. The PUT replaces every setting. Client-side
  // validation mirrors the specification, the server field errors are mapped to the fields.
  // Since 2.3 the screen also holds the express secrets (CLAUDE.md section 22.2): the anonymous
  // mode switch (off by default), its three limits, a reminder to complete the legal texts while
  // it is on (H24, T-404) and the emergency purge of the live anonymous express secrets
  // (POST …/express-secrets/purge, after a confirmation). An auditor has no access (403
  // read-only-role, shown as a load error); the fields and the purge are also disabled for the
  // read-only role in case the screen is shown.
  // The tenant navigation is in the sidebar (SidebarTenantBlock of AdminShell).
  import { describeError } from '../../../shared/api/problem';
  import {
    Alert,
    Button,
    Checkbox,
    HelpIcon,
    Spinner,
    TextField,
    announce,
  } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import Card from '../../components/Card.svelte';
  import PageHeader from '../../components/PageHeader.svelte';
  import SelectField from '../../components/SelectField.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { isAuditor, tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    EXPRESS_LIMITS,
    MAX_FILE_MIB,
    MIN_FILE_MIB,
    SECRET_DURATIONS,
    purgeResultText,
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
    expressPerIp: `${uid}-express-ip`,
    expressPerToken: `${uid}-express-token`,
    expressPending: `${uid}-express-pending`,
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
    expressEnabled: false,
    expressPerHourPerIpText: String(EXPRESS_LIMITS.perHourPerIp.def),
    expressPerHourPerTokenText: String(EXPRESS_LIMITS.perHourPerToken.def),
    expressMaxPendingText: String(EXPRESS_LIMITS.maxPending.def),
  });
  let errors = $state<SummaryError[]>([]);
  let purgeOpen = $state(false);
  let purgeDone = $state('');

  const readOnly = $derived(isAuditor(adminSession.me?.role));

  const tenantId = $derived(params['id'] ?? '');
  const fields = $derived({
    durations: { id: ids.durations, label: t('adminSecrets.settings.durations.label') },
    defaultDuration: { id: ids.defaultDuration, label: t('adminSecrets.settings.defaultDuration.label') },
    fileMaxBytes: { id: ids.fileMaxBytes, label: t('adminSecrets.settings.fileMaxBytes.label') },
    expressPerHourPerIp: { id: ids.expressPerIp, label: t('adminSecrets.express.perIp.label') },
    expressPerHourPerToken: { id: ids.expressPerToken, label: t('adminSecrets.express.perToken.label') },
    expressMaxPending: { id: ids.expressPending, label: t('adminSecrets.express.maxPending.label') },
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

  async function purge(): Promise<string | void> {
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/express-secrets/purge', {
        path: { tenantId },
      });
      purgeDone = purgeResultText(res.data.deleted, t);
      announce(purgeDone);
    } catch (err) {
      return describeError(i18n, err).message;
    }
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

<PageHeader title={t('adminTenants.secrets.title')}>
  {#snippet help()}
    <HelpIcon topic="tenant-secrets" title={t('adminTenants.secrets.title')} {nav} />
  {/snippet}
</PageHeader>

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

    <fieldset class="tt-secrets__group" id="{uid}-express">
      <legend>{t('adminSecrets.express.legend')}</legend>
      <p class="tt-text-sm tt-text-muted">{t('adminSecrets.express.intro')}</p>
      <Checkbox
        label={t('adminSecrets.express.enabled.label')}
        hint={t('adminSecrets.express.enabled.hint')}
        disabled={readOnly}
        bind:checked={draft.expressEnabled}
      />
      {#if draft.expressEnabled}
        <div class="tt-secrets__reminder" id="{uid}-express-reminder">
          <Alert severity="info">
            <p>{t('adminSecrets.express.reminder.text')}</p>
            <p>
              <a class="tt-link-target" href={nav.href(tenantPath(tenantId, 'legal'))} use:nav.link>
                {t('adminSecrets.express.reminder.link')}
              </a>
            </p>
          </Alert>
        </div>
      {/if}
      <TextField
        id={ids.expressPerIp}
        label={t('adminSecrets.express.perIp.label')}
        hint={t('adminSecrets.express.perIp.hint', EXPRESS_LIMITS.perHourPerIp)}
        inputmode="numeric"
        autocomplete="off"
        disabled={readOnly}
        bind:value={draft.expressPerHourPerIpText}
        error={errorFor(errors, ids.expressPerIp)}
      />
      <TextField
        id={ids.expressPerToken}
        label={t('adminSecrets.express.perToken.label')}
        hint={t('adminSecrets.express.perToken.hint', EXPRESS_LIMITS.perHourPerToken)}
        inputmode="numeric"
        autocomplete="off"
        disabled={readOnly}
        bind:value={draft.expressPerHourPerTokenText}
        error={errorFor(errors, ids.expressPerToken)}
      />
      <TextField
        id={ids.expressPending}
        label={t('adminSecrets.express.maxPending.label')}
        hint={t('adminSecrets.express.maxPending.hint', EXPRESS_LIMITS.maxPending)}
        inputmode="numeric"
        autocomplete="off"
        disabled={readOnly}
        bind:value={draft.expressMaxPendingText}
        error={errorFor(errors, ids.expressPending)}
      />
    </fieldset>
  </FormSection>

  <Card
    title={t('adminSecrets.express.purge.title')}
    headingId="{uid}-purge-title"
    description={t('adminSecrets.express.purge.intro')}
  >
    <p>
      <Button variant="danger" disabled={readOnly} onclick={() => (purgeOpen = true)}>
        {t('adminSecrets.express.purge.button')}
      </Button>
    </p>
    {#if purgeDone !== ''}
      <Alert severity="success" live={false}>{purgeDone}</Alert>
    {/if}
  </Card>

  <ConfirmDialog
    bind:open={purgeOpen}
    title={t('adminSecrets.express.purge.confirmTitle')}
    text={t('adminSecrets.express.purge.confirmText')}
    confirmLabel={t('adminSecrets.express.purge.confirm')}
    busyLabel={t('adminSecrets.express.purge.busy')}
    danger
    onconfirm={purge}
  />
{/if}

<style>
  .tt-secrets__group {
    margin: 0 0 var(--tt-space-4);
    padding: 0;
    border: 0;
  }

  .tt-secrets__reminder {
    margin: 0 0 var(--tt-space-4);
  }

  .tt-secrets__inline {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-4);
  }
</style>
