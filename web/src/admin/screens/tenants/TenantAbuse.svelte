<script lang="ts">
  // Abuse detection of a tenant (CLAUDE.md sections 10 and 15, version 1.1): GET/PUT
  // /admin/tenants/{id}/abuse-thresholds. Every member is sent on save; a nullable threshold is
  // disabled (null) when its box is unchecked. Sizes with a unit, volume factor 1.5 to 100, time
  // zone with suggestions, office hours (or none), blocking option, invitations per hour and
  // external quotas. Client-side validation mirrors the specification; the field errors of the
  // server (problem pointers) are shown next to the fields. An admin without the right to change
  // the tenant gets the 403 of the server on save.
  // The tenant sub-navigation is rendered by App.svelte.
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Checkbox, HelpIcon, Spinner, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import type { AdminScreenProps } from '../types';
  import {
    DEFAULTS,
    LIMITS,
    WEEKDAYS,
    isDirty,
    issuesToSummary,
    timeZoneSuggestions,
    toBody,
    toForm,
    toggleWeekday,
    validateForm,
    type AbuseFields,
    type AbuseForm,
    type AbuseThresholds,
  } from './abuse';
  import ThresholdBytes from './ThresholdBytes.svelte';
  import ThresholdCount from './ThresholdCount.svelte';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const id = (name: string): string => `${uid}-${name}`;
  const zones = timeZoneSuggestions();

  let loading = $state(true);
  let loadError = $state('');
  let saved = $state.raw<AbuseThresholds | undefined>(undefined);
  let form = $state<AbuseForm | undefined>(undefined);
  let errors = $state<SummaryError[]>([]);

  const tenantId = $derived(params['id'] ?? '');
  const dirty = $derived(saved !== undefined && form !== undefined && isDirty(saved, form));
  const label = (key: string): string => t(`adminAbuse.thresholds.${key}.label`);
  const fields: AbuseFields = $derived({
    maxDailyBytesPerSender: { id: id('maxDailyBytesPerSender'), label: label('maxDailyBytesPerSender') },
    maxDailyTransfersPerSender: {
      id: id('maxDailyTransfersPerSender'),
      label: label('maxDailyTransfersPerSender'),
    },
    maxRecipientsPerTransfer: {
      id: id('maxRecipientsPerTransfer'),
      label: label('maxRecipientsPerTransfer'),
    },
    blockOnExceed: { id: id('blockOnExceed'), label: label('blockOnExceed') },
    unusualVolumeFactor: { id: id('unusualVolumeFactor'), label: label('unusualVolumeFactor') },
    unusualMinHistoryDays: { id: id('unusualMinHistoryDays'), label: label('unusualMinHistoryDays') },
    largeExternalTransferBytes: {
      id: id('largeExternalTransferBytes'),
      label: label('largeExternalTransferBytes'),
    },
    timeZone: { id: id('timeZone'), label: label('timeZone') },
    officeHours: { id: id('officeStart'), label: label('officeHours') },
    maxInvitationsPerInviter: {
      id: id('maxInvitationsPerInviter'),
      label: label('maxInvitationsPerInviter'),
    },
    externalMaxDailyBytes: { id: id('externalMaxDailyBytes'), label: label('externalMaxDailyBytes') },
    externalMaxDailyDeposits: {
      id: id('externalMaxDailyDeposits'),
      label: label('externalMaxDailyDeposits'),
    },
  });

  function show(a: AbuseThresholds): void {
    saved = a;
    form = toForm(a);
  }

  async function load(tid: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/abuse-thresholds', {
        path: { tenantId: tid },
      });
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

  function validate(): SummaryError[] {
    return form === undefined ? [] : issuesToSummary(validateForm(form), fields, t);
  }

  async function save(): Promise<SubmitOutcome> {
    const body = form === undefined ? undefined : toBody(form);
    if (body === undefined) {
      return { ok: false, errors: validate() };
    }
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/abuse-thresholds', {
        path: { tenantId },
        body,
      });
      show(res.data);
      return { ok: true, message: t('adminAbuse.thresholds.saved') };
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
  <h1 tabindex="-1">{t('adminAbuse.thresholds.title')}</h1>
  <HelpIcon topic="tenant-abuse" title={t('adminAbuse.thresholds.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== '' || form === undefined}
  <Alert severity="error">{loadError}</Alert>
{:else}
  <FormSection
    title={t('adminAbuse.thresholds.form.title')}
    intro={t('adminAbuse.thresholds.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    {validate}
    onsubmit={save}
    bind:errors
  >
    <fieldset class="tt-abuse__group">
      <legend>{t('adminAbuse.thresholds.groups.sender')}</legend>
      <p class="tt-abuse__hint">{t('adminAbuse.thresholds.groups.senderHint')}</p>
      <ThresholdBytes
        id={fields.maxDailyBytesPerSender.id}
        label={fields.maxDailyBytesPerSender.label}
        hint={t('adminAbuse.thresholds.maxDailyBytesPerSender.hint')}
        bind:value={form.maxDailyBytesPerSender}
        error={errorFor(errors, fields.maxDailyBytesPerSender.id)}
      />
      <ThresholdCount
        id={fields.maxDailyTransfersPerSender.id}
        label={fields.maxDailyTransfersPerSender.label}
        hint={t('adminAbuse.thresholds.maxDailyTransfersPerSender.hint')}
        bind:value={form.maxDailyTransfersPerSender}
        error={errorFor(errors, fields.maxDailyTransfersPerSender.id)}
      />
      <ThresholdCount
        id={fields.maxRecipientsPerTransfer.id}
        label={fields.maxRecipientsPerTransfer.label}
        hint={t('adminAbuse.thresholds.maxRecipientsPerTransfer.hint', {
          min: LIMITS.maxRecipientsPerTransfer.min,
          max: LIMITS.maxRecipientsPerTransfer.max,
        })}
        bind:value={form.maxRecipientsPerTransfer}
        error={errorFor(errors, fields.maxRecipientsPerTransfer.id)}
      />
      <Checkbox
        id={fields.blockOnExceed.id}
        label={fields.blockOnExceed.label}
        hint={t('adminAbuse.thresholds.blockOnExceed.hint')}
        bind:checked={form.blockOnExceed}
      />
    </fieldset>

    <fieldset class="tt-abuse__group">
      <legend>{t('adminAbuse.thresholds.groups.unusual')}</legend>
      <p class="tt-abuse__hint">{t('adminAbuse.thresholds.groups.unusualHint')}</p>
      <ThresholdCount
        id={fields.unusualVolumeFactor.id}
        label={fields.unusualVolumeFactor.label}
        hint={t('adminAbuse.thresholds.unusualVolumeFactor.hint', {
          min: LIMITS.unusualVolumeFactor.min,
          max: LIMITS.unusualVolumeFactor.max,
        })}
        inputmode="decimal"
        bind:value={form.unusualVolumeFactor}
        error={errorFor(errors, fields.unusualVolumeFactor.id)}
      />
      <TextField
        id={fields.unusualMinHistoryDays.id}
        label={fields.unusualMinHistoryDays.label}
        hint={t('adminAbuse.thresholds.unusualMinHistoryDays.hint', {
          min: LIMITS.unusualMinHistoryDays.min,
          max: LIMITS.unusualMinHistoryDays.max,
        })}
        inputmode="numeric"
        autocomplete="off"
        required
        bind:value={form.unusualMinHistoryDays}
        error={errorFor(errors, fields.unusualMinHistoryDays.id)}
      />
      <ThresholdBytes
        id={fields.largeExternalTransferBytes.id}
        label={fields.largeExternalTransferBytes.label}
        hint={t('adminAbuse.thresholds.largeExternalTransferBytes.hint')}
        bind:value={form.largeExternalTransferBytes}
        error={errorFor(errors, fields.largeExternalTransferBytes.id)}
      />
    </fieldset>

    <fieldset class="tt-abuse__group">
      <legend>{t('adminAbuse.thresholds.groups.time')}</legend>
      <TextField
        id={fields.timeZone.id}
        label={fields.timeZone.label}
        hint={t('adminAbuse.thresholds.timeZone.hint')}
        list="{uid}-zones"
        autocomplete="off"
        spellcheck={false}
        required
        bind:value={form.timeZone}
        error={errorFor(errors, fields.timeZone.id)}
      />
      <datalist id="{uid}-zones">
        {#each zones as zone (zone)}
          <option value={zone}></option>
        {/each}
      </datalist>
      <Checkbox
        id={id('officeEnabled')}
        label={t('adminAbuse.thresholds.officeHours.enable')}
        hint={t('adminAbuse.thresholds.officeHours.hint')}
        bind:checked={form.officeHoursEnabled}
      />
      {#if form.officeHoursEnabled}
        <div class="tt-abuse__office">
          <TextField
            id={id('officeStart')}
            label={t('adminAbuse.thresholds.officeHours.start')}
            inputmode="numeric"
            placeholder={DEFAULTS.officeStart}
            autocomplete="off"
            required
            bind:value={form.officeStart}
            error={errorFor(errors, fields.officeHours.id)}
          />
          <TextField
            id={id('officeEnd')}
            label={t('adminAbuse.thresholds.officeHours.end')}
            hint={t('adminAbuse.thresholds.officeHours.endHint')}
            inputmode="numeric"
            placeholder={DEFAULTS.officeEnd}
            autocomplete="off"
            required
            bind:value={form.officeEnd}
          />
          <fieldset class="tt-abuse__days">
            <legend>{t('adminAbuse.thresholds.officeHours.weekdays')}</legend>
            {#each WEEKDAYS as day (day)}
              <Checkbox
                id={id(`day-${day}`)}
                label={t(`adminAbuse.thresholds.weekday.${day}`)}
                checked={form.officeWeekdays.includes(day)}
                onchange={(e) => {
                  if (form !== undefined) {
                    form.officeWeekdays = toggleWeekday(
                      form.officeWeekdays,
                      day,
                      (e.currentTarget as HTMLInputElement).checked,
                    );
                  }
                }}
              />
            {/each}
          </fieldset>
        </div>
      {/if}
    </fieldset>

    <fieldset class="tt-abuse__group">
      <legend>{t('adminAbuse.thresholds.groups.external')}</legend>
      <p class="tt-abuse__hint">{t('adminAbuse.thresholds.groups.externalHint')}</p>
      <TextField
        id={fields.maxInvitationsPerInviter.id}
        label={fields.maxInvitationsPerInviter.label}
        hint={t('adminAbuse.thresholds.maxInvitationsPerInviter.hint', {
          min: LIMITS.maxInvitationsPerInviter.min,
          max: LIMITS.maxInvitationsPerInviter.max,
        })}
        inputmode="numeric"
        autocomplete="off"
        required
        bind:value={form.maxInvitationsPerInviter}
        error={errorFor(errors, fields.maxInvitationsPerInviter.id)}
      />
      <ThresholdBytes
        id={fields.externalMaxDailyBytes.id}
        label={fields.externalMaxDailyBytes.label}
        hint={t('adminAbuse.thresholds.externalMaxDailyBytes.hint')}
        bind:value={form.externalMaxDailyBytes}
        error={errorFor(errors, fields.externalMaxDailyBytes.id)}
      />
      <ThresholdCount
        id={fields.externalMaxDailyDeposits.id}
        label={fields.externalMaxDailyDeposits.label}
        hint={t('adminAbuse.thresholds.externalMaxDailyDeposits.hint')}
        bind:value={form.externalMaxDailyDeposits}
        error={errorFor(errors, fields.externalMaxDailyDeposits.id)}
      />
    </fieldset>
  </FormSection>
{/if}

<style>
  .tt-abuse__group {
    margin: 0 0 var(--tt-space-6);
    padding: var(--tt-space-3) var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
  }

  .tt-abuse__group legend {
    padding: 0 var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-abuse__hint {
    margin: 0 0 var(--tt-space-3);
    color: var(--tt-muted);
  }

  .tt-abuse__office {
    margin-left: var(--tt-space-5);
  }

  .tt-abuse__days {
    margin: 0 0 var(--tt-space-3);
    padding: 0;
    border: 0;
  }
</style>
