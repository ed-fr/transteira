<script lang="ts">
  // Maintenance mode (super admin): GET and PUT /admin/system/maintenance (logic in
  // maintenance.ts).
  // - State: on or off (StatusBadge), source, start date; while TT_MAINTENANCE=true forces the
  //   mode, an explanation and the stored choice of the super admin.
  // - Form: the mode and one plain text message per language (fr, en), with a preview shown
  //   as text (white-space: pre-line), never as HTML (threat T-170). A PUT replaces every
  //   stored message: the fields are prefilled with the saved ones, and emptying both clears
  //   them. Changing the mode asks for confirmation (new deposits blocked or reopened on every
  //   tenant). While forced, the mode cannot be turned off here and every save records it as
  //   on (the server answers 409 otherwise); a 409 reloads the state.
  // - The message fields have no maxlength: a counter shows the length in code points (the unit
  //   of the server rule) and the check on submit reports a message that is too long.
  // - Cancelling the confirmation saves nothing: no success message, a polite announcement.
  // - After a save, the maintenance banner of the administration gets the state of the answer
  //   (adminMaintenance.set, which also drops older reads still in flight).
  // The system sub-navigation is rendered by App.svelte.
  import { onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Checkbox, Spinner, TextArea, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { adminMaintenance } from '../../maintenance.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    MAX_MESSAGE_LENGTH,
    MESSAGE_LANGUAGES,
    buildMaintenanceUpdate,
    confirmationFor,
    confirmationKeys,
    formFromMaintenance,
    isMaintenanceDirty,
    maintenanceFailure,
    maintenanceView,
    messageLength,
    normalizeMessage,
    savedKey,
    validateMaintenanceForm,
    type Maintenance,
    type MaintenanceConfirmation,
    type MaintenanceFieldRefs,
    type MaintenanceForm,
  } from './maintenance';

  let { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    enabled: `${uid}-enabled`,
    fr: `${uid}-message-fr`,
    en: `${uid}-message-en`,
  };

  let current = $state.raw<Maintenance | undefined>(undefined);
  let form = $state<MaintenanceForm | undefined>(undefined);
  let loading = $state(true);
  let loadError = $state('');
  let errors = $state<SummaryError[]>([]);

  // Confirmation dialog: save() waits for the answer.
  let confirmOpen = $state(false);
  let confirmKind = $state<MaintenanceConfirmation>('enable');
  let answer: ((confirmed: boolean) => void) | undefined;

  const view = $derived(current === undefined ? undefined : maintenanceView(current));
  const dirty = $derived(current !== undefined && form !== undefined && isMaintenanceDirty(current, form));
  const keys = $derived(confirmationKeys(confirmKind));

  const refs = $derived<MaintenanceFieldRefs>({
    enabled: { id: ids.enabled, label: t('sysMaintenance.form.enabled.label') },
    fr: { id: ids.fr, label: t('sysMaintenance.form.message.fr') },
    en: { id: ids.en, label: t('sysMaintenance.form.message.en') },
  });

  const dateTime = (d: string): string => formatDate(d, { dateStyle: 'medium', timeStyle: 'short' });

  function show(next: Maintenance): void {
    current = next;
    form = formFromMaintenance(next);
  }

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/system/maintenance');
      show(res.data);
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  // Reloads the state after a 409 without leaving the form (which shows the failure); a failed
  // read keeps the state on screen.
  async function reloadQuietly(): Promise<void> {
    try {
      const res = await adminApi.get('/admin/system/maintenance');
      show(res.data);
      adminMaintenance.set(res.data);
    } catch {
      // The failure of the save is already reported; the next visit reloads the state.
    }
  }

  onMount(() => {
    void load();
  });

  function validate(): SummaryError[] {
    return form === undefined ? [] : validateMaintenanceForm(form, refs, t);
  }

  function ask(kind: MaintenanceConfirmation): Promise<boolean> {
    confirmKind = kind;
    confirmOpen = true;
    return new Promise((resolve) => {
      answer = resolve;
    });
  }

  function settle(confirmed: boolean): void {
    answer?.(confirmed);
    answer = undefined;
  }

  async function save(): Promise<SubmitOutcome> {
    if (current === undefined || form === undefined || view === undefined) {
      return { ok: false, message: t('errors.unknown') };
    }
    const before = current;
    const kind = confirmationFor(before, form);
    if (kind !== undefined && !(await ask(kind))) {
      // Not a success: nothing is shown on the form, the outcome is only announced.
      announce(t('sysMaintenance.notSaved'), 'polite');
      return { ok: false };
    }
    try {
      const res = await adminApi.put('/admin/system/maintenance', {
        body: buildMaintenanceUpdate(form, view.forced),
      });
      show(res.data);
      adminMaintenance.set(res.data);
      return { ok: true, message: t(savedKey(before, res.data)) };
    } catch (err) {
      const failure = describeError(i18n, err);
      if (failure.status === 409) {
        // The environment forces the mode (restarted with TT_MAINTENANCE=true): show it.
        await reloadQuietly();
      }
      return maintenanceFailure(failure, refs, t);
    }
  }
</script>

<h1 tabindex="-1">{t('adminSystem.maintenance.title')}</h1>
<p>{t('adminSystem.maintenance.intro')}</p>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else if current !== undefined && form !== undefined && view !== undefined}
  <section aria-labelledby="{uid}-state">
    <h2 id="{uid}-state">{t('sysMaintenance.state.title')}</h2>
    <dl class="tt-dl">
      <dt>{t('sysMaintenance.state.label')}</dt>
      <dd><StatusBadge variant={view.variant} label={t(view.stateKey)} /></dd>
      <dt>{t('sysMaintenance.source.label')}</dt>
      <dd>{t(view.sourceKey)}</dd>
      {#if view.since !== undefined}
        <dt>{t('sysMaintenance.state.since')}</dt>
        <dd><time datetime={view.since}>{dateTime(view.since)}</time></dd>
      {/if}
      {#if view.storedKey !== undefined}
        <dt>{t('sysMaintenance.stored.label')}</dt>
        <dd>{t(view.storedKey)}</dd>
      {/if}
    </dl>
    {#if view.forced}
      <Alert severity="info" live={false} title={t('sysMaintenance.forced.title')}>
        <p>{t('sysMaintenance.forced.text')}</p>
        <p>{t('sysMaintenance.forced.save')}</p>
      </Alert>
    {/if}
  </section>

  <FormSection
    title={t('sysMaintenance.form.title')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    {validate}
    onsubmit={save}
    bind:errors
  >
    <Checkbox
      id={ids.enabled}
      label={t('sysMaintenance.form.enabled.label')}
      hint={view.forced ? t('sysMaintenance.form.enabled.forcedHint') : t('sysMaintenance.form.enabled.hint')}
      disabled={view.forced}
      error={errorFor(errors, ids.enabled)}
      bind:checked={form.enabled}
    />

    <Alert severity="warning" live={false}>{t('sysMaintenance.form.message.warning')}</Alert>

    {#each MESSAGE_LANGUAGES as lang (lang)}
      <TextArea
        id={ids[lang]}
        {lang}
        label={refs[lang].label}
        hint={t('sysMaintenance.form.message.hint', { max: MAX_MESSAGE_LENGTH })}
        counterMax={MAX_MESSAGE_LENGTH}
        countLength={messageLength}
        rows={4}
        error={errorFor(errors, ids[lang])}
        bind:value={form.messages[lang]}
      />
    {/each}

    <section class="sys-maint__previews" aria-labelledby="{uid}-preview">
      <h3 id="{uid}-preview">{t('sysMaintenance.preview.title')}</h3>
      <p class="tt-text-muted">{t('sysMaintenance.preview.intro')}</p>
      {#each MESSAGE_LANGUAGES as lang (lang)}
        {@const text = normalizeMessage(form.messages[lang])}
        <h4>{refs[lang].label}</h4>
        {#if text === ''}
          <p class="tt-text-muted">{t('sysMaintenance.preview.empty')}</p>
        {:else}
          <p class="sys-maint__preview" {lang}>{text}</p>
        {/if}
      {/each}
    </section>
  </FormSection>

  <ConfirmDialog
    bind:open={confirmOpen}
    title={t(keys.title)}
    text={t(keys.text)}
    confirmLabel={t(keys.action)}
    danger={confirmKind !== 'disable'}
    onconfirm={() => settle(true)}
    onclose={() => settle(false)}
  />
{/if}

<style>
  .sys-maint__previews {
    margin-top: var(--tt-space-4);
  }

  .sys-maint__previews h4 {
    margin: var(--tt-space-3) 0 var(--tt-space-1);
    font-size: var(--tt-font-size-base);
  }

  .sys-maint__preview {
    margin: 0;
    padding: var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    white-space: pre-line;
    overflow-wrap: anywhere;
  }
</style>
