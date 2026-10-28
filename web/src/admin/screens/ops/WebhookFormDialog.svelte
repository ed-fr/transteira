<script lang="ts">
  // Creation or edition of a webhook in a modal dialog, shared by the tenant and the instance
  // webhooks (scope decides the events offered):
  // - creation: name, kind (Teams, Slack, generic JSON), URL, events (checkboxes, at least one)
  //   and enabled; the parent sends POST and shows the secret of a generic webhook once;
  // - edition (JSON Merge Patch, only the changed fields): name, a new URL (empty keeps the
  //   current one, which the API never returns), events and enabled; the kind cannot change.
  // API errors land on their fields (url-not-allowed on the URL, /events/<i> on the events); the
  // limit of 20 webhooks (409) and the limit of 30 creations and URL changes per hour (429, with
  // the wait when known) are general messages. Closing with unsaved changes (Cancel,
  // Escape, close button) asks for a confirmation first. The form is rebuilt at each opening.
  import { untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Button, Checkbox, Dialog, RadioGroup, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import {
    errorFor,
    unsavedChangesGuard,
    type SubmitOutcome,
    type SummaryError,
  } from '../../components/form';
  import { isEmptyPatch } from '../../forms/patch';
  import type { AddGuard } from '../types';
  import {
    WEBHOOK_KINDS,
    WEBHOOK_NAME_MAX,
    WEBHOOK_URL_MAX,
    buildWebhookPatch,
    createBody,
    createFormTouched,
    editFormFrom,
    emptyWebhookForm,
    eventLabel,
    kindLabel,
    toggleEvent,
    validateWebhookForm,
    webhookErrorOutcome,
    webhookEvents,
    type Webhook,
    type WebhookCreate,
    type WebhookForm,
    type WebhookScope,
    type WebhookUpdate,
    type WebhookWithSecret,
  } from './webhooks';

  interface Props {
    /** Bound open state. */
    open?: boolean;
    /** Tenant webhooks or instance-wide webhooks. */
    scope: WebhookScope;
    /** The webhook to edit; undefined for a creation. */
    webhook?: Webhook | undefined;
    /** Sends the creation (POST); rejects with the API error. */
    create: (body: WebhookCreate) => Promise<WebhookWithSecret>;
    /** Sends the merge patch (PATCH); rejects with the API error. */
    update: (id: string, patch: WebhookUpdate) => Promise<WebhookWithSecret>;
    /** Called with the answer after a successful save (the dialog then closes). */
    onsaved: (webhook: WebhookWithSecret, created: boolean) => void;
    /** Called after the dialog closed (saved or not), once the focus is back on its opener. */
    onclose?: () => void;
    /** Registers a navigation guard (router.addGuard). */
    addGuard: AddGuard;
    /** Asks the user to confirm discarding changes (default window.confirm). */
    confirmDiscard?: (message: string) => boolean;
  }

  let {
    open = $bindable(false),
    scope,
    webhook,
    create,
    update,
    onsaved,
    onclose,
    addGuard,
    confirmDiscard,
  }: Props = $props();

  const uid = $props.id();
  const ids = {
    name: `${uid}-name`,
    url: `${uid}-url`,
    events: `${uid}-events`,
    enabled: `${uid}-enabled`,
  };

  let form = $state<WebhookForm>(untrack(() => (webhook ? editFormFrom(webhook) : emptyWebhookForm())));
  let errors = $state<SummaryError[]>([]);

  const creating = $derived(webhook === undefined);
  const events = $derived(webhookEvents(scope));
  const fields = $derived({
    name: { id: ids.name, label: t('opsWebhooks.form.name.label') },
    url: { id: ids.url, label: t('opsWebhooks.form.url.label') },
    // The first checkbox receives the focus of the error summary.
    events: { id: `${ids.events}-0`, label: t('opsWebhooks.form.events.label') },
    enabled: { id: ids.enabled, label: t('opsWebhooks.form.enabled.label') },
  });
  const dirty = $derived(
    open &&
      (webhook === undefined ? createFormTouched(form) : !isEmptyPatch(buildWebhookPatch(webhook, form))),
  );
  // A creation is never "no changes to save": submitting the untouched form runs the
  // validation (every required field in error) instead of announcing that nothing changed.
  const submitDirty = $derived(creating ? dirty || undefined : dirty);
  const kindOptions = $derived(
    WEBHOOK_KINDS.map((kind) => ({
      value: kind,
      label: kindLabel(kind, t),
      hint: t(`opsWebhooks.form.kind.hints.${kind}`),
    })),
  );
  const eventsError = $derived(errorFor(errors, fields.events.id));

  const ask = (message: string): boolean => (confirmDiscard ?? ((m: string) => window.confirm(m)))(message);
  /** True when the dialog may close: no unsaved change, or discarding them confirmed. */
  const mayClose = (): boolean =>
    unsavedChangesGuard(() => dirty, ask, t('opsWebhooks.form.discardConfirm'))('');

  function cancel(): void {
    if (mayClose()) {
      open = false;
    }
  }

  // Each opening starts again from the webhook as listed (or from an empty form).
  $effect.pre(() => {
    if (open) {
      untrack(() => {
        form = webhook ? editFormFrom(webhook) : emptyWebhookForm();
        errors = [];
      });
    }
  });

  async function save(): Promise<SubmitOutcome> {
    try {
      if (webhook === undefined) {
        const res = await create(createBody(form));
        open = false;
        onsaved(res, true);
        return { ok: true, message: t('opsWebhooks.form.created') };
      }
      const res = await update(webhook.id, buildWebhookPatch(webhook, form));
      open = false;
      onsaved(res, false);
      return { ok: true, message: t('opsWebhooks.form.saved') };
    } catch (err) {
      return webhookErrorOutcome(describeError(i18n, err), fields, t);
    }
  }
</script>

<Dialog
  bind:open
  title={webhook
    ? t('opsWebhooks.form.editTitle', { name: webhook.name })
    : t('opsWebhooks.form.createTitle')}
  beforeclose={mayClose}
  {onclose}
>
  {#if open}
    <FormSection
      as="fieldset"
      title={t('opsWebhooks.form.legend')}
      intro={creating ? t('opsWebhooks.form.createIntro') : t('opsWebhooks.form.editIntro')}
      dirty={submitDirty}
      {addGuard}
      validate={() => validateWebhookForm(form, fields, t, { scope, creating })}
      onsubmit={save}
      saveLabel={creating ? t('opsWebhooks.form.submit') : undefined}
      savingLabel={creating ? t('admin.common.creating') : undefined}
      bind:errors
    >
      <TextField
        id={ids.name}
        label={t('opsWebhooks.form.name.label')}
        hint={t('opsWebhooks.form.name.hint')}
        bind:value={form.name}
        required
        maxlength={WEBHOOK_NAME_MAX}
        autocomplete="off"
        error={errorFor(errors, ids.name)}
      />
      {#if webhook === undefined}
        <RadioGroup
          legend={t('opsWebhooks.form.kind.label')}
          options={kindOptions}
          required
          bind:value={form.kind}
        />
      {:else}
        <p>
          <span class="tt-text-bold">{t('opsWebhooks.form.kind.label')}</span>
          {kindLabel(webhook.kind, t)}
        </p>
      {/if}
      <TextField
        id={ids.url}
        type="url"
        label={creating ? t('opsWebhooks.form.url.label') : t('opsWebhooks.form.url.newLabel')}
        hint={creating
          ? t('opsWebhooks.form.url.hint', { max: WEBHOOK_URL_MAX })
          : t('opsWebhooks.form.url.editHint', { hint: webhook?.urlHint ?? '' })}
        bind:value={form.url}
        required={creating}
        maxlength={WEBHOOK_URL_MAX}
        autocomplete="off"
        spellcheck={false}
        autocapitalize="none"
        error={errorFor(errors, ids.url)}
      />
      <fieldset
        class="tt-webhook-events"
        aria-describedby={eventsError ? `${ids.events}-hint ${ids.events}-error` : `${ids.events}-hint`}
      >
        <legend class="tt-webhook-events__legend">
          {t('opsWebhooks.form.events.label')}
          <span class="tt-webhook-events__required">{t('components.field.required')}</span>
        </legend>
        <p class="tt-webhook-events__hint" id="{ids.events}-hint">
          {scope === 'system'
            ? t('opsWebhooks.form.events.hintSystem')
            : t('opsWebhooks.form.events.hintTenant')}
        </p>
        {#each events as event, index (event)}
          <Checkbox
            id="{ids.events}-{index}"
            label={eventLabel(event, t)}
            checked={form.events.includes(event)}
            onchange={(e: Event) => {
              form.events = toggleEvent(form.events, event, (e.currentTarget as HTMLInputElement).checked);
            }}
          />
        {/each}
        {#if eventsError}
          <p class="tt-webhook-events__error" id="{ids.events}-error">
            <span class="visually-hidden">{t('components.field.errorPrefix')}</span>
            {eventsError}
          </p>
        {/if}
      </fieldset>
      <Checkbox
        id={ids.enabled}
        label={t('opsWebhooks.form.enabled.label')}
        hint={t('opsWebhooks.form.enabled.hint')}
        bind:checked={form.enabled}
      />
      {#snippet actions()}
        <Button variant="secondary" onclick={cancel}>
          {t('admin.common.cancel')}
        </Button>
      {/snippet}
    </FormSection>
  {/if}
</Dialog>

<style>
  .tt-webhook-events {
    margin: 0 0 var(--tt-space-4);
    padding: 0;
    border: 0;
    min-width: 0;
  }

  .tt-webhook-events__legend {
    padding: 0;
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-webhook-events__required {
    margin-left: var(--tt-space-1);
    font-weight: normal;
    color: var(--tt-muted);
  }

  .tt-webhook-events__hint {
    margin: 0 0 var(--tt-space-2);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-webhook-events__error {
    margin: var(--tt-space-1) 0 0;
    color: var(--tt-danger);
    font-weight: var(--tt-font-weight-bold);
  }
</style>
