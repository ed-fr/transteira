<script lang="ts">
  // Invitation of an external person, /invite (CLAUDE.md section 9). Reserved to internal
  // depositors: GET /deposit-sessions/current must give a session with canInvite; otherwise the
  // page explains how to get one. POST /invitations (20 per hour per inviter: 429; 403
  // deposit-not-allowed, deliberately generic, gives a neutral message in the form).
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../../shared/api/api';
  import type { components } from '../../shared/api/schema';
  import { describeError } from '../../shared/api/problem';
  import {
    Alert,
    Button,
    RadioGroup,
    Spinner,
    TextArea,
    TextField,
    languageName,
  } from '../../shared/components';
  import { i18n, locale, t } from '../../shared/i18n/i18n.svelte';
  import { Countdown } from './countdown.svelte';
  import ErrorPage from './ErrorPage.svelte';
  import Maintenance from './Maintenance.svelte';
  import { INVITATION_MESSAGE_MAX, inviteFailure, isNoSession, looksLikeEmail } from './outcomes';
  import SessionExpired from './SessionExpired.svelte';
  import type { ScreenProps } from './types';

  type DepositSession = components['schemas']['DepositSession'];
  type Language = components['schemas']['Language'];
  type State =
    | { kind: 'loading' }
    | { kind: 'no-session' }
    | { kind: 'not-allowed' }
    | { kind: 'form'; session: DepositSession }
    | { kind: 'sent'; email: string; session: DepositSession }
    | { kind: 'expired' }
    | { kind: 'error' };

  let { tenant, nav }: ScreenProps = $props();
  let view = $state<State>({ kind: 'loading' });
  let email = $state('');
  let message = $state('');
  let language = $state<Language | undefined>();
  let errors = $state<{ email?: string; message?: string; language?: string }>({});
  let formError = $state<string | undefined>();
  let sending = $state(false);
  let retrying = $state(false);
  let emailInput: HTMLInputElement | undefined = $state();
  const limit = new Countdown({ ondone: () => (formError = undefined) });
  onDestroy(() => limit.stop());

  const defaultLanguage = $derived<Language>(
    tenant.availableLanguages.find((l) => l === locale.current) ?? tenant.language,
  );
  const languageOptions = $derived(
    tenant.availableLanguages.map((code) => ({ value: code, label: languageName(code) })),
  );

  async function load(): Promise<void> {
    try {
      const { data } = await api.get('/deposit-sessions/current');
      view = data.canInvite ? { kind: 'form', session: data } : { kind: 'not-allowed' };
    } catch (err) {
      view = isNoSession(err) ? { kind: 'no-session' } : { kind: 'error' };
    }
  }

  onMount(() => {
    void load();
  });

  async function retry(): Promise<void> {
    retrying = true;
    await load();
    retrying = false;
  }

  function resetForm(): void {
    email = '';
    message = '';
    errors = {};
    formError = undefined;
  }

  async function submit(event: SubmitEvent, session: DepositSession): Promise<void> {
    event.preventDefault();
    if (sending || limit.active) {
      return;
    }
    errors = {};
    formError = undefined;
    const address = email.trim();
    if (!looksLikeEmail(address)) {
      errors = { email: t('fieldErrors.invalid-email') };
      emailInput?.focus();
      return;
    }
    sending = true;
    try {
      const chosen = language ?? defaultLanguage;
      const trimmed = message.trim();
      await api.post('/invitations', {
        body: { email: address, language: chosen, ...(trimmed === '' ? {} : { message: trimmed }) },
      });
      resetForm();
      view = { kind: 'sent', email: address, session };
    } catch (err) {
      const failure = inviteFailure(err);
      switch (failure.kind) {
        case 'invalid': {
          const fields = describeError(i18n, err).fields;
          errors = {
            email: fields['email']?.message,
            message: fields['message']?.message,
            language: fields['language']?.message,
          };
          formError = t('errors.validation-failed');
          break;
        }
        case 'session':
          view = { kind: 'expired' };
          break;
        case 'not-allowed':
          view = { kind: 'not-allowed' };
          break;
        case 'refused':
          // Generic on purpose (blocklist or network rule): keep the form to fix the address.
          formError = t('invitation.invite.refused');
          emailInput?.focus();
          break;
        case 'rate-limited':
          formError = t('invitation.invite.rateLimited');
          limit.start(failure.retryAfterSeconds ?? 60);
          break;
        case 'maintenance':
          formError = t('errors.maintenance');
          break;
        default:
          formError = t('common.error.text');
      }
    } finally {
      sending = false;
    }
  }
</script>

{#if tenant.maintenance}
  <Maintenance message={tenant.maintenanceMessage} language={tenant.maintenanceMessageLanguage} />
{:else if view.kind === 'loading'}
  <h1 tabindex="-1">{t('invitation.invite.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'no-session'}
  <SessionExpired
    {nav}
    title={t('invitation.invite.noSession.title')}
    text={t('invitation.invite.noSession.text')}
  />
{:else if view.kind === 'expired'}
  <SessionExpired {nav} />
{:else if view.kind === 'not-allowed'}
  <h1 tabindex="-1">{t('invitation.invite.notAllowed.title')}</h1>
  <p>{t('invitation.invite.notAllowed.text')}</p>
  <p><a href={nav.href('/')} use:nav.link>{t('common.backHome')}</a></p>
{:else if view.kind === 'error'}
  <ErrorPage onretry={() => void retry()} {retrying} />
{:else if view.kind === 'sent'}
  {@const session = view.session}
  <h1 tabindex="-1">{t('invitation.invite.sent.title')}</h1>
  <Alert severity="success">{t('invitation.invite.sent.text', { email: view.email })}</Alert>
  <div class="tt-cluster tt-mt-4">
    <Button onclick={() => (view = { kind: 'form', session })}>{t('invitation.invite.sent.another')}</Button>
    <a href={nav.href('/')} use:nav.link>{t('invitation.invite.backToDeposit')}</a>
  </div>
{:else}
  {@const session = view.session}
  <h1 tabindex="-1">{t('invitation.invite.title')}</h1>
  <p>{t('invitation.invite.intro', { inviter: session.email })}</p>
  <form class="tt-stack" onsubmit={(event) => void submit(event, session)} novalidate>
    {#if formError}
      <Alert severity="error">
        {formError}
        {#if limit.active}
          {t('common.retryAfter', { count: limit.remaining })}
        {/if}
      </Alert>
    {/if}
    <TextField
      label={t('invitation.invite.email')}
      hint={t('invitation.invite.emailHint')}
      type="email"
      autocomplete="email"
      required
      bind:value={email}
      bind:element={emailInput}
      error={errors.email}
    />
    <TextArea
      label={t('invitation.invite.message')}
      hint={t('invitation.invite.messageHint')}
      maxlength={INVITATION_MESSAGE_MAX}
      bind:value={message}
      error={errors.message}
    />
    {#if languageOptions.length > 1}
      <RadioGroup
        legend={t('invitation.invite.language')}
        hint={t('invitation.invite.languageHint')}
        options={languageOptions}
        value={language ?? defaultLanguage}
        onchange={(value) => (language = value)}
        error={errors.language}
        inline
      />
    {/if}
    <div class="tt-cluster">
      <Button type="submit" loading={sending} disabled={limit.active}>{t('invitation.invite.submit')}</Button>
      <a href={nav.href('/')} use:nav.link>{t('invitation.invite.backToDeposit')}</a>
    </div>
  </form>
{/if}
