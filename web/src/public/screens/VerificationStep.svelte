<script lang="ts">
  // Recipient verification (CLAUDE.md section 10, version 1.1): the link is personal, its
  // recipient proves the address by a 6-digit code before anything else is shown. Two phases:
  // "Send me a code" (the masked address is shown, never the full one), then the code entry (15
  // minutes, 2 wrong attempts). The cookie is set by the server; once the code is accepted the
  // parent reads the transfer again (the password form or the files follow).
  import { tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { languageValues } from '../../shared/api/schema';
  import { Alert, Button, TextField, announce } from '../../shared/components';
  import { formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import Countdown from '../deposit/Countdown.svelte';
  import {
    normalizeCode,
    verificationConfirmFailure,
    verificationStartFailure,
    type VerificationGone,
  } from './outcomes';

  interface Props {
    /** Link token of the download page. */
    token: string;
    /** Masked address of the recipient (PublicTransfer.recipientEmailMasked). */
    emailMasked: string | undefined;
    /** The access had been granted and expired: explain why the code is asked again. */
    expired?: boolean;
    /** Called once the code is accepted (or when this browser was already verified). */
    onverified: () => void | Promise<void>;
    /** Called when the transfer is no longer available. */
    ongone: (kind: VerificationGone) => void;
    /** What the code opens: the download (default) or a reply to the transfer. */
    purpose?: 'download' | 'reply';
    /** Reply purpose only: called when the service is under maintenance. */
    onmaintenance?: (() => void) | undefined;
    /** Reply purpose only: back to the download page. */
    oncancel?: (() => void) | undefined;
  }

  let {
    token,
    emailMasked,
    expired = false,
    onverified,
    ongone,
    purpose = 'download',
    onmaintenance,
    oncancel,
  }: Props = $props();

  let phase = $state<'start' | 'code'>('start');
  let masked = $state<string | undefined>(undefined);
  let expiresAt = $state<string | undefined>(undefined);
  let code = $state('');
  let codeError = $state<string | undefined>();
  let formError = $state<string | undefined>();
  let notice = $state<string | undefined>();
  let busy = $state(false);
  let retryAt = $state<number | undefined>(undefined);
  let remaining = $state(0);
  let codeInput: HTMLInputElement | undefined = $state();

  const shownEmail = $derived(masked ?? emailMasked ?? '');
  const until = $derived(
    expiresAt === undefined ? '' : formatDate(expiresAt, { hour: '2-digit', minute: '2-digit' }),
  );

  function language(): 'fr' | 'en' {
    const current = i18n.locale.current;
    return (languageValues as readonly string[]).includes(current) ? (current as 'fr' | 'en') : 'en';
  }

  /** Asks for a code; a 204 means this browser is already verified (read the transfer again). */
  async function send(resend: boolean): Promise<void> {
    if (busy || remaining > 0) {
      return;
    }
    busy = true;
    formError = undefined;
    codeError = undefined;
    notice = undefined;
    try {
      const res = await api.post('/downloads/{linkToken}/verification', {
        path: { linkToken: token },
        body: { purpose, language: language() },
      });
      if (res.status === 204 || !res.data) {
        await onverified();
        return;
      }
      masked = res.data.emailMasked;
      expiresAt = res.data.expiresAt;
      code = '';
      phase = 'code';
      if (resend) {
        notice = t('download.verify.resent');
      }
      await tick();
      codeInput?.focus();
    } catch (err) {
      const failure = verificationStartFailure(err);
      switch (failure.kind) {
        case 'rate-limited':
          retryAt = Date.now() + (failure.retryAfterSeconds ?? 60) * 1000;
          formError = t('download.verify.rateLimited');
          break;
        case 'mail-unavailable':
          formError = t('download.verify.mailUnavailable');
          break;
        case 'conflict':
          formError = t('download.verify.conflict');
          break;
        case 'maintenance':
          if (onmaintenance === undefined) {
            formError = t('download.reply.maintenance');
          } else {
            onmaintenance();
          }
          break;
        case 'not-found':
        case 'gone':
        case 'max-downloads':
          ongone(failure.kind);
          break;
        default:
          formError = t('common.error.text');
      }
    } finally {
      busy = false;
    }
  }

  async function confirm(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy || remaining > 0) {
      return;
    }
    const value = normalizeCode(code);
    formError = undefined;
    notice = undefined;
    if (!/^\d{6}$/.test(value)) {
      codeError = value === '' ? t('download.verify.required') : t('download.verify.format');
      codeInput?.focus();
      return;
    }
    codeError = undefined;
    busy = true;
    try {
      await api.post('/downloads/{linkToken}/verification/confirm', {
        path: { linkToken: token },
        body: { code: value },
      });
      announce(t('download.verify.done'));
      await onverified();
    } catch (err) {
      const failure = verificationConfirmFailure(err);
      switch (failure.kind) {
        case 'wrong':
          codeError =
            failure.attemptsRemaining === undefined
              ? t('download.verify.wrong')
              : `${t('download.verify.wrong')} ${t('common.attemptsRemaining', { count: failure.attemptsRemaining })}`;
          code = '';
          codeInput?.focus();
          break;
        case 'exhausted':
        case 'no-code':
          // A new code must be requested: back to the first phase, with the explanation.
          phase = 'start';
          code = '';
          formError = t(
            failure.kind === 'exhausted' ? 'download.verify.exhausted' : 'download.verify.noCode',
          );
          break;
        case 'rate-limited':
          retryAt = Date.now() + (failure.retryAfterSeconds ?? 60) * 1000;
          formError = t('download.verify.rateLimited');
          break;
        case 'not-found':
        case 'gone':
        case 'max-downloads':
          ongone(failure.kind);
          break;
        default:
          formError = t('common.error.text');
      }
    } finally {
      busy = false;
    }
  }
</script>

<h1 tabindex="-1">{purpose === 'reply' ? t('download.verify.replyTitle') : t('download.verify.title')}</h1>

{#if expired}
  <Alert severity="info">{t('download.verify.expired')}</Alert>
{/if}

{#if phase === 'start'}
  <p>{purpose === 'reply' ? t('download.verify.replyIntro') : t('download.verify.intro')}</p>
  {#if shownEmail !== ''}
    <p class="tt-break">{t('download.verify.address', { email: shownEmail })}</p>
  {/if}
  {#if purpose === 'download'}
    <p class="tt-text-muted tt-text-sm">{t('download.verify.personal')}</p>
  {/if}
  {#if formError}
    <Alert severity="error">{formError}</Alert>
  {/if}
  <Countdown until={retryAt} bind:remaining />
  <div class="tt-cluster">
    <Button loading={busy} disabled={remaining > 0} onclick={() => void send(false)}>
      {t('download.verify.send')}
    </Button>
    {#if oncancel}
      <Button variant="secondary" disabled={busy} onclick={oncancel}>{t('download.reply.page.back')}</Button>
    {/if}
  </div>
{:else}
  <p class="tt-break">{t('download.verify.sent', { email: shownEmail })}</p>
  {#if until !== ''}
    <p class="tt-text-muted tt-text-sm">{t('download.verify.expires', { time: until })}</p>
  {/if}
  {#if notice}
    <Alert severity="info">{notice}</Alert>
  {/if}
  {#if formError}
    <Alert severity="error">{formError}</Alert>
  {/if}
  <form class="tt-stack" novalidate onsubmit={confirm}>
    <TextField
      label={t('download.verify.label')}
      inputmode="numeric"
      autocomplete="one-time-code"
      pattern="[0-9]*"
      spellcheck={false}
      required
      hint={t('download.verify.hint')}
      error={codeError}
      bind:value={code}
      bind:element={codeInput}
    />
    <Countdown until={retryAt} bind:remaining />
    <div class="tt-cluster">
      <Button type="submit" loading={busy} disabled={remaining > 0}>{t('download.verify.submit')}</Button>
      <Button variant="secondary" disabled={busy || remaining > 0} onclick={() => void send(true)}>
        {t('download.verify.resend')}
      </Button>
    </div>
  </form>
{/if}
