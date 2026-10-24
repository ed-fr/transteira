<script lang="ts">
  // Second factor of the sign-in (CLAUDE.md section 6.5): the 6-digit TOTP code, or one of the
  // recovery codes. Shows the attempts left after a wrong code and, when the server locks the
  // second factor (429), a countdown that disables the submit button. The pre-auth session
  // expires after 5 minutes, which the screen says.
  //
  // The focus goes to the code field when the step appears (the only automatic focus of the
  // authentication screens: the admin has just submitted the password). The typed codes are
  // cleared when the component goes away.
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, Button, TextField, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { createFormState } from '../auth/formState.svelte';
  import type { TotpCode } from '../auth/session.svelte';
  import {
    normalizeRecoveryCode,
    normalizeTotpCode,
    recoveryCodeError,
    renderMessage,
    totpCodeError,
    totpFailure,
  } from '../auth/views';

  interface Props {
    /** Sends the code; a rejection is shown by the component. */
    onverify: (body: TotpCode) => Promise<void>;
    /** Abandons the sign-in. */
    oncancel: () => void;
  }

  let { onverify, oncancel }: Props = $props();

  const uid = $props.id();
  const codeId = `${uid}-code`;
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });
  let mode = $state<'totp' | 'recovery'>('totp');
  let code = $state('');
  let recoveryCode = $state('');

  const fieldError = $derived.by(() => {
    const message = renderMessage(form.fields['code'], t);
    if (message === undefined || form.attemptsRemaining === undefined) {
      return message;
    }
    return `${message} ${t('adminAuth.totp.attemptsRemaining', { count: form.attemptsRemaining })}`;
  });
  const general = $derived(renderMessage(form.general, t));

  function focusCode(): void {
    document.getElementById(codeId)?.focus();
  }

  async function switchMode(): Promise<void> {
    mode = mode === 'totp' ? 'recovery' : 'totp';
    code = '';
    recoveryCode = '';
    form.clear();
    await tick();
    focusCode();
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (form.blocked) {
      return;
    }
    const error = mode === 'totp' ? totpCodeError(code) : recoveryCodeError(recoveryCode);
    if (!form.check({ code: error })) {
      await tick();
      focusCode();
      return;
    }
    const body: TotpCode =
      mode === 'totp'
        ? { code: normalizeTotpCode(code) }
        : { recoveryCode: normalizeRecoveryCode(recoveryCode) };
    form.busy = true;
    try {
      await onverify(body);
    } catch (err) {
      form.fail(totpFailure(describeError(i18n, err), 'login'));
      code = '';
      recoveryCode = '';
      await tick();
      focusCode();
    } finally {
      form.busy = false;
    }
  }

  onMount(focusCode);

  onDestroy(() => {
    code = '';
    recoveryCode = '';
    form.dispose();
  });
</script>

<h1 tabindex="-1">{t('adminAuth.totp.title')}</h1>
<p>{mode === 'totp' ? t('adminAuth.totp.intro') : t('adminAuth.totp.recoveryIntro')}</p>
<p class="tt-text-muted tt-text-sm">{t('adminAuth.stepTimeout')}</p>

{#if general !== undefined}
  <Alert severity="error" live={!form.locked}>{general}</Alert>
{/if}

<form class="tt-stack" novalidate onsubmit={submit}>
  {#if mode === 'totp'}
    <TextField
      id={codeId}
      label={t('adminAuth.totp.code.label')}
      hint={t('adminAuth.totp.code.hint')}
      inputmode="numeric"
      autocomplete="one-time-code"
      pattern="[0-9]*"
      maxlength={6}
      spellcheck={false}
      required
      error={fieldError}
      bind:value={code}
    />
  {:else}
    <TextField
      id={codeId}
      label={t('adminAuth.totp.recoveryCode.label')}
      hint={t('adminAuth.totp.recoveryCode.hint')}
      autocomplete="off"
      autocapitalize="off"
      spellcheck={false}
      maxlength={64}
      required
      error={fieldError}
      bind:value={recoveryCode}
    />
  {/if}
  <div class="tt-cluster">
    <Button
      type="submit"
      loading={form.busy}
      loadingLabel={t('adminAuth.totp.submitting')}
      disabled={form.remaining > 0}
    >
      {t('adminAuth.totp.submit')}
    </Button>
    <Button variant="link" disabled={form.busy} onclick={() => void switchMode()}>
      {mode === 'totp' ? t('adminAuth.totp.useRecovery') : t('adminAuth.totp.useTotp')}
    </Button>
  </div>
</form>
<p>
  <Button variant="secondary" disabled={form.busy} onclick={oncancel}>{t('adminAuth.totp.cancel')}</Button>
</p>
