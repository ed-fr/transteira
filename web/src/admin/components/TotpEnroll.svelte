<script lang="ts">
  // TOTP enrollment (CLAUDE.md section 6.5, threat model T-162): QR code (data: URL, shown only
  // when its base64 is a valid PNG), the setup key grouped by 4 with a copy button, account and
  // issuer read from the otpauth URI and shown as plain text (never a link), then the 6-digit
  // confirmation code. A confirmation refused because the pending secret expired (409
  // state-conflict) offers to start again.
  //
  // The secret only lives in the enrollment prop (memory): it is never written to storage, to
  // the URL or to an announcement, and the typed code is cleared when the component goes away.
  // Without an enrollment, onrestart is called on mount to request one (mandatory enrollment
  // of a pre-auth session).
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, Button, CopyButton, Spinner, TextField, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { createFormState } from '../auth/formState.svelte';
  import type { TotpEnrollment } from '../auth/machine';
  import { normalizeTotpCode, renderMessage, totpCodeError, totpFailure } from '../auth/views';
  import { formatSecret, parseOtpauthLabel, qrCodeDataUrl } from '../forms/totp';

  interface Props {
    /** The secret to confirm; undefined while it is requested. */
    enrollment: TotpEnrollment | undefined;
    /** Enrollment required by the account (changes the introduction). */
    required?: boolean;
    /** Step of a pre-auth session (shows the 5-minute note). */
    preauth?: boolean;
    /** Level of the heading: 1 for a step of its own, 2 or 3 inside a page. */
    headingLevel?: 1 | 2 | 3;
    /** Confirms the code; a rejection is shown by the component. */
    onconfirm: (code: string) => Promise<void>;
    /** Requests a new secret (missing or expired enrollment). */
    onrestart: () => Promise<void>;
    /** Leaves the enrollment (button shown when set). */
    oncancel?: () => void;
    /** Label of the cancel button. */
    cancelLabel?: string;
  }

  let {
    enrollment,
    required = false,
    preauth = false,
    headingLevel = 1,
    onconfirm,
    onrestart,
    oncancel,
    cancelLabel,
  }: Props = $props();

  const uid = $props.id();
  const codeId = `${uid}-code`;
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });
  let code = $state('');
  let expired = $state(false);
  let starting = $state(false);
  let startError = $state('');
  let heading: HTMLElement | undefined = $state();

  const qr = $derived(enrollment === undefined ? null : qrCodeDataUrl(enrollment.qrCodePng));
  const label = $derived(enrollment === undefined ? null : parseOtpauthLabel(enrollment.otpauthUri));
  const secretText = $derived(enrollment === undefined ? '' : formatSecret(enrollment.secret));
  const secretRaw = $derived(secretText.replace(/ /g, ''));
  const codeError = $derived.by(() => {
    const message = renderMessage(form.fields['code'], t);
    if (message === undefined || form.attemptsRemaining === undefined) {
      return message;
    }
    return `${message} ${t('adminAuth.totp.attemptsRemaining', { count: form.attemptsRemaining })}`;
  });
  const general = $derived(renderMessage(form.general, t));

  async function start(): Promise<void> {
    starting = true;
    startError = '';
    try {
      await onrestart();
      expired = false;
      code = '';
      form.clear();
    } catch (err) {
      startError = describeError(i18n, err).message;
    } finally {
      starting = false;
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (form.blocked || enrollment === undefined) {
      return;
    }
    if (!form.check({ code: totpCodeError(code) })) {
      await tick();
      document.getElementById(codeId)?.focus();
      return;
    }
    form.busy = true;
    try {
      await onconfirm(normalizeTotpCode(code));
      code = '';
    } catch (err) {
      const failure = totpFailure(describeError(i18n, err), 'enroll');
      form.fail(failure);
      expired = failure.enrollmentExpired === true;
      code = '';
      await tick();
      document.getElementById(codeId)?.focus();
    } finally {
      form.busy = false;
    }
  }

  onMount(() => {
    heading?.focus();
    if (enrollment === undefined) {
      void start();
    }
  });

  onDestroy(() => {
    code = '';
    form.dispose();
  });
</script>

<section class="tt-enroll" aria-labelledby="{uid}-title">
  <svelte:element this={`h${headingLevel}`} id="{uid}-title" tabindex="-1" bind:this={heading}>
    {t('adminAuth.enroll.title')}
  </svelte:element>
  <p>{required ? t('adminAuth.enroll.requiredIntro') : t('adminAuth.enroll.intro')}</p>
  {#if preauth}
    <p class="tt-text-muted tt-text-sm">{t('adminAuth.stepTimeout')}</p>
  {/if}

  {#if enrollment === undefined}
    {#if startError !== ''}
      <Alert severity="error">{startError}</Alert>
      <div class="tt-cluster">
        <Button loading={starting} onclick={() => void start()}>{t('adminAuth.enroll.restart')}</Button>
        {#if oncancel}
          <Button variant="secondary" onclick={oncancel}>{cancelLabel ?? t('admin.common.cancel')}</Button>
        {/if}
      </div>
    {:else}
      <p><Spinner showLabel label={t('admin.common.loading')} /></p>
    {/if}
  {:else}
    <ol class="tt-stack">
      <li>{t('adminAuth.enroll.step1')}</li>
      <li>
        <p class="tt-mt-0">{t('adminAuth.enroll.step2')}</p>
        {#if qr !== null}
          <img class="tt-enroll__qr" src={qr} alt={t('adminAuth.enroll.qrAlt')} width="200" height="200" />
        {:else}
          <Alert severity="warning" live={false}>{t('adminAuth.enroll.qrUnavailable')}</Alert>
        {/if}
        <p class="tt-text-bold tt-mb-0">{t('adminAuth.enroll.manualKey.label')}</p>
        <p class="tt-text-muted tt-text-sm tt-mt-0">{t('adminAuth.enroll.manualKey.hint')}</p>
        <div class="tt-cluster">
          <code class="tt-mono tt-enroll__key">{secretText}</code>
          <CopyButton text={secretRaw} label={t('adminAuth.enroll.manualKey.copy')} small />
        </div>
        {#if label !== null}
          <dl class="tt-dl">
            <dt>{t('adminAuth.enroll.account')}</dt>
            <dd class="tt-break">{label.account}</dd>
            {#if label.issuer !== null}
              <dt>{t('adminAuth.enroll.issuer')}</dt>
              <dd class="tt-break">{label.issuer}</dd>
            {/if}
          </dl>
        {/if}
      </li>
      <li>{t('adminAuth.enroll.step3')}</li>
    </ol>

    {#if general !== undefined}
      <Alert severity="error" live={!form.locked}>{general}</Alert>
    {/if}
    {#if expired}
      <Button onclick={() => void start()} loading={starting}>{t('adminAuth.enroll.restart')}</Button>
      {#if startError !== ''}
        <Alert severity="error">{startError}</Alert>
      {/if}
    {:else}
      <form class="tt-stack" novalidate onsubmit={submit}>
        <TextField
          id={codeId}
          label={t('adminAuth.enroll.code.label')}
          hint={t('adminAuth.enroll.code.hint')}
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern="[0-9]*"
          maxlength={6}
          spellcheck={false}
          required
          error={codeError}
          bind:value={code}
        />
        <div class="tt-cluster">
          <Button
            type="submit"
            loading={form.busy}
            loadingLabel={t('adminAuth.enroll.submitting')}
            disabled={form.remaining > 0}
          >
            {t('adminAuth.enroll.submit')}
          </Button>
          {#if oncancel}
            <Button variant="secondary" disabled={form.busy} onclick={oncancel}>
              {cancelLabel ?? t('admin.common.cancel')}
            </Button>
          {/if}
        </div>
      </form>
    {/if}
  {/if}
</section>

<style>
  .tt-enroll__qr {
    display: block;
    margin: var(--tt-space-3) 0;
    border: var(--tt-border-width) solid var(--tt-border);
    background: #fff;
    image-rendering: pixelated;
  }

  .tt-enroll__key {
    font-size: var(--tt-font-size-lg);
    letter-spacing: 0.05em;
    word-break: break-all;
  }
</style>
