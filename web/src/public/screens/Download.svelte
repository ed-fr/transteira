<script lang="ts">
  // Download page /d/:token (CLAUDE.md section 10). Locked transfer: password form (3 wrong
  // attempts lock the transfer for 15 minutes, shown as a countdown with the field disabled).
  // Unlocked: sender, message (text), expiry, total, files with size and SHA-256, warnings for
  // files not analysed by the antivirus, per-file and ZIP links (filtered by safeApiHref).
  // A per-recipient link (version 1.1) first asks the recipient to prove their address by code
  // (VerificationStep), then the password form if any, then the files.
  // Downloads stay available during maintenance (the banner is shown by App.svelte).
  // When the window gets the focus back, the transfer is read again (at most once a minute): the
  // one-hour download grant may have expired (password form again), or the transfer may be gone.
  import { onDestroy, onMount } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Alert, Button, CopyButton, Spinner, TextField, announce } from '../../shared/components';
  import { languageValues } from '../../shared/api/schema';
  import { formatBytes, formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import { Countdown } from './countdown.svelte';
  import ErrorPage from './ErrorPage.svelte';
  import NotFound from './NotFound.svelte';
  import ReportAbuse from './ReportAbuse.svelte';
  import VerificationStep from './VerificationStep.svelte';
  import {
    canReply,
    replyFailure,
    downloadView,
    isNotScanned,
    downloadLoadFailure,
    needsVerification,
    shouldRecheck,
    unlockFailure,
    type PublicTransfer,
  } from './outcomes';
  import type { ScreenProps } from './types';

  type State =
    | { kind: 'loading' }
    | { kind: 'ready'; transfer: PublicTransfer }
    | { kind: 'not-found' }
    | { kind: 'gone' }
    | { kind: 'max-downloads' }
    | { kind: 'error' };

  let { tenant, params, nav }: ScreenProps = $props();
  const token = $derived(params['token'] ?? '');

  let view = $state<State>({ kind: 'loading' });
  let password = $state('');
  let passwordError = $state<string | undefined>();
  let formError = $state<string | undefined>();
  let unlocking = $state(false);
  let retrying = $state(false);
  // The recipient had access and has to verify again (the one-hour cookie expired).
  let verifyExpired = $state(false);
  // Reply to the transfer (version 1.1): verification step first when the server asks for it.
  let replyVerifying = $state(false);
  let replyBusy = $state(false);
  let replyError = $state<string | undefined>();
  let passwordInput: HTMLInputElement | undefined = $state();
  const lock = new Countdown({
    ondone: () => {
      formError = undefined;
      announce(t('download.locked.unlockedAgain'));
    },
  });
  onDestroy(() => lock.stop());

  let lastLoadAt = 0;

  async function load(linkToken: string): Promise<void> {
    lastLoadAt = Date.now();
    try {
      const { data } = await api.get('/downloads/{linkToken}', { path: { linkToken } });
      view = { kind: 'ready', transfer: data };
    } catch (err) {
      const failure = downloadLoadFailure(err);
      view = { kind: failure };
    }
  }

  // Silent check on window focus: a network error keeps the page as it is.
  async function recheck(): Promise<void> {
    if (view.kind !== 'ready' || unlocking || !shouldRecheck(lastLoadAt, Date.now())) {
      return;
    }
    const wasUnlocked = !view.transfer.locked;
    lastLoadAt = Date.now();
    try {
      const { data } = await api.get('/downloads/{linkToken}', { path: { linkToken: token } });
      view = { kind: 'ready', transfer: data };
      if (wasUnlocked && needsVerification(data)) {
        verifyExpired = true;
        announce(t('download.verify.expired'));
      } else if (wasUnlocked && data.locked) {
        formError = t('download.locked.expired');
        announce(formError);
      }
    } catch (err) {
      const failure = downloadLoadFailure(err);
      if (failure !== 'error') {
        view = { kind: failure };
      }
    }
  }

  // The screen is keyed on the path by App.svelte: the token never changes while mounted. Not an
  // $effect: the API client reads the language, which must not trigger a reload.
  onMount(() => {
    void load(token);
  });

  async function retry(): Promise<void> {
    retrying = true;
    await load(token);
    retrying = false;
  }

  function language(): 'fr' | 'en' {
    const current = i18n.locale.current;
    return (languageValues as readonly string[]).includes(current) ? (current as 'fr' | 'en') : 'en';
  }

  /**
   * Opens a reply session (the cookie is set by the server) and goes to the reply screen. A
   * recipient who has not proved their address yet is sent through the verification step, once.
   */
  async function reply(afterVerification = false): Promise<void> {
    if (replyBusy) {
      return;
    }
    replyBusy = true;
    replyError = undefined;
    try {
      await api.post('/downloads/{linkToken}/reply', {
        path: { linkToken: token },
        body: { language: language() },
      });
      nav.navigate(`/d/${encodeURIComponent(token)}/reply`);
    } catch (err) {
      const failure = replyFailure(err);
      switch (failure.kind) {
        case 'verification-required':
          if (afterVerification) {
            replyError = t('common.error.text');
          } else {
            replyVerifying = true;
          }
          break;
        case 'not-found':
        case 'gone':
        case 'max-downloads':
          view = { kind: failure.kind };
          break;
        case 'not-allowed':
          replyError = t('download.reply.notAllowed');
          break;
        case 'deposit-not-allowed':
          replyError = t('download.reply.depositNotAllowed');
          break;
        case 'maintenance':
          replyError = t('download.reply.maintenance');
          break;
        case 'rate-limited':
          replyError = t('download.reply.rateLimited');
          break;
        default:
          replyError = t('common.error.text');
      }
    } finally {
      replyBusy = false;
    }
  }

  async function replyVerified(): Promise<void> {
    replyVerifying = false;
    await reply(true);
  }

  async function unlock(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (unlocking || lock.active) {
      return;
    }
    passwordError = undefined;
    formError = undefined;
    if (password === '') {
      passwordError = t('download.locked.required');
      passwordInput?.focus();
      return;
    }
    unlocking = true;
    try {
      await api.post('/downloads/{linkToken}/unlock', { path: { linkToken: token }, body: { password } });
      password = '';
      await load(token);
      announce(t('download.locked.unlocked'));
    } catch (err) {
      const failure = unlockFailure(err);
      switch (failure.kind) {
        case 'wrong':
          passwordError =
            failure.attemptsRemaining === undefined
              ? t('download.locked.wrong')
              : `${t('download.locked.wrong')} ${t('common.attemptsRemaining', { count: failure.attemptsRemaining })}`;
          password = '';
          passwordInput?.focus();
          break;
        case 'locked':
          password = '';
          formError = t('download.locked.locked');
          lock.start(failure.retryAfterSeconds ?? 900);
          break;
        case 'required':
          passwordError = t('download.locked.required');
          passwordInput?.focus();
          break;
        case 'verification-required':
          verifyExpired = true;
          await load(token);
          break;
        case 'not-found':
        case 'gone':
        case 'max-downloads':
          view = { kind: failure.kind };
          break;
        default:
          formError = t('common.error.text');
      }
    } finally {
      unlocking = false;
    }
  }
</script>

<svelte:window onfocus={() => void recheck()} />

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{t('download.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'not-found'}
  <NotFound {nav} title={t('download.notFound.title')} text={t('download.notFound.text')} homeLink={false} />
{:else if view.kind === 'gone'}
  <NotFound {nav} title={t('download.gone.title')} text={t('download.gone.text')} homeLink={false} />
{:else if view.kind === 'max-downloads'}
  <NotFound
    {nav}
    title={t('download.maxDownloads.title')}
    text={t('download.maxDownloads.text')}
    homeLink={false}
  />
{:else if view.kind === 'error'}
  <ErrorPage onretry={() => void retry()} {retrying} />
{:else if replyVerifying}
  <VerificationStep
    {token}
    purpose="reply"
    emailMasked={view.kind === 'ready' ? view.transfer.recipientEmailMasked : undefined}
    onverified={replyVerified}
    ongone={(kind) => (view = { kind })}
    onmaintenance={() => {
      replyVerifying = false;
      replyError = t('download.reply.maintenance');
    }}
    oncancel={() => (replyVerifying = false)}
  />
{:else if needsVerification(view.transfer)}
  <VerificationStep
    {token}
    emailMasked={view.transfer.recipientEmailMasked}
    expired={verifyExpired}
    onverified={async () => {
      verifyExpired = false;
      await load(token);
    }}
    ongone={(kind) => (view = { kind })}
  />
  <ReportAbuse {token} />
{:else if view.transfer.locked}
  {@const transfer = view.transfer}
  <h1 tabindex="-1">{t('download.locked.title')}</h1>
  <dl class="tt-dl">
    <dt>{t('download.sender')}</dt>
    <dd>{transfer.senderEmail}</dd>
    <dt>{t('download.expires')}</dt>
    <dd>{formatDate(transfer.expiresAt, { dateStyle: 'long', timeStyle: 'short' })}</dd>
    {#if transfer.confidentialityLevel}
      <dt>{t('download.level')}</dt>
      <dd>{transfer.confidentialityLevel.label}</dd>
    {/if}
  </dl>
  <p>{t('download.locked.text')}</p>
  <form class="tt-stack" onsubmit={unlock} novalidate>
    {#if formError}
      <Alert severity="error">
        {formError}
        {#if lock.active}
          {t('common.retryAfter', { count: lock.remaining })}
        {/if}
      </Alert>
    {/if}
    <TextField
      label={t('download.locked.label')}
      type="password"
      autocomplete="off"
      required
      bind:value={password}
      bind:element={passwordInput}
      error={passwordError}
      disabled={lock.active}
    />
    <Button type="submit" loading={unlocking} disabled={lock.active}>{t('download.locked.submit')}</Button>
  </form>
  <ReportAbuse {token} />
{:else}
  {@const transfer = view.transfer}
  {@const dl = downloadView(transfer)}
  <h1 tabindex="-1">{t('download.title')}</h1>
  <dl class="tt-dl">
    <dt>{t('download.sender')}</dt>
    <dd>{transfer.senderEmail}</dd>
    <dt>{t('download.expires')}</dt>
    <dd>{formatDate(transfer.expiresAt, { dateStyle: 'long', timeStyle: 'short' })}</dd>
    <dt>{t('download.total')}</dt>
    <dd>{t('download.totalValue', { count: dl.files.length, size: formatBytes(dl.totalBytes) })}</dd>
    {#if dl.levelLabel !== undefined}
      <dt>{t('download.level')}</dt>
      <dd>{dl.levelLabel}</dd>
    {/if}
    {#if dl.downloadsRemaining !== undefined}
      <dt>{t('download.downloadsRemaining')}</dt>
      <dd>{dl.downloadsRemaining}</dd>
    {/if}
  </dl>
  {#if transfer.reply}
    <Alert severity="warning" live={false}>{t('download.reply.notice', { tenant: tenant.name })}</Alert>
  {/if}
  {#if transfer.message}
    <h2 class="tt-text-lg">{t('download.message')}</h2>
    <p class="tt-break message">{transfer.message}</p>
  {/if}

  {#if dl.deleteAfterFirstDownload}
    <Alert severity="warning" live={false}>{t('download.deleteAfterFirst')}</Alert>
  {/if}
  {#if dl.hasUnscanned}
    <Alert severity="warning" live={false}>{t('download.scan.summary')}</Alert>
  {/if}

  {#if dl.files.length === 0}
    <p>{t('download.noFiles')}</p>
  {:else}
    {#if dl.archiveHref}
      <p class="tt-mt-4">
        <a class="link-button link-button--primary" href={dl.archiveHref} download>
          {t('download.archive.button')}
        </a>
      </p>
      <p class="tt-text-muted tt-text-sm">{t('download.archive.hint')}</p>
    {/if}

    <div class="table-wrap">
      <table class="files">
        <caption>{t('download.files.caption')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('download.files.name')}</th>
            <th scope="col">{t('download.files.size')}</th>
            <th scope="col">{t('download.files.sha256')}</th>
            <th scope="col">{t('download.files.action')}</th>
          </tr>
        </thead>
        <tbody>
          {#each dl.files as file (file.id)}
            <tr>
              <th scope="row" class="tt-break file-name">
                {file.name}
                {#if isNotScanned(file.scanStatus)}
                  <span class="scan-warning tt-text-sm">
                    {file.scanStatus === 'not_scanned_encrypted'
                      ? t('download.scan.notScannedEncrypted')
                      : t('download.scan.notScannedTooLarge')}
                  </span>
                {/if}
              </th>
              <td class="nowrap">{formatBytes(file.size)}</td>
              <td>
                <code class="tt-mono tt-break">{file.sha256}</code>
                <CopyButton
                  small
                  text={file.sha256}
                  ariaLabel={t('download.files.copySha', { name: file.name })}
                />
              </td>
              <td>
                {#if file.href}
                  <a class="link-button" href={file.href} download>
                    {t('download.files.download')}<span class="visually-hidden">
                      {t('download.files.downloadName', { name: file.name })}</span
                    >
                  </a>
                {:else}
                  <span class="tt-text-muted">{t('download.files.unavailable')}</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="tt-text-muted tt-text-sm">{t('download.integrity')}</p>
  {/if}
  {#if canReply(transfer)}
    <section class="tt-stack reply" aria-labelledby="tt-reply-title">
      <h2 id="tt-reply-title" class="tt-text-lg">{t('download.reply.button')}</h2>
      <p class="tt-mb-0 tt-break">{t('download.reply.hint', { email: transfer.senderEmail })}</p>
      {#if replyError}
        <Alert severity="error">{replyError}</Alert>
      {/if}
      <div class="tt-cluster">
        <Button variant="secondary" loading={replyBusy} onclick={() => void reply()}>
          {t('download.reply.button')}
        </Button>
      </div>
    </section>
  {/if}
  <ReportAbuse {token} />
{/if}

<style>
  .reply {
    margin: var(--tt-space-4) 0;
  }

  .message {
    white-space: pre-line;
  }

  .table-wrap {
    overflow-x: auto;
    margin: var(--tt-space-4) 0;
  }

  .files {
    width: 100%;
    border-collapse: collapse;
  }

  .files caption {
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
    text-align: left;
  }

  .files th,
  .files td {
    padding: var(--tt-space-2);
    border-bottom: 1px solid var(--tt-border);
    text-align: left;
    vertical-align: top;
  }

  .file-name {
    font-weight: var(--tt-font-weight-normal);
  }

  .scan-warning {
    display: block;
    margin-top: var(--tt-space-1);
    padding: var(--tt-space-1) var(--tt-space-2);
    border-left: 4px solid var(--tt-warning);
    background: var(--tt-warning-bg);
    color: var(--tt-text);
    font-weight: var(--tt-font-weight-normal);
  }

  .nowrap {
    white-space: nowrap;
  }

  .link-button {
    display: inline-flex;
    align-items: center;
    min-height: 2rem;
    padding: var(--tt-space-1) var(--tt-space-3);
    border: 2px solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
    color: var(--tt-text);
    font-weight: var(--tt-font-weight-bold);
    text-decoration: none;
  }

  .link-button--primary {
    min-height: var(--tt-control-height);
    padding: var(--tt-space-2) var(--tt-space-5);
    border-color: var(--tt-primary);
    background: var(--tt-primary);
    color: var(--tt-on-primary);
  }

  .link-button:hover {
    text-decoration: underline;
  }
</style>
