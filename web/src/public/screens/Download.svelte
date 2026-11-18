<script lang="ts">
  // Download page /d/:token (CLAUDE.md section 10). Locked transfer: password form (3 wrong
  // attempts lock the transfer for 15 minutes, shown as a countdown with the field disabled).
  // Unlocked: sender, message (text), expiry, total, files with size and SHA-256, warnings for
  // files not analysed by the antivirus, per-file and ZIP links (filtered by safeApiHref).
  // A per-recipient link (version 1.1) first asks the recipient to prove their address by code
  // (VerificationStep), then the password form if any, then the files.
  // End-to-end encrypted transfer (version 2.0): once the view is unlocked, the key read from the
  // link fragment "#k=" (once, at load, then removed from the URL and the history entry) or typed
  // by the recipient opens the sealed metadata and message in the browser (e2e.ts); the files are
  // decrypted by the Service Worker, or in memory as a fallback (shared/e2e/download.ts), and the
  // ZIP is built in the browser. One decrypted download starts at a time: every download button is
  // disabled until the pending one has started; start, end and failure are announced.
  // Downloads stay available during maintenance (the banner is shown by App.svelte).
  // When the window gets the focus back, the transfer is read again (at most once a minute): the
  // one-hour download grant may have expired (password form again), or the transfer may be gone.
  // Layout of version 2.3 (section 13.2), in a medium public card (CardFrame; narrow for the end
  // states): header with the sender initial, "N files for you" and the sender address
  // (download/Header); information pills (download/InfoPills: relative expiry, level, downloads
  // left, total size); the message in a bubble; the antivirus summary banner; the prominent ZIP
  // link; the list "Files of this transfer", one row per file (download/FileRow); the bottom strip
  // with "Reply with files" and "Report an abuse" (download/BottomStrip).
  import { onDestroy, onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Alert, Button, Icon, Spinner, TextField, announce, type IconName } from '../../shared/components';
  import { fullName } from '../../shared/components/folders';
  import { ARCHIVE_NAME } from '../../shared/e2e/archive-names';
  import { languageValues } from '../../shared/api/schema';
  import { formatBytes, i18n, t } from '../../shared/i18n/i18n.svelte';
  import {
    E2EDownloader,
    E2EDownloadError,
    type DownloadErrorCode,
    type DownloadEvents,
  } from '../../shared/e2e/download';
  import { useCardFrame, type CardSize } from '../frame/card.svelte';
  import { startClock } from './clock';
  import { Countdown } from './countdown.svelte';
  import BottomStrip from './download/BottomStrip.svelte';
  import DownloadFileRow from './download/FileRow.svelte';
  import Header from './download/Header.svelte';
  import InfoPills from './download/InfoPills.svelte';
  import {
    isDowngrade,
    isEndToEnd,
    openEndToEnd,
    parseKeyText,
    takeKeyFromLocation,
    webCryptoAvailable,
    type E2EOpening,
  } from './e2e';
  import ErrorPage from './ErrorPage.svelte';
  import NotFound from './NotFound.svelte';
  import VerificationStep from './VerificationStep.svelte';
  import {
    canReply,
    replyFailure,
    downloadView,
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
    | { kind: 'downgrade' }
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

  // End-to-end encryption: the key bytes (never sent anywhere, kept in this component only). The
  // fragment is removed from the address bar at once: a reload then asks for the key.
  const keyFromLink = takeKeyFromLocation(window.location, window.history);
  // The router still holds the fragment it read at the navigation: forget it there too.
  onMount(() => nav.syncLocation());
  const cryptoAvailable = webCryptoAvailable();
  let keyBytes = $state.raw<Uint8Array | undefined>(keyFromLink);
  let keyText = $state('');
  let keyError = $state<string | undefined>();
  let keyInput: HTMLInputElement | undefined = $state();
  let e2e = $state.raw<E2EOpening | undefined>();
  let openGeneration = 0;
  let downloader: E2EDownloader | undefined;
  // Download waiting for its start, by button (file id or "archive").
  let busy = $state<Record<string, boolean>>({});
  const downloadPending = $derived(Object.keys(busy).length > 0);
  let downloadError = $state<string | undefined>();
  let filesHeading: HTMLHeadingElement | undefined = $state();

  let lastLoadAt = 0;
  // Clock of the relative expiry: the time of the last successful read of the transfer, moved on
  // every 30 seconds while the page stays open (the text would otherwise stay frozen).
  let now = $state(Date.now());
  onMount(() => startClock((time) => (now = time)));

  // Medium card for the transfer (password and verification steps included), narrow for the end
  // states (not found, gone, error), like the other short pages.
  const frame = useCardFrame();
  const cardSize = $derived<CardSize>(view.kind === 'loading' || view.kind === 'ready' ? 'medium' : 'narrow');
  $effect.pre(() => frame?.request(cardSize));

  /**
   * Opens the sealed metadata of an unlocked end-to-end encrypted transfer with the current key.
   * A wrong key brings the key form back with its error (focused when the recipient typed it).
   */
  async function openTransfer(transfer: PublicTransfer, fromForm: boolean): Promise<void> {
    const bytes = keyBytes;
    if (!isEndToEnd(transfer) || transfer.locked || needsVerification(transfer) || bytes === undefined) {
      return;
    }
    const generation = ++openGeneration;
    // Never rejects: unsupported without WebCrypto, tampered for a format error.
    const result = await openEndToEnd(transfer, bytes);
    if (generation !== openGeneration) {
      return;
    }
    if (result.kind === 'wrong-key') {
      keyBytes = undefined;
      e2e = undefined;
      keyError = t(
        fromForm || keyFromLink === undefined ? 'download.e2e.key.wrong' : 'download.e2e.key.wrongLink',
      );
      if (fromForm) {
        await tick();
        keyInput?.focus();
      }
      return;
    }
    e2e = result;
    if (fromForm) {
      // The key form is gone: the focus goes to the title of the page.
      if (result.kind === 'open') {
        keyText = '';
        announce(t('download.e2e.opened'));
      }
      await tick();
      filesHeading?.focus();
    }
  }

  async function submitKey(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    keyError = undefined;
    if (keyText.trim() === '') {
      keyError = t('download.e2e.key.required');
      keyInput?.focus();
      return;
    }
    const bytes = parseKeyText(keyText);
    if (bytes === undefined) {
      keyError = t('download.e2e.key.invalid');
      keyInput?.focus();
      return;
    }
    keyBytes = bytes;
    if (view.kind === 'ready') {
      await openTransfer(view.transfer, true);
    }
  }

  const DOWNLOAD_ERRORS: Record<Exclude<DownloadErrorCode, 'cancelled'>, string> = {
    'wrong-key': 'download.e2e.key.wrong',
    corrupt: 'download.e2e.error.corrupt',
    'unsupported-browser': 'download.e2e.error.unsupportedBrowser',
    network: 'download.e2e.error.network',
    unavailable: 'download.e2e.error.unavailable',
  };

  /**
   * Runs a decrypted download: busy (every download button disabled) until it has started, then
   * announced when started, done or failed (with its error message).
   */
  async function decryptDownload(
    busyKey: string,
    name: string,
    run: (d: E2EDownloader, events: DownloadEvents) => Promise<void>,
  ): Promise<void> {
    if (downloadPending) {
      return;
    }
    busy[busyKey] = true;
    downloadError = undefined;
    try {
      downloader ??= new E2EDownloader();
      await run(downloader, {
        onStarted: () => {
          delete busy[busyKey];
          announce(t('download.e2e.started', { name }));
        },
      });
      announce(t('download.e2e.done', { name }));
    } catch (err) {
      const code: DownloadErrorCode = err instanceof E2EDownloadError ? err.code : 'network';
      if (code !== 'cancelled') {
        downloadError = t(DOWNLOAD_ERRORS[code]);
        announce(downloadError, 'assertive');
        if (code === 'unavailable') {
          await load(token);
        }
      }
    } finally {
      delete busy[busyKey];
    }
  }

  async function load(linkToken: string): Promise<void> {
    lastLoadAt = Date.now();
    try {
      const { data } = await api.get('/downloads/{linkToken}', { path: { linkToken } });
      if (isDowngrade(data, keyFromLink)) {
        view = { kind: 'downgrade' };
        return;
      }
      now = Date.now();
      view = { kind: 'ready', transfer: data };
      void openTransfer(data, false);
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
      if (isDowngrade(data, keyFromLink)) {
        view = { kind: 'downgrade' };
        return;
      }
      now = Date.now();
      view = { kind: 'ready', transfer: data };
      void openTransfer(data, false);
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

<!-- End state of the page (not found, gone, refused): a decorative icon above the explanation. -->
{#snippet ended(icon: IconName, tone: 'neutral' | 'danger', title: string, text: string)}
  <div class="tt-dlend">
    <span class="tt-dlend__icon tt-dlend__icon--{tone}"><Icon name={icon} size="lg" /></span>
    <NotFound {nav} {title} {text} homeLink={false} />
  </div>
{/snippet}

<!-- Message of the sender, in a bubble under a heading for screen readers. -->
{#snippet bubble(text: string)}
  <div class="tt-dl__message">
    <h2 class="visually-hidden">{t('download.message')}</h2>
    <p class="tt-dl__bubble tt-break">{text}</p>
  </div>
{/snippet}

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{t('download.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'not-found'}
  {@render ended('x', 'neutral', t('download.notFound.title'), t('download.notFound.text'))}
{:else if view.kind === 'gone'}
  {@render ended('clock', 'neutral', t('download.gone.title'), t('download.gone.text'))}
{:else if view.kind === 'max-downloads'}
  {@render ended('download', 'neutral', t('download.maxDownloads.title'), t('download.maxDownloads.text'))}
{:else if view.kind === 'downgrade'}
  {@render ended('alert', 'danger', t('download.e2e.downgrade.title'), t('download.e2e.downgrade.text'))}
{:else if view.kind === 'error'}
  <div class="tt-dlend">
    <span class="tt-dlend__icon tt-dlend__icon--neutral"><Icon name="alert" size="lg" /></span>
    <ErrorPage onretry={() => void retry()} {retrying} />
  </div>
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
  <BottomStrip {token} />
{:else if view.transfer.locked}
  {@const transfer = view.transfer}
  <div class="tt-dl">
    <Header title={t('download.locked.title')} senderEmail={transfer.senderEmail} />
    <InfoPills expiresAt={transfer.expiresAt} {now} levelLabel={transfer.confidentialityLevel?.label} />
    <p>{t('download.locked.text')}</p>
    {#if isEndToEnd(transfer)}
      <p>{t('download.e2e.lockedNotice')}</p>
    {/if}
    <form class="tt-stack tt-dl__form" onsubmit={unlock} novalidate>
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
  </div>
  <BottomStrip {token} />
{:else}
  {@const transfer = view.transfer}
  {@const dl = downloadView(transfer)}
  {@const opened = e2e?.kind === 'open' ? e2e : undefined}
  {@const fileCount = opened ? opened.files.length : dl.files.length}
  {@const totalBytes = opened ? opened.totalBytes : dl.totalBytes}
  <div class="tt-dl">
    <Header
      title={t('download.heading', { count: fileCount })}
      senderEmail={transfer.senderEmail}
      bind:element={filesHeading}
    />
    <InfoPills
      expiresAt={transfer.expiresAt}
      {now}
      levelLabel={dl.levelLabel}
      downloadsRemaining={dl.downloadsRemaining}
      {totalBytes}
    />
    {#if transfer.reply}
      <Alert severity="warning" live={false} class="tt-dl__alert">
        {t('download.reply.notice', { tenant: tenant.name })}
      </Alert>
    {/if}
    {#if transfer.message}
      {@render bubble(transfer.message)}
    {/if}
    {#if opened?.message}
      {@render bubble(opened.message)}
    {/if}

    {#if dl.deleteAfterFirstDownload}
      <Alert severity="warning" live={false} class="tt-dl__alert">{t('download.deleteAfterFirst')}</Alert>
    {/if}
    {#if isEndToEnd(transfer)}
      <Alert severity="warning" live={false} class="tt-dl__alert">{t('download.e2e.notice')}</Alert>
      {#if !cryptoAvailable || e2e?.kind === 'unsupported'}
        <Alert severity="error" class="tt-dl__alert">{t('download.e2e.unsupported')}</Alert>
      {:else if keyBytes === undefined}
        <section class="tt-stack tt-dl__key" aria-labelledby="tt-e2e-key-title">
          <h2 id="tt-e2e-key-title" class="tt-text-lg">{t('download.e2e.key.title')}</h2>
          <p class="tt-mb-0">{t('download.e2e.key.text')}</p>
          <form class="tt-stack tt-dl__form" onsubmit={submitKey} novalidate>
            <TextField
              id="tt-e2e-key"
              label={t('download.e2e.key.label')}
              hint={t('download.e2e.key.hint')}
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              required
              bind:value={keyText}
              bind:element={keyInput}
              error={keyError}
            />
            <div class="tt-cluster">
              <Button type="submit" id="tt-e2e-key-submit">{t('download.e2e.key.submit')}</Button>
            </div>
          </form>
        </section>
      {:else if e2e === undefined}
        <Spinner label={t('download.e2e.opening')} showLabel />
      {:else if e2e.kind === 'tampered'}
        <Alert severity="error" class="tt-dl__alert">{t('download.e2e.tampered')}</Alert>
      {:else if opened}
        {#if downloadError}
          <!-- Announced by decryptDownload (assertive): not a live region of its own. -->
          <Alert severity="error" live={false} class="tt-dl__alert">{downloadError}</Alert>
        {/if}
        {#if opened.files.length === 0}
          <p>{t('download.noFiles')}</p>
        {:else}
          {#if opened.files.every((f) => f.url !== undefined)}
            <div class="tt-dl__zip">
              <Button
                id="tt-e2e-archive"
                class="tt-dl__zipbtn"
                loading={busy['archive'] === true}
                disabled={downloadPending && busy['archive'] !== true}
                loadingLabel={t('download.e2e.busy')}
                onclick={() =>
                  void decryptDownload('archive', ARCHIVE_NAME, (d, events) =>
                    d.downloadArchive(
                      opened.key,
                      opened.files.map((f) => ({
                        url: f.url ?? '',
                        index: f.index,
                        name: f.entryName,
                        size: f.size,
                        sha256: f.sha256,
                      })),
                      ARCHIVE_NAME,
                      events,
                    ),
                  )}
              >
                {#if busy['archive'] !== true}<Icon name="download" />{/if}
                {t('download.archive.button')}
              </Button>
              <p class="tt-dl__hint">{t('download.e2e.archiveHint')}</p>
            </div>
          {/if}

          <ul class="tt-dl__files" aria-label={t('download.files.caption')}>
            {#each opened.files as file (file.id)}
              {@const name = fullName(file.path, file.name)}
              {@const url = file.url}
              {#snippet decrypt()}
                {#if url !== undefined}
                  <Button
                    variant="secondary"
                    class="tt-dlrow__action"
                    loading={busy[file.id] === true}
                    disabled={downloadPending && busy[file.id] !== true}
                    loadingLabel={t('download.e2e.busyName', { name })}
                    title={t('download.files.downloadFile', { name })}
                    onclick={() =>
                      void decryptDownload(file.id, name, (d, events) =>
                        d.downloadFile(
                          opened.key,
                          {
                            url,
                            index: file.index,
                            name: file.name,
                            size: file.size,
                            sha256: file.sha256,
                          },
                          events,
                        ),
                      )}
                  >
                    {#if busy[file.id] !== true}<Icon name="download" />{/if}<span class="visually-hidden"
                      >{t('download.files.downloadFile', { name })}</span
                    >
                  </Button>
                {/if}
              {/snippet}
              <DownloadFileRow
                name={file.name}
                path={file.path}
                size={file.size}
                scanStatus="not_scanned_e2e"
                sha256={file.sha256}
                cipherSha256={file.ciphertextSha256}
                action={url === undefined ? undefined : decrypt}
              />
            {/each}
          </ul>
          <p class="tt-dl__note">{t('download.e2e.integrity')}</p>
        {/if}
      {/if}
    {:else}
      {#if dl.notScanned > 0}
        <Alert
          severity="warning"
          live={false}
          class="tt-dl__alert"
          title={t('download.scan.summaryTitle', { count: dl.notScanned })}
        >
          {t('download.scan.summaryText', { count: dl.notScanned })}
        </Alert>
      {/if}

      {#if dl.files.length === 0}
        <p>{t('download.noFiles')}</p>
      {:else}
        {#if dl.archiveHref}
          <div class="tt-dl__zip">
            <a class="tt-dl__zipbtn" href={dl.archiveHref} download>
              <Icon name="download" />
              {t('download.archive.button')}
            </a>
            <p class="tt-dl__hint">{t('download.archive.hint', { size: formatBytes(dl.totalBytes) })}</p>
          </div>
        {/if}

        <ul class="tt-dl__files" aria-label={t('download.files.caption')}>
          {#each dl.files as file (file.id)}
            <DownloadFileRow
              name={file.name}
              path={file.path}
              size={file.size}
              scanStatus={file.scanStatus}
              sha256={file.sha256}
              href={file.href}
            />
          {/each}
        </ul>
        <p class="tt-dl__note">{t('download.integrity')}</p>
      {/if}
    {/if}
  </div>
  <BottomStrip
    {token}
    canReply={canReply(transfer)}
    {replyBusy}
    {replyError}
    replyHint={t('download.reply.hint', { email: transfer.senderEmail })}
    onreply={() => void reply()}
  />
{/if}

<style>
  /* One column of blocks spaced by the gap: the margins of the direct children are reset. */
  .tt-dl {
    display: flex;
    flex-direction: column;
    gap: var(--tt-space-5);
  }

  .tt-dl > p,
  .tt-dl__key > p,
  .tt-dl :global(.tt-dl__alert) {
    margin: 0;
  }

  .tt-dl__form {
    max-width: 26rem;
  }

  .tt-dl__bubble {
    margin: 0;
    padding: var(--tt-space-4) var(--tt-space-5);
    border: var(--tt-border-width) solid transparent;
    border-radius: var(--tt-radius-sm) var(--tt-radius-lg) var(--tt-radius-lg) var(--tt-radius-lg);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
    white-space: pre-line;
  }

  .tt-dl__zip {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-3) var(--tt-space-4);
  }

  /* Prominent ZIP control: the link of a plain transfer, the decrypting Button otherwise. */
  .tt-dl__zip :global(.tt-dl__zipbtn) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--tt-space-2);
    min-height: 3.25rem;
    padding: var(--tt-space-3) var(--tt-space-6);
    border: 2px solid transparent;
    border-radius: var(--tt-radius-lg);
    background: var(--tt-primary);
    color: var(--tt-on-primary);
    font-size: var(--tt-font-size-lg);
    font-weight: var(--tt-font-weight-bold);
    line-height: var(--tt-line-height-tight);
    text-decoration: none;
    box-shadow: var(--tt-shadow);
  }

  .tt-dl__zip a.tt-dl__zipbtn:hover {
    text-decoration: underline;
  }

  .tt-dl__hint {
    margin: 0;
    color: var(--tt-text-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-dl__files {
    margin: 0;
    padding: 0;
    border-top: var(--tt-border-width) solid var(--tt-separator);
    list-style: none;
  }

  .tt-dl__note {
    color: var(--tt-text-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-dlend__icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 3.5rem;
    height: 3.5rem;
    margin-bottom: var(--tt-space-4);
    border: var(--tt-border-width) solid transparent;
    border-radius: var(--tt-radius-full);
  }

  .tt-dlend__icon--neutral {
    background: var(--tt-chip-bg);
    color: var(--tt-chip-text);
  }

  .tt-dlend__icon--danger {
    background: var(--tt-danger-bg);
    color: var(--tt-danger);
  }

  @media (max-width: 40rem) {
    .tt-dl {
      gap: var(--tt-space-4);
    }

    .tt-dl__zip :global(.tt-dl__zipbtn) {
      width: 100%;
    }
  }

  @media (forced-colors: active) {
    .tt-dl__zip :global(.tt-dl__zipbtn) {
      border-color: ButtonText;
    }

    .tt-dl__zip a.tt-dl__zipbtn {
      border-color: LinkText;
    }
  }
</style>
