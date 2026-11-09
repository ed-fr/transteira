<script lang="ts">
  // Page of a one-time secret /s/:token (V2.1, CLAUDE.md section 22.1). The key K is read once
  // from the link fragment "#k=" and removed from the address bar and the history entry at once
  // (a reload no longer has it: "incomplete link"). The status (GET) consumes nothing: it gives
  // the expiry, the passphrase descriptor and the file size. Nothing is revealed before the
  // recipient presses "Show the secret": a bot or a browser without JavaScript only issues the
  // GET. After the reveal the text is shown read-only (it can be hidden) with a copy button and a
  // clipboard warning, and the optional file is downloaded once with its 10-minute grant,
  // decrypted in memory and checked (reveal.ts). The bytes of K are wiped once the secret is
  // revealed or can no longer be (T-344, T-357).
  import { onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Alert, Button, CopyButton, Spinner, TextArea, TextField, announce } from '../../shared/components';
  import { browserDeps } from '../../shared/e2e/download';
  import { formatBytes, formatDate, t } from '../../shared/i18n/i18n.svelte';
  import {
    downloadFile,
    grantExpired,
    loadStatus,
    revealSecret,
    type FileFailure,
    type GoneReason,
    type RevealDeps,
    type RevealedFile,
    type RevealedSecret,
    type SecretFailure,
    type SecretStatus,
  } from '../secret/reveal';
  import { takeKeyFromLocation, webCryptoAvailable } from './e2e';
  import ErrorPage from './ErrorPage.svelte';
  import NotFound from './NotFound.svelte';
  import type { ScreenProps } from './types';

  type State =
    | { kind: 'loading' }
    | { kind: 'ready'; status: SecretStatus }
    | { kind: 'revealed'; secret: RevealedSecret }
    | { kind: 'incomplete' }
    | { kind: 'not-found' }
    | { kind: 'wrong-key' }
    | { kind: 'gone'; reason: GoneReason }
    | { kind: 'tampered' }
    | { kind: 'unsupported' }
    | { kind: 'error' };

  let { params, nav }: ScreenProps = $props();
  const token = $derived(params['token'] ?? '');

  const deps: RevealDeps = { api, fetch: (input, init) => globalThis.fetch(input, init) };

  // The key bytes stay in this component only, never in the URL after this line.
  const key = takeKeyFromLocation(window.location, window.history);
  // The router still holds the fragment it read at the navigation: forget it there too.
  onMount(() => nav.syncLocation());

  let view = $state<State>({ kind: 'loading' });
  let retrying = $state(false);
  let passphrase = $state('');
  let passphraseError = $state<string | undefined>();
  let formError = $state<string | undefined>();
  let formAlert: HTMLDivElement | undefined = $state();
  let passphraseInput: HTMLInputElement | undefined = $state();
  let revealing = $state(false);
  let textHidden = $state(false);

  let fileBusy = $state(false);
  let fileDone = $state(false);
  let fileError = $state<string | undefined>();

  const GONE_TEXTS: Record<GoneReason, string> = {
    read: 'secret.reveal.gone.read',
    expired: 'secret.reveal.gone.expired',
    deleted: 'secret.reveal.gone.deleted',
    locked: 'secret.reveal.gone.locked',
    unknown: 'secret.reveal.gone.unknown',
  };

  const FILE_ERRORS: Record<FileFailure, string> = {
    unavailable: 'secret.reveal.download.error.unavailable',
    corrupt: 'secret.reveal.download.error.corrupt',
    'rate-limited': 'secret.reveal.download.error.rateLimited',
    maintenance: 'secret.reveal.download.error.maintenance',
    'in-setup': 'secret.reveal.download.error.inSetup',
    network: 'secret.reveal.download.error.network',
    error: 'secret.reveal.download.error.unknown',
  };

  /** Moves the focus to the heading of a page that replaced the form. */
  async function focusHeading(): Promise<void> {
    await tick();
    document.querySelector<HTMLElement>('h1[tabindex="-1"]')?.focus();
  }

  /** Terminal state of a failure, undefined when the form stays (with its message). */
  function terminal(failure: SecretFailure): State | undefined {
    switch (failure.kind) {
      case 'not-found':
      case 'wrong-key':
      case 'tampered':
      case 'unsupported':
        return { kind: failure.kind };
      case 'gone':
        return { kind: 'gone', reason: failure.reason };
      default:
        return undefined;
    }
  }

  async function load(): Promise<void> {
    const outcome = await loadStatus(deps, token);
    if (outcome.kind === 'failure') {
      view = terminal(outcome.failure) ?? { kind: 'error' };
    } else if (key === undefined) {
      view = { kind: 'incomplete' };
    } else if (!webCryptoAvailable()) {
      view = { kind: 'unsupported' };
    } else {
      view = { kind: 'ready', status: outcome.status };
    }
  }

  // Keyed on the path by App.svelte: the token never changes while mounted.
  onMount(() => {
    void load();
  });

  async function retry(): Promise<void> {
    retrying = true;
    await load();
    retrying = false;
    await focusHeading();
  }

  async function showFormError(message: string): Promise<void> {
    formError = message;
    await tick();
    formAlert?.focus();
  }

  async function reveal(event: SubmitEvent, status: SecretStatus): Promise<void> {
    event.preventDefault();
    if (revealing || key === undefined) {
      return;
    }
    passphraseError = undefined;
    formError = undefined;
    revealing = true;
    const outcome = await revealSecret(deps, token, key, passphrase, status);
    revealing = false;
    if (outcome.kind === 'revealed') {
      key.fill(0);
      passphrase = '';
      view = { kind: 'revealed', secret: outcome.secret };
      announce(t('secret.reveal.revealed.announce'));
      await focusHeading();
      return;
    }
    const failure = outcome.failure;
    const end = terminal(failure);
    if (end !== undefined) {
      key.fill(0);
      passphrase = '';
      view = end;
      await focusHeading();
      return;
    }
    switch (failure.kind) {
      case 'passphrase-required':
      case 'passphrase-invalid':
      case 'wrong-passphrase':
        passphraseError =
          failure.kind === 'passphrase-required'
            ? t('secret.reveal.passphrase.required')
            : failure.kind === 'passphrase-invalid'
              ? t('secret.reveal.passphrase.invalid')
              : `${t('secret.reveal.passphrase.wrong')} ${t('common.attemptsRemaining', { count: failure.attemptsRemaining })}`;
        if (failure.kind === 'wrong-passphrase') {
          passphrase = '';
        }
        await tick();
        passphraseInput?.focus();
        break;
      case 'rate-limited':
        await showFormError(
          failure.retryAfterSeconds === undefined
            ? t('secret.reveal.error.rateLimited')
            : `${t('secret.reveal.error.rateLimited')} ${t('common.retryAfter', { count: failure.retryAfterSeconds })}`,
        );
        break;
      case 'maintenance':
        await showFormError(t('secret.reveal.error.maintenance'));
        break;
      case 'in-setup':
        await showFormError(t('secret.reveal.error.inSetup'));
        break;
      case 'network':
        await showFormError(t('secret.reveal.error.network'));
        break;
      default:
        await showFormError(t('secret.reveal.error.unknown'));
    }
  }

  async function download(secret: RevealedSecret, file: RevealedFile): Promise<void> {
    if (fileBusy || fileDone) {
      return;
    }
    fileError = undefined;
    if (grantExpired(file, Date.now())) {
      fileDone = true;
      fileError = t(FILE_ERRORS.unavailable);
      announce(fileError, 'assertive');
      return;
    }
    fileBusy = true;
    const outcome = await downloadFile(deps, token, secret.rootKey, file);
    fileBusy = false;
    if (outcome.kind === 'ok') {
      browserDeps().saveBlob(outcome.blob, outcome.name);
      fileDone = true;
      announce(t('secret.reveal.download.done', { name: outcome.name }));
      return;
    }
    // The grant is single use: once the file is gone, the button is useless.
    if (outcome.failure === 'unavailable' || outcome.failure === 'corrupt') {
      fileDone = true;
    }
    fileError = t(FILE_ERRORS[outcome.failure]);
    announce(fileError, 'assertive');
  }
</script>

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{t('secret.reveal.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'incomplete'}
  <NotFound
    {nav}
    title={t('secret.reveal.incomplete.title')}
    text={t('secret.reveal.incomplete.text')}
    homeLink={false}
  />
{:else if view.kind === 'not-found'}
  <NotFound
    {nav}
    title={t('secret.reveal.notFound.title')}
    text={t('secret.reveal.notFound.text')}
    homeLink={false}
  />
{:else if view.kind === 'wrong-key'}
  <NotFound
    {nav}
    title={t('secret.reveal.wrongKey.title')}
    text={t('secret.reveal.wrongKey.text')}
    homeLink={false}
  />
{:else if view.kind === 'gone'}
  <NotFound {nav} title={t('secret.reveal.gone.title')} text={t(GONE_TEXTS[view.reason])} homeLink={false} />
{:else if view.kind === 'tampered'}
  <NotFound
    {nav}
    title={t('secret.reveal.tampered.title')}
    text={t('secret.reveal.tampered.text')}
    homeLink={false}
  />
{:else if view.kind === 'unsupported'}
  <NotFound
    {nav}
    title={t('secret.reveal.unsupported.title')}
    text={t('secret.reveal.unsupported.text')}
    homeLink={false}
  />
{:else if view.kind === 'error'}
  <ErrorPage message={t('secret.reveal.loadError')} onretry={() => void retry()} {retrying} />
{:else if view.kind === 'ready'}
  {@const status = view.status}
  <h1 tabindex="-1">{t('secret.reveal.title')}</h1>
  <p>{t('secret.reveal.intro')}</p>
  <dl class="tt-dl">
    <dt>{t('secret.reveal.expires')}</dt>
    <dd>{formatDate(status.expiresAt, { dateStyle: 'long', timeStyle: 'short' })}</dd>
    {#if status.file}
      <dt>{t('secret.reveal.file')}</dt>
      <dd>{t('secret.reveal.fileSize', { size: formatBytes(status.file.size) })}</dd>
    {/if}
  </dl>
  {#if status.file}
    <Alert severity="warning" live={false}>{t('secret.reveal.notScanned')}</Alert>
  {/if}
  <form class="tt-stack" onsubmit={(event) => void reveal(event, status)} novalidate>
    {#if formError}
      <Alert severity="error" bind:element={formAlert}>{formError}</Alert>
    {/if}
    {#if status.passphrase}
      <TextField
        id="tt-secret-passphrase"
        label={t('secret.reveal.passphrase.label')}
        hint={t('secret.reveal.passphrase.hint')}
        type="password"
        autocomplete="off"
        data-1p-ignore
        data-lpignore="true"
        data-bwignore
        required
        bind:value={passphrase}
        bind:element={passphraseInput}
        error={passphraseError}
        disabled={revealing}
      />
    {/if}
    <p class="tt-mb-0">{t('secret.reveal.once')}</p>
    <div class="tt-cluster">
      <Button type="submit" id="tt-secret-show" loading={revealing} loadingLabel={t('secret.reveal.opening')}>
        {t('secret.reveal.show')}
      </Button>
    </div>
  </form>
{:else}
  {@const secret = view.secret}
  <h1 tabindex="-1">{t('secret.reveal.revealed.title')}</h1>
  <Alert severity="warning" live={false}>{t('secret.reveal.revealed.warning')}</Alert>
  {#if secret.text !== ''}
    {#if textHidden}
      <p id="tt-secret-text-hidden">{t('secret.reveal.revealed.hidden')}</p>
    {:else}
      <TextArea
        id="tt-secret-text"
        class="secret-text"
        label={t('secret.reveal.revealed.text')}
        value={secret.text}
        readonly
        rows={8}
        spellcheck={false}
        autocomplete="off"
      />
    {/if}
    <div class="tt-cluster">
      <Button variant="secondary" aria-pressed={textHidden} onclick={() => (textHidden = !textHidden)}>
        {t('secret.reveal.revealed.hide')}
      </Button>
      <CopyButton text={secret.text} label={t('secret.reveal.revealed.copy')} />
    </div>
    <p class="tt-text-sm tt-text-muted">{t('secret.reveal.revealed.clipboard')}</p>
  {:else}
    <p>{t('secret.reveal.revealed.noText')}</p>
  {/if}

  {#if secret.file.kind === 'tampered'}
    <Alert severity="error" live={false}>{t('secret.reveal.download.tampered')}</Alert>
  {:else if secret.file.kind === 'ready'}
    {@const file = secret.file}
    <section class="tt-stack file" aria-labelledby="tt-secret-file-title">
      <h2 id="tt-secret-file-title" class="tt-text-lg">{t('secret.reveal.download.title')}</h2>
      <dl class="tt-dl">
        <dt>{t('secret.reveal.download.name')}</dt>
        <dd class="tt-break">{file.name}</dd>
        <dt>{t('secret.reveal.download.size')}</dt>
        <dd>{formatBytes(file.size)}</dd>
        <dt>{t('secret.reveal.download.sha256')}</dt>
        <dd>
          <code class="tt-mono tt-break">{file.sha256}</code>
          <CopyButton
            small
            text={file.sha256}
            ariaLabel={t('secret.reveal.download.copySha', { name: file.name })}
          />
        </dd>
      </dl>
      <Alert severity="warning" live={false}>{t('secret.reveal.notScanned')}</Alert>
      {#if !fileDone}
        <p class="tt-mb-0">
          {t('secret.reveal.download.grant', {
            time: formatDate(file.grantExpiresAt, { timeStyle: 'short' }),
          })}
        </p>
      {/if}
      {#if fileError}
        <!-- Announced by download (assertive): not a live region of its own. -->
        <Alert severity="error" live={false}>{fileError}</Alert>
      {:else if fileDone}
        <Alert severity="success" live={false}>{t('secret.reveal.download.done', { name: file.name })}</Alert>
      {/if}
      {#if !fileDone}
        <div class="tt-cluster">
          <Button
            id="tt-secret-download"
            loading={fileBusy}
            loadingLabel={t('secret.reveal.download.busy')}
            onclick={() => void download(secret, file)}
          >
            {t('secret.reveal.download.button')}
          </Button>
        </div>
      {/if}
    </section>
  {/if}
{/if}

<style>
  .file {
    margin: var(--tt-space-4) 0;
  }

  :global(.secret-text .tt-field__input) {
    font-family: var(--tt-font-mono);
    white-space: pre-wrap;
  }
</style>
