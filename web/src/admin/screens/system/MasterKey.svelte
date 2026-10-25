<script lang="ts">
  // Master key (super admin; CLAUDE.md section 16.1, threat model T-169, procedure in
  // docs/operations/master-key.md). Shows the identifiers of the current and new master keys
  // (never key material: the API returns identifiers only), the latest rotation and its
  // progress, and starts step 3 of the rotation (or resumes an interrupted one) after a
  // two-box checklist and a TOTP or recovery code re-confirmation in a dialog. The view model
  // is in masterKey.ts.
  //
  // - The progress of a running rotation is read every 2 s while the screen is shown (10 s
  //   while the page is hidden or the rotation looks interrupted, with a backoff after failed
  //   reads); polling stops on a final status and when the screen goes away.
  // - Each read extends the admin session (T-165): after 10 minutes without user activity
  //   (activity.ts) the polling pauses with a notice and a "Resume updates" button. After an
  //   error that is not worth retrying it stops with a "Retry" button. Both halts hold across
  //   reloads of the status and end only on a user action or with another rotation.
  // - Answers of an earlier polling (another rotation, or before a restart of the polling) are
  //   ignored.
  // - Screen readers hear the start, the 25/50/75/100 % milestones and the end, never every read.
  // - The typed code lives only in this component: cleared at each submit, when the dialog
  //   closes and when the screen goes away; never in the URL, storage, announcements or logs.
  // The system sub-navigation is rendered by App.svelte.
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import {
    Alert,
    Button,
    Checkbox,
    Dialog,
    HelpIcon,
    ProgressBar,
    Spinner,
    TextField,
    announce,
  } from '../../../shared/components';
  import { formatDate, formatNumber, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import { createFormState } from '../../auth/formState.svelte';
  import { renderMessage, type Message } from '../../auth/views';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { createActivityTracker, documentActivity } from '../../activity';
  import { documentVisibility } from '../../maintenance.svelte';
  import type { AdminScreenProps } from '../types';
  import {
    MASTER_KEY_DOC,
    POLL_MS,
    announceProgress,
    canStart,
    checklistDone,
    codeError,
    idleHalt,
    isStalled,
    observeProgress,
    pollDelay,
    pollErrorAction,
    pollHalted,
    problemDetail,
    progressText,
    progressView,
    rotationStatusKey,
    rotationStatusVariant,
    screenState,
    shouldPoll,
    startBody,
    startFailure,
    startLabelKey,
    withRotation,
    type AnnounceState,
    type CodeMode,
    type KeyRotation,
    type MasterKeyStatus,
    type PollHalt,
    type ProgressWatch,
  } from './masterKey';
  import { browserPollerDeps, createPoller } from './poller';

  let { params: _params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const codeId = `${uid}-code`;
  const requiredId = `${uid}-required`;
  const progressHeadingId = `${uid}-progress`;

  // ---- Status and progress ----
  let status = $state.raw<MasterKeyStatus | undefined>(undefined);
  let loading = $state(true);
  let loadError = $state('');
  let loadGeneration = 0;
  let stalled = $state(false);
  let pollErrors = $state(0);
  // Halt of the polling by the screen (idle admin, persistent error), see pollHalted.
  let halt = $state.raw<PollHalt | undefined>(undefined);
  let watch: ProgressWatch | undefined;
  let announced: AnnounceState | undefined;
  let pollingId: string | undefined;
  // Incremented at each start and stop of the polling: an answer of an earlier one is ignored.
  let pollGeneration = 0;
  let destroyed = false;
  const doc = typeof document === 'undefined' ? undefined : document;
  const poller = createPoller(browserPollerDeps(documentVisibility(doc)));
  const activity = createActivityTracker(documentActivity(doc));

  // ---- Page message (refused start) ----
  let pageMessage = $state.raw<Message | undefined>(undefined);

  // ---- Start ----
  let vaultCopy = $state(false);
  let idsChecked = $state(false);
  let dialogOpen = $state(false);
  let mode = $state<CodeMode>('totp');
  let code = $state('');
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });

  const kind = $derived(status === undefined ? undefined : screenState(status, stalled));
  const latest = $derived(status?.latestRotation);
  const progress = $derived(latest === undefined ? undefined : progressView(latest));
  const ready = $derived(checklistDone(vaultCopy, idsChecked));
  const general = $derived(renderMessage(form.general, t));
  const fieldError = $derived.by(() => {
    const message = renderMessage(form.fields['code'], t);
    if (message === undefined || form.attemptsRemaining === undefined) {
      return message;
    }
    return `${message} ${t('adminAuth.totp.attemptsRemaining', { count: form.attemptsRemaining })}`;
  });

  const when = (iso: string): string => formatDate(iso, { dateStyle: 'medium', timeStyle: 'short' });

  function say(message: Message | undefined): void {
    const text = renderMessage(message, t);
    if (text !== undefined && text !== '') {
      announce(text, 'polite');
    }
  }

  /** Records a read of rotation: interruption watch and milestone announcements. */
  function observe(rotation: KeyRotation, started = false): void {
    watch = observeProgress(watch, rotation, Date.now());
    stalled = rotation.status === 'running' && isStalled(watch, Date.now());
    const step = announceProgress(announced, rotation, started);
    announced = step.state;
    say(step.message);
  }

  function stopPolling(): void {
    pollGeneration++;
    poller.stop();
    pollingId = undefined;
  }

  /** Starts or stops the polling to match the status (and the halt, if any). */
  function syncPolling(): void {
    const rotation = status?.latestRotation;
    if (destroyed || !shouldPoll(status) || rotation === undefined || pollHalted(halt, rotation.id)) {
      stopPolling();
      return;
    }
    // A halt of another rotation no longer applies.
    halt = undefined;
    if (poller.active && pollingId === rotation.id) {
      return;
    }
    stopPolling();
    const generation = pollGeneration;
    pollingId = rotation.id;
    pollErrors = 0;
    poller.start((ctx) => pollOnce(rotation.id, generation, ctx.visible), POLL_MS);
  }

  /** User action ("Resume updates", "Retry"): ends the halt and reads the status again. */
  function resumePolling(): void {
    halt = undefined;
    activity.reset();
    void loadStatus();
  }

  async function pollOnce(
    rotationId: string,
    generation: number,
    visible: boolean,
  ): Promise<number | undefined> {
    if (generation !== pollGeneration) {
      return undefined;
    }
    // No timer-driven read for an idle admin: it would keep the session alive (T-165).
    const idle = idleHalt(activity, rotationId);
    if (idle !== undefined) {
      halt = idle;
      return undefined;
    }
    try {
      const { data } = await adminApi.get('/admin/system/master-key/rotations/{rotationId}', {
        path: { rotationId },
      });
      if (destroyed || status === undefined || generation !== pollGeneration || data.id !== rotationId) {
        return undefined;
      }
      pollErrors = 0;
      status = withRotation(status, data);
      observe(data);
      if (data.status !== 'running') {
        // Final status: read the whole status again (restartRequired, new key).
        void loadStatus();
        return undefined;
      }
      return pollDelay({ visible, stalled, errors: 0 });
    } catch (err) {
      if (destroyed || generation !== pollGeneration) {
        return undefined;
      }
      if (pollErrorAction(describeError(i18n, err)) === 'retry') {
        pollErrors += 1;
        return pollDelay({ visible, stalled, errors: pollErrors });
      }
      // Kept across the reload below: no new read until a user action or another rotation.
      halt = { reason: 'error', rotationId };
      pollErrors = 0;
      void loadStatus();
      return undefined;
    }
  }

  async function loadStatus(): Promise<void> {
    const mine = ++loadGeneration;
    loading = true;
    try {
      const { data } = await adminApi.get('/admin/system/master-key');
      if (mine !== loadGeneration || destroyed) {
        return;
      }
      status = data;
      loadError = '';
      if (data.latestRotation !== undefined) {
        observe(data.latestRotation);
      } else {
        stalled = false;
      }
      syncPolling();
    } catch (err) {
      if (mine === loadGeneration) {
        loadError = describeError(i18n, err).message;
      }
    } finally {
      if (mine === loadGeneration) {
        loading = false;
      }
    }
  }

  // ---- Start dialog ----

  function openDialog(): void {
    if (!ready || kind === undefined || !canStart(kind)) {
      return;
    }
    pageMessage = undefined;
    mode = 'totp';
    code = '';
    form.clear();
    dialogOpen = true;
    void tick().then(focusCode);
  }

  function focusCode(): void {
    document.getElementById(codeId)?.focus();
  }

  async function switchMode(): Promise<void> {
    mode = mode === 'totp' ? 'recovery' : 'totp';
    code = '';
    form.clear();
    await tick();
    focusCode();
  }

  function onDialogClose(): void {
    code = '';
    form.clear();
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (form.blocked) {
      return;
    }
    if (!form.check({ code: codeError(mode, code) })) {
      await tick();
      focusCode();
      return;
    }
    const body = startBody(mode, code);
    // The code is not kept once the request is built, whatever the answer.
    code = '';
    form.busy = true;
    try {
      const { data } = await adminApi.post('/admin/system/master-key/rotations', { body });
      if (destroyed) {
        return;
      }
      dialogOpen = false;
      vaultCopy = false;
      idsChecked = false;
      watch = undefined;
      stalled = false;
      status = status === undefined ? status : withRotation(status, data);
      observe(data, true);
      // Resumed rotation: same id, the polling restarts anyway (a user action ends any halt).
      halt = undefined;
      activity.reset();
      stopPolling();
      syncPolling();
      await tick();
      document.getElementById(progressHeadingId)?.focus();
    } catch (err) {
      const view = describeError(i18n, err);
      if (view.code === 'state-conflict') {
        // Read the state again; a worker that runs after all restarts the interruption watch.
        watch = undefined;
        stalled = false;
        await loadStatus();
      }
      const failure = startFailure(
        view,
        problemDetail(err),
        view.code === 'state-conflict' ? status : undefined,
      );
      if (failure.kind === 'form') {
        form.fail(failure.failure);
        await tick();
        focusCode();
      } else {
        dialogOpen = false;
        pageMessage = failure.message;
        if (failure.reload && view.code !== 'state-conflict') {
          void loadStatus();
        }
      }
    } finally {
      form.busy = false;
    }
  }

  onMount(() => {
    void loadStatus();
  });

  onDestroy(() => {
    destroyed = true;
    stopPolling();
    activity.dispose();
    code = '';
    form.dispose();
  });
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminSystem.masterKey.title')}</h1>
  <HelpIcon topic="system-master-key" title={t('adminSystem.masterKey.title')} {nav} />
</div>
<p>{t('adminSystem.masterKey.intro')}</p>

{#if pageMessage !== undefined}
  <Alert severity="warning" ondismiss={() => (pageMessage = undefined)}>
    {renderMessage(pageMessage, t)}
  </Alert>
{/if}

{#if status === undefined}
  {#if loadError !== ''}
    <Alert severity="error">
      <p>{loadError}</p>
      <Button variant="secondary" onclick={() => void loadStatus()}>{t('common.retry')}</Button>
    </Alert>
  {:else}
    <Spinner />
  {/if}
{:else}
  <div class="tt-stack" aria-busy={loading ? 'true' : undefined}>
    {#if loadError !== ''}
      <Alert severity="error">
        <p>{loadError}</p>
        <Button variant="secondary" onclick={() => void loadStatus()}>{t('common.retry')}</Button>
      </Alert>
    {/if}

    <section aria-labelledby="{uid}-keys">
      <h2 id="{uid}-keys">{t('sysMasterKey.keys.title')}</h2>
      <dl class="tt-dl">
        <dt>{t('sysMasterKey.keys.active')}</dt>
        <dd><code>{status.activeKeyId}</code></dd>
        <dt>{t('sysMasterKey.keys.new')}</dt>
        <dd>
          {#if status.newKeyId !== undefined}
            <code>{status.newKeyId}</code>
          {:else}
            {t('sysMasterKey.keys.none')}
          {/if}
        </dd>
      </dl>
      {#if status.restartRequired}
        <p><StatusBadge variant="warning" label={t('sysMasterKey.keys.restartRequired')} /></p>
      {/if}
      <p class="tt-text-muted tt-text-sm">{t('sysMasterKey.keys.check')}</p>
    </section>

    {#if kind === 'noNewKey'}
      <section aria-labelledby="{uid}-prepare">
        <h2 id="{uid}-prepare">{t('sysMasterKey.prepare.title')}</h2>
        <p>{t('sysMasterKey.prepare.intro')}</p>
        <ol>
          <li>{t('sysMasterKey.prepare.step1')}</li>
          <li>{t('sysMasterKey.prepare.step2')}</li>
          <li>{t('sysMasterKey.prepare.step3')}</li>
        </ol>
        <p>{t('sysMasterKey.prepare.doc')} <code>{MASTER_KEY_DOC}</code></p>
      </section>
    {/if}

    {#if kind === 'restartRequired'}
      <section aria-labelledby="{uid}-done">
        <h2 id="{uid}-done">{t('sysMasterKey.done.title')}</h2>
        <Alert severity="success" live={false}>
          <p>{t('sysMasterKey.done.intro')}</p>
        </Alert>
        <ol>
          <li>{t('sysMasterKey.done.step1')}</li>
          <li>{t('sysMasterKey.done.step2')}</li>
          <li>{t('sysMasterKey.done.step3')}</li>
        </ol>
        <p>{t('sysMasterKey.done.effect')}</p>
        <p>{t('sysMasterKey.done.noStart')}</p>
        <p>{t('sysMasterKey.prepare.doc')} <code>{MASTER_KEY_DOC}</code></p>
      </section>
    {/if}

    {#if latest !== undefined && progress !== undefined}
      <section aria-labelledby={progressHeadingId}>
        <h2 id={progressHeadingId} tabindex="-1">{t('sysMasterKey.latest.title')}</h2>

        {#if kind === 'interrupted'}
          <Alert severity="warning" title={t('sysMasterKey.interrupted.title')}>
            <p>{t('sysMasterKey.interrupted.text')}</p>
          </Alert>
        {:else if kind === 'otherRotation'}
          <Alert severity="warning" live={false} title={t('sysMasterKey.other.title')}>
            <p>{t('sysMasterKey.other.text')}</p>
            <p>{t('sysMasterKey.prepare.doc')} <code>{MASTER_KEY_DOC}</code></p>
          </Alert>
        {:else if kind === 'failed'}
          <Alert severity="error" live={false} title={t('sysMasterKey.failed.title')}>
            {#if latest.error !== undefined && latest.error !== ''}
              <p>{t('sysMasterKey.failed.text')}</p>
              <p class="tt-masterkey__error">{latest.error}</p>
            {/if}
            <p>{t('sysMasterKey.failed.retry')}</p>
          </Alert>
        {/if}

        {#if latest.status === 'running'}
          <ProgressBar
            label={t('sysMasterKey.latest.progressLabel')}
            value={progress.percent}
            max={100}
            valueText={progressText(progress, t, (n) => formatNumber(n))}
          />
          {#if halt?.reason === 'idle' && halt.rotationId === latest.id}
            <Alert severity="info">
              <p>{t('sysMasterKey.poll.idle')}</p>
              <Button variant="secondary" onclick={resumePolling}>{t('sysMasterKey.poll.resume')}</Button>
            </Alert>
          {:else if halt?.reason === 'error' && halt.rotationId === latest.id}
            <Alert severity="warning">
              <p>{t('sysMasterKey.poll.stopped')}</p>
              <Button variant="secondary" onclick={resumePolling}>{t('common.retry')}</Button>
            </Alert>
          {:else if pollErrors > 0}
            <Alert severity="warning">{t('sysMasterKey.poll.error')}</Alert>
          {/if}
          {#if kind === 'running'}
            <p class="tt-text-muted tt-text-sm">{t('sysMasterKey.latest.leave')}</p>
          {/if}
        {/if}

        <dl class="tt-dl">
          <dt>{t('sysMasterKey.latest.id')}</dt>
          <dd><code>{latest.id}</code></dd>
          <dt>{t('sysMasterKey.latest.status')}</dt>
          <dd>
            <StatusBadge
              variant={rotationStatusVariant(latest.status)}
              label={t(rotationStatusKey(latest.status))}
            />
          </dd>
          <dt>{t('sysMasterKey.latest.from')}</dt>
          <dd><code>{latest.fromKeyId}</code></dd>
          <dt>{t('sysMasterKey.latest.to')}</dt>
          <dd><code>{latest.toKeyId}</code></dd>
          <dt>{t('sysMasterKey.latest.started')}</dt>
          <dd>{when(latest.startedAt)}</dd>
          {#if latest.completedAt !== undefined}
            <dt>{t('sysMasterKey.latest.completed')}</dt>
            <dd>{when(latest.completedAt)}</dd>
          {/if}
          {#if latest.status !== 'running'}
            <dt>{t('sysMasterKey.latest.progressLabel')}</dt>
            <dd>{progressText(progress, t, (n) => formatNumber(n))}</dd>
          {/if}
        </dl>
      </section>
    {/if}

    {#if kind !== undefined && canStart(kind)}
      <section aria-labelledby="{uid}-start">
        <h2 id="{uid}-start">{t(startLabelKey(kind))}</h2>
        <p>{t('sysMasterKey.start.intro')}</p>
        <Checkbox label={t('sysMasterKey.start.vault')} bind:checked={vaultCopy} />
        <Checkbox label={t('sysMasterKey.start.ids')} bind:checked={idsChecked} />
        {#if !ready}
          <p id={requiredId} class="tt-text-muted tt-text-sm">{t('sysMasterKey.start.required')}</p>
        {/if}
        <Button
          disabled={!ready || form.busy}
          aria-describedby={ready ? undefined : requiredId}
          onclick={openDialog}
        >
          {t(startLabelKey(kind))}
        </Button>
      </section>
    {/if}
  </div>
{/if}

<Dialog
  bind:open={dialogOpen}
  title={t('sysMasterKey.dialog.title')}
  beforeclose={() => !form.busy}
  onclose={onDialogClose}
>
  <p>{mode === 'totp' ? t('sysMasterKey.dialog.intro') : t('sysMasterKey.dialog.recoveryIntro')}</p>
  <p class="tt-text-muted tt-text-sm">{t('sysMasterKey.dialog.wait')}</p>
  <p class="tt-text-muted tt-text-sm">{t('sysMasterKey.dialog.session')}</p>
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
        bind:value={code}
      />
    {/if}
    <Button variant="link" disabled={form.busy} onclick={() => void switchMode()}>
      {mode === 'totp' ? t('adminAuth.totp.useRecovery') : t('adminAuth.totp.useTotp')}
    </Button>
    <div class="tt-cluster tt-masterkey__actions">
      <Button variant="secondary" disabled={form.busy} onclick={() => (dialogOpen = false)}>
        {t('sysMasterKey.dialog.cancel')}
      </Button>
      <Button
        type="submit"
        loading={form.busy}
        loadingLabel={t('sysMasterKey.dialog.submitting')}
        disabled={form.remaining > 0}
      >
        {t('sysMasterKey.dialog.submit')}
      </Button>
    </div>
  </form>
</Dialog>

<style>
  .tt-masterkey__error {
    overflow-wrap: anywhere;
    white-space: pre-wrap;
  }

  .tt-masterkey__actions {
    justify-content: flex-end;
  }
</style>
