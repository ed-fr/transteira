<script lang="ts">
  // Recovery codes, shown once after a TOTP confirmation (threat model T-162): ordered list in a
  // monospace font, "copy all", download as a .txt file (Blob object URL clicked through an
  // <a download> link, then revoked), and a required acknowledgement before continuing.
  //
  // The codes only live in the codes prop (memory). The announcement says that the codes are
  // displayed without reading them; nothing is written to storage or to the URL.
  //
  // Until the acknowledgement box is ticked, leaving the page asks for a confirmation: the
  // router navigation guard (addGuard, in-app links, back and forward) and the beforeunload
  // warning (reload, closing the tab, another address), the same pattern as
  // ActivationLinkPanel. During sign-in, first-run setup and activation, a reload would restore
  // the session already opened on the server without showing these codes again, so the
  // beforeunload warning is the only protection there; forced redirects (session expired,
  // signed out) bypass the guard on purpose.
  import { onMount, tick } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, Button, Checkbox, CopyButton, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import {
    browserDownloadEnvironment,
    downloadText,
    recoveryCodesClipboard,
    recoveryCodesText,
    recoveryLeaveMessage,
  } from '../auth/views';
  import type { AddGuard } from '../screens/types';
  import { activationBeforeUnload, activationLeaveGuard } from './activationLink';

  interface Props {
    /** Single-use recovery codes. */
    codes: readonly string[];
    /** Username written in the header of the text file, when known. */
    username?: string | undefined;
    /** Level of the heading: 1 for a step of its own, 2 or 3 inside a page. */
    headingLevel?: 1 | 2 | 3;
    /** Registers a navigation guard and returns its removal (router.addGuard). */
    addGuard?: AddGuard | undefined;
    /** Asks the user to confirm leaving (default window.confirm). */
    confirmLeave?: (message: string) => boolean;
    /** Called once the admin confirmed having saved the codes; a rejection is shown. */
    oncontinue: () => Promise<void> | void;
  }

  let { codes, username, headingLevel = 1, addGuard, confirmLeave, oncontinue }: Props = $props();

  const uid = $props.id();
  const checkboxId = `${uid}-ack`;
  let acknowledged = $state(false);
  let ackError = $state<string | undefined>(undefined);
  let error = $state('');
  let busy = $state(false);
  let heading: HTMLElement | undefined = $state();

  const pending = (): boolean => !acknowledged;
  const ask = (message: string): boolean => (confirmLeave ?? ((m: string) => window.confirm(m)))(message);
  const onBeforeUnload = activationBeforeUnload(pending);

  // The guard stays registered until the acknowledgement box is ticked.
  $effect(() => {
    if (acknowledged || addGuard === undefined) {
      return;
    }
    return addGuard(activationLeaveGuard(pending, ask, recoveryLeaveMessage(t)));
  });

  function download(): void {
    const header =
      username === undefined || username === ''
        ? t('adminAuth.recovery.fileHeaderGeneric')
        : t('adminAuth.recovery.fileHeader', { username });
    downloadText(
      t('adminAuth.recovery.fileName'),
      recoveryCodesText(codes, header),
      browserDownloadEnvironment(),
    );
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy) {
      return;
    }
    error = '';
    if (!acknowledged) {
      ackError = t('adminAuth.recovery.acknowledgeRequired');
      await tick();
      document.getElementById(checkboxId)?.focus();
      return;
    }
    ackError = undefined;
    busy = true;
    try {
      await oncontinue();
    } catch (err) {
      error = describeError(i18n, err).message;
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    heading?.focus();
    announce(t('adminAuth.recovery.announced'));
  });
</script>

<svelte:window onbeforeunload={onBeforeUnload} />

<section aria-labelledby="{uid}-title">
  <svelte:element this={`h${headingLevel}`} id="{uid}-title" tabindex="-1" bind:this={heading}>
    {t('adminAuth.recovery.title')}
  </svelte:element>
  <p>{t('adminAuth.recovery.intro')}</p>
  <Alert severity="warning" live={false}>
    <p>{t('adminAuth.recovery.shownOnce')}</p>
  </Alert>

  <p class="tt-text-bold tt-mb-2" id="{uid}-list">{t('adminAuth.recovery.listLabel')}</p>
  <ol class="tt-recovery__list tt-mono" aria-labelledby="{uid}-list">
    {#each codes as code, index (index)}
      <li>{code}</li>
    {/each}
  </ol>
  <div class="tt-cluster tt-mb-4">
    <CopyButton text={recoveryCodesClipboard(codes)} label={t('adminAuth.recovery.copyAll')} />
    <Button variant="secondary" onclick={download}>{t('adminAuth.recovery.download')}</Button>
  </div>

  {#if error !== ''}
    <Alert severity="error">{error}</Alert>
  {/if}
  <form class="tt-stack" novalidate onsubmit={submit}>
    <Checkbox
      id={checkboxId}
      label={t('adminAuth.recovery.acknowledge')}
      required
      error={ackError}
      bind:checked={acknowledged}
    />
    <div>
      <Button type="submit" loading={busy}>{t('adminAuth.recovery.continue')}</Button>
    </div>
  </form>
</section>

<style>
  .tt-recovery__list {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
    gap: var(--tt-space-2) var(--tt-space-6);
    margin: 0 0 var(--tt-space-4);
    padding-left: var(--tt-space-6);
    font-size: var(--tt-font-size-lg);
  }
</style>
