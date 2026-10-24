<script lang="ts">
  // Single-use activation link of an admin account, shown once after createAdmin or
  // resetAdminCredentials (threat model T-162):
  // - read-only field with the link, copy button, expiry date;
  // - warnings: shown only once, not sent by any email, to hand over through another channel;
  // - until "I have handed over the link" is pressed, leaving the page asks for a confirmation
  //   (router navigation guard and beforeunload warning);
  // - the link lives only in this component's state (a copy of the prop), cleared when the
  //   panel goes away; it is never announced, logged, put in the URL or stored. The heading
  //   takes the focus when the panel appears, so that screen readers start from it.
  //
  //   {#if link}
  //     <ActivationLinkPanel {link} username={account.username} addGuard={(g) => nav.addGuard(g)}
  //                          ondone={() => (link = undefined)} />
  //   {/if}
  import { onDestroy, onMount, untrack } from 'svelte';
  import { Alert, Button, CopyButton, TextField } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { activationBeforeUnload, activationLeaveGuard, expiryText, leaveMessage } from './activationLink';
  import type { AddGuard } from '../screens/types';

  interface Props {
    /** The link and its expiry (ISO 8601). */
    link: { url: string; expiresAt: string };
    /** Username of the account, named in the introduction. */
    username: string;
    /** Level of the heading inside the page (default 2). */
    headingLevel?: 2 | 3;
    /** Registers a navigation guard and returns its removal (router.addGuard). */
    addGuard?: AddGuard | undefined;
    /** Asks the user to confirm leaving (default window.confirm). */
    confirmLeave?: (message: string) => boolean;
    /** Called once the admin acknowledged the link (the guards are released first). */
    ondone: () => void;
  }

  let { link, username, headingLevel = 2, addGuard, confirmLeave, ondone }: Props = $props();

  const uid = $props.id();
  const inputId = `${uid}-url`;
  // Local copy of the secret, cleared on destroy.
  let url = $state(untrack(() => link.url));
  const expiresAt = untrack(() => link.expiresAt);
  let acknowledged = $state(false);
  let heading: HTMLElement | undefined = $state();

  const pending = (): boolean => !acknowledged && url !== '';
  const ask = (message: string): boolean => (confirmLeave ?? ((m: string) => window.confirm(m)))(message);
  const onBeforeUnload = activationBeforeUnload(pending);
  const expiry = $derived(expiryText(expiresAt, (d) => i18n.formatDate(d), t));

  // The guard stays registered while the link is shown and not acknowledged.
  $effect(() => {
    if (acknowledged || addGuard === undefined) {
      return;
    }
    return addGuard(activationLeaveGuard(pending, ask, leaveMessage(t)));
  });

  function done(): void {
    acknowledged = true;
    ondone();
  }

  onMount(() => {
    heading?.focus();
  });

  onDestroy(() => {
    url = '';
    acknowledged = true;
  });
</script>

<svelte:window onbeforeunload={onBeforeUnload} />

<section class="tt-activation tt-card" aria-labelledby="{uid}-title">
  <svelte:element
    this={`h${headingLevel}`}
    id="{uid}-title"
    tabindex="-1"
    bind:this={heading}
    class="tt-mt-0"
  >
    {t('adminAccounts.activationLink.title')}
  </svelte:element>
  <p>{t('adminAccounts.activationLink.intro', { username })}</p>
  <Alert severity="warning" live={false}>
    <p class="tt-text-bold">{t('adminAccounts.activationLink.shownOnce')}</p>
    <p>{t('adminAccounts.activationLink.warning')}</p>
  </Alert>

  <div class="tt-activation__field">
    <TextField
      id={inputId}
      label={t('adminAccounts.activationLink.label')}
      value={url}
      readonly
      autocomplete="off"
      spellcheck="false"
      hint={expiry}
      onfocus={(event) => event.currentTarget.select()}
    />
  </div>
  <div class="tt-cluster tt-mb-4">
    <CopyButton text={url} label={t('adminAccounts.activationLink.copy')} />
    <Button onclick={done}>{t('adminAccounts.activationLink.done')}</Button>
  </div>
</section>

<style>
  .tt-activation {
    margin-bottom: var(--tt-space-6);
  }

  .tt-activation__field {
    margin: var(--tt-space-4) 0 var(--tt-space-3);
  }
</style>
