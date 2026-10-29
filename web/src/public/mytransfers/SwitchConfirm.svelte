<script lang="ts">
  // Confirmation asked when an access link is opened while a "My transfers" session is already
  // active: a page could make the browser open /me#mta_... with a link of another address (login
  // CSRF), so the session is never replaced without the sender's consent.
  import { onMount } from 'svelte';
  import { Button } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Address of the active session. */
    email: string;
    /** Opens the link, replacing the active session. */
    onswitch: () => void;
    /** Keeps the active session and drops the link. */
    onstay: () => void;
  }

  let { email, onswitch, onstay }: Props = $props();
  let heading: HTMLElement | undefined = $state();

  onMount(() => heading?.focus());
</script>

<h1 tabindex="-1" bind:this={heading}>{t('myTransfers.switch.title')}</h1>
<p>{t('myTransfers.switch.text', { email })}</p>
<p class="tt-text-muted tt-text-sm">{t('myTransfers.switch.hint')}</p>
<div class="tt-cluster">
  <Button onclick={onswitch}>{t('myTransfers.switch.confirm')}</Button>
  <Button variant="secondary" onclick={onstay}>{t('myTransfers.switch.stay', { email })}</Button>
</div>
