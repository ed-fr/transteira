<script lang="ts">
  // Confirmation that the activation link of an admin was mailed (since API 1.2). The API never
  // returns a mailed link, so there is nothing to copy: the panel shows the address, the end of
  // validity and the next steps. The heading takes the focus when the panel appears and the
  // message is announced through the shared live region.
  import { onMount } from 'svelte';
  import { Alert, Button, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Address the link was sent to. */
    email: string;
    /** End of validity of the link (ISO 8601). */
    expiresAt: string;
    /** The administrator must also configure two-factor authentication. */
    totpRequired?: boolean;
    /** Label of the button leaving the panel. */
    doneLabel: string;
    /** Level of the heading inside the page (default 2). */
    headingLevel?: 2 | 3;
    /** Called when the button is pressed. */
    ondone: () => void;
  }

  let { email, expiresAt, totpRequired = true, doneLabel, headingLevel = 2, ondone }: Props = $props();

  const uid = $props.id();
  let heading: HTMLElement | undefined = $state();
  const date = $derived.by(() => {
    const parsed = new Date(expiresAt);
    return Number.isNaN(parsed.getTime()) ? undefined : i18n.formatDate(parsed);
  });
  const text = $derived(
    date === undefined
      ? t('adminAccounts.invitation.sent.textNoDate', { email })
      : t('adminAccounts.invitation.sent.text', { email, date }),
  );

  onMount(() => {
    heading?.focus();
    announce(text);
  });
</script>

<section class="tt-card tt-mb-4" aria-labelledby="{uid}-title">
  <svelte:element
    this={`h${headingLevel}`}
    id="{uid}-title"
    tabindex="-1"
    bind:this={heading}
    class="tt-mt-0"
  >
    {t('adminAccounts.invitation.sent.title')}
  </svelte:element>
  <p>{text}</p>
  {#if totpRequired}
    <Alert severity="info" live={false}><p>{t('adminAccounts.invitation.sent.totp')}</p></Alert>
  {/if}
  <p>{t('adminAccounts.invitation.sent.notShown')}</p>
  <Button onclick={ondone}>{doneLabel}</Button>
</section>
