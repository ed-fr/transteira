<script lang="ts">
  // Email step: the depositor gives an address; a code is sent (or, for a recognised internal
  // address, the session opens at once). Invited depositors use the invited address.
  import { Alert, Button, TextField } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import Countdown from './Countdown.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
  }

  let { flow }: Props = $props();
  let remaining = $state(0);

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void flow.submitEmail();
  }
</script>

<h1 tabindex="-1">{t('deposit.email.title')}</h1>

{#if flow.invitation}
  <p>{t('deposit.email.invitationIntro', { invitedBy: flow.invitation.invitedBy })}</p>
{:else}
  <p>{t('deposit.email.intro')}</p>
{/if}

{#if flow.notice}
  <Alert severity="info">{t(flow.notice.key, flow.notice.params)}</Alert>
{/if}

{#if flow.errorText}
  <Alert severity="error">{flow.errorText}</Alert>
{/if}

<form class="tt-stack" novalidate onsubmit={submit}>
  <TextField
    label={t('deposit.email.label')}
    type="email"
    autocomplete="email"
    spellcheck={false}
    required
    readonly={flow.invitation !== undefined}
    hint={flow.invitation ? t('deposit.email.invitationHint') : t('deposit.email.hint')}
    error={flow.fieldError ? t(flow.fieldError.key, flow.fieldError.params) : undefined}
    bind:value={flow.email}
  />
  <Countdown until={flow.retryAt} bind:remaining />
  <Button
    type="submit"
    loading={flow.busy}
    disabled={remaining > 0 || flow.invitationGone}
    loadingLabel={t('deposit.email.sending')}
  >
    {t('deposit.email.submit')}
  </Button>
</form>
