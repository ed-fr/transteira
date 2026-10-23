<script lang="ts">
  // Code step: the 6-digit code sent by mail (CLAUDE.md section 7: valid 15 minutes, 2 wrong
  // attempts). The page is not left: the code is typed here. No maxlength: a pasted "123 456" is
  // kept whole, the flow strips the spaces before checking the 6 digits.
  import { Alert, Button, TextField } from '../../shared/components';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import Countdown from './Countdown.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
  }

  let { flow }: Props = $props();
  let remaining = $state(0);

  const email = $derived(flow.challenge?.email ?? flow.email);
  const expires = $derived(
    flow.challenge ? formatDate(flow.challenge.expiresAt, { hour: '2-digit', minute: '2-digit' }) : '',
  );
  const fieldText = $derived.by(() => {
    if (flow.fieldError === undefined) {
      return undefined;
    }
    const base = t(flow.fieldError.key, flow.fieldError.params);
    return flow.attemptsRemaining === undefined
      ? base
      : `${base} ${t('common.attemptsRemaining', { count: flow.attemptsRemaining })}`;
  });

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void flow.submitCode();
  }
</script>

<h1 tabindex="-1">{t('deposit.code.title')}</h1>

<p class="tt-break">{t('deposit.code.intro', { email })}</p>
{#if expires !== ''}
  <p class="tt-text-muted tt-text-sm">{t('deposit.code.expires', { time: expires })}</p>
{/if}

{#if flow.notice}
  <Alert severity="info">{t(flow.notice.key, flow.notice.params)}</Alert>
{/if}

{#if flow.errorText}
  <Alert severity="error">{flow.errorText}</Alert>
{/if}

<form class="tt-stack" novalidate onsubmit={submit}>
  <TextField
    label={t('deposit.code.label')}
    inputmode="numeric"
    autocomplete="one-time-code"
    pattern="[0-9]*"
    spellcheck={false}
    required
    hint={t('deposit.code.hint')}
    error={fieldText}
    bind:value={flow.code}
  />
  <Countdown until={flow.retryAt} bind:remaining />
  <div class="tt-cluster">
    <Button type="submit" loading={flow.busy} disabled={remaining > 0}>{t('deposit.code.submit')}</Button>
    <Button variant="secondary" disabled={flow.busy || remaining > 0} onclick={() => void flow.resendCode()}>
      {t('deposit.code.resend')}
    </Button>
    {#if !flow.invitation}
      <Button variant="link" disabled={flow.busy} onclick={() => flow.changeEmail()}>
        {t('deposit.code.changeEmail')}
      </Button>
    {/if}
  </div>
</form>
