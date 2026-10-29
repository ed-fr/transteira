<script lang="ts">
  // Identity of the depositor, link to invite an external person (internal sessions allowed to
  // invite) and the "End session" action.
  import { Button } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
    /** In-app navigation (the public router); a normal link is followed when absent. */
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, onnavigate }: Props = $props();

  function invite(event: MouseEvent): void {
    if (
      onnavigate !== undefined &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.shiftKey &&
      event.button === 0
    ) {
      event.preventDefault();
      onnavigate('/invite');
    }
  }
</script>

{#if flow.session}
  <div class="tt-cluster tt-cluster--between tt-text-sm">
    <p class="tt-mb-0 tt-break">{t('deposit.session.as', { email: flow.session.email })}</p>
    <div class="tt-cluster">
      {#if flow.canInvite}
        <a href="/invite" onclick={invite}>{t('deposit.session.invite')}</a>
      {/if}
      <Button variant="link" small disabled={flow.busy} onclick={() => void flow.endSession()}>
        {t('deposit.session.end')}
      </Button>
    </div>
  </div>
  {#if flow.isRemoteSession}
    <p class="tt-text-muted tt-text-sm">{t('deposit.session.remote')}</p>
  {/if}
{/if}
