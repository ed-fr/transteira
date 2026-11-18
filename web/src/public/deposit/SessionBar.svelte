<script lang="ts">
  // Identity of the depositor, link to invite an external person (internal sessions allowed to
  // invite) and the way to end the session.
  //
  // Variants:
  //   'bar'    (default, done step) a line "Identified as <address>", the invite link and the
  //            "End session" button
  //   'strip'  the "From" block of the deposit form (CLAUDE.md section 13.2): a success strip with
  //            a check mark and the verified address in its own element (read "Identified as
  //            <address>"), and a "Change" button drawn as a link, which ends the session (its
  //            accessible name says so: "Change address (ends the session)"); the invite link and
  //            the remote deposit note under it. Its colours are the success status ones (never
  //            the tenant's), text AA on the success tint in both themes.
  import { Button, Icon } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';

  interface Props {
    flow: DepositFlow;
    /** In-app navigation (the public router); a normal link is followed when absent. */
    onnavigate?: ((path: string) => void) | undefined;
    /** Look: a line (done step) or the "From" strip of the form. */
    variant?: 'bar' | 'strip';
  }

  let { flow, onnavigate, variant = 'bar' }: Props = $props();

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
  {#if variant === 'strip'}
    <div class="tt-from" role="group" aria-labelledby="tt-deposit-from-label">
      <p class="tt-from__label" id="tt-deposit-from-label">{t('deposit.form.from.label')}</p>
      <div class="tt-from__strip">
        <p class="tt-from__identity">
          <Icon name="check" />
          <span class="visually-hidden">{`${t('deposit.form.from.identified')} `}</span>
          <span class="tt-from__email">{flow.session.email}</span>
        </p>
        <button
          type="button"
          class="tt-from__change"
          disabled={flow.busy}
          onclick={() => void flow.endSession()}
        >
          {t('deposit.form.from.change')}<span class="visually-hidden"
            >{` ${t('deposit.form.from.changeDetail')}`}</span
          >
        </button>
      </div>
      {#if flow.canInvite}
        <p class="tt-from__more">
          <a class="tt-session__invite" href="/invite" onclick={invite}>{t('deposit.session.invite')}</a>
        </p>
      {/if}
      {#if flow.isRemoteSession}
        <p class="tt-from__more tt-text-muted">{t('deposit.session.remote')}</p>
      {/if}
    </div>
  {:else}
    <div class="tt-cluster tt-cluster--between tt-text-sm">
      <p class="tt-mb-0 tt-break">{t('deposit.session.as', { email: flow.session.email })}</p>
      <div class="tt-cluster">
        {#if flow.canInvite}
          <a class="tt-session__invite" href="/invite" onclick={invite}>{t('deposit.session.invite')}</a>
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
{/if}

<style>
  .tt-from__label {
    margin: 0 0 var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-from__strip {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0 var(--tt-space-3);
    min-height: var(--tt-control-height);
    padding: 0 var(--tt-space-1) 0 var(--tt-space-3);
    border: var(--tt-border-width) solid transparent;
    border-radius: var(--tt-radius);
    background: var(--tt-success-bg);
    color: var(--tt-success);
  }

  .tt-from__identity {
    display: flex;
    align-items: center;
    gap: var(--tt-space-2);
    min-width: 0;
    margin: 0;
    padding: var(--tt-space-2) 0;
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-from__email {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  /* A button drawn as a link, in the status colour of the strip (AA on its tint). */
  .tt-from__change {
    min-width: var(--tt-control-height);
    min-height: var(--tt-control-height);
    margin-left: auto;
    padding: var(--tt-space-1) var(--tt-space-2);
    border: 0;
    border-radius: var(--tt-radius-sm);
    background: none;
    color: inherit;
    font: inherit;
    font-size: var(--tt-font-size-sm);
    text-decoration: underline;
    text-underline-offset: 0.2em;
    cursor: pointer;
  }

  .tt-from__change:hover:not(:disabled) {
    text-decoration-thickness: 2px;
  }

  .tt-from__change:disabled {
    cursor: not-allowed;
    opacity: 0.65;
  }

  /* A 44 px target on its own line (public pages). */
  .tt-session__invite {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
  }

  .tt-from__more {
    margin: var(--tt-space-1) 0 0;
    font-size: var(--tt-font-size-sm);
  }

  /* Forced colours: the tint is dropped, the border keeps the strip visible. */
  @media (forced-colors: active) {
    .tt-from__strip {
      border-color: CanvasText;
    }
  }
</style>
