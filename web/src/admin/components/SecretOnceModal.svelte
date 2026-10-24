<script lang="ts">
  // Secret shown once (e.g. the value of a new API token), in a modal dialog built on the shared
  // Dialog and CopyButton (threat model T-162):
  // - the secret in a selectable monospace block, a copy button, and the warning that it will
  //   not be shown again;
  // - the Close button is enabled once the secret was copied successfully (CopyButton oncopy with
  //   a true result; a failed copy does not count) or the box "I have stored this
  //   secret" is ticked; until then the dialog cannot be dismissed (no header close button,
  //   Escape refused; should the browser close it anyway, it is reopened), leaving the page asks
  //   for a confirmation (router navigation guard) and the beforeunload warning is armed;
  // - the secret lives only in this component's state (a copy of the prop), cleared when the
  //   dialog closes and when the component goes away; it is never announced, logged, put in the
  //   URL or stored.
  //
  //   <SecretOnceModal bind:open={showSecret} title={createdTitle} secret={created.token}
  //                    addGuard={(g) => nav.addGuard(g)} onclose={() => (created = undefined)} />
  import { onDestroy, tick, untrack } from 'svelte';
  import { Alert, Button, Checkbox, CopyButton, Dialog } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { AddGuard } from '../screens/types';
  import { activationBeforeUnload, activationLeaveGuard } from './activationLink';
  import {
    canDismissSecret,
    copiedAfter,
    secretCancelGuard,
    secretLeaveMessage,
    secretPending,
  } from './secretOnce';

  interface Props {
    /** Bound open state. */
    open?: boolean;
    /** Title of the dialog. */
    title: string;
    /** The secret, shown once. */
    secret: string;
    /** Explanation shown before the secret (default: generic "copy it now" text). */
    text?: string;
    /** Label of the secret block (default "Secret"). */
    secretLabel?: string;
    /** Registers a navigation guard and returns its removal (router.addGuard). */
    addGuard?: AddGuard | undefined;
    /** Asks the user to confirm leaving (default window.confirm). */
    confirmLeave?: (message: string) => boolean;
    /** Called after the dialog closed (the secret is already cleared). */
    onclose?: () => void;
  }

  let {
    open = $bindable(false),
    title,
    secret,
    text,
    secretLabel,
    addGuard,
    confirmLeave,
    onclose,
  }: Props = $props();

  const uid = $props.id();
  // Local copy of the secret, cleared on close and on destroy.
  let value = $state(untrack(() => secret));
  let acknowledged = $state(false);
  let copied = $state(false);
  let closing = false;

  const dismissable = $derived(canDismissSecret(acknowledged, copied));
  const pending = (): boolean => open && secretPending(value, acknowledged, copied);
  const ask = (message: string): boolean => (confirmLeave ?? ((m: string) => window.confirm(m)))(message);
  const onBeforeUnload = activationBeforeUnload(pending);
  const onCancel = secretCancelGuard(pending);

  // Opening with a new secret (another token created while mounted) restarts the
  // acknowledgement; the local copy is otherwise left cleared once closed.
  $effect.pre(() => {
    const next = secret;
    const shown = open;
    untrack(() => {
      if (shown && next !== '' && next !== value) {
        value = next;
        acknowledged = false;
        copied = false;
      }
    });
  });

  // The guard stays registered while the secret is shown and not dismissable.
  $effect(() => {
    if (!open || dismissable || addGuard === undefined) {
      return;
    }
    return addGuard(activationLeaveGuard(pending, ask, secretLeaveMessage(t)));
  });

  function close(): void {
    if (!dismissable) {
      return;
    }
    closing = true;
    open = false;
  }

  async function handleClose(): Promise<void> {
    if (!closing && secretPending(value, acknowledged, copied)) {
      // Closed by the browser despite the refused cancel (e.g. repeated Escape): reopen.
      await tick();
      open = true;
      return;
    }
    closing = false;
    value = '';
    onclose?.();
  }

  onDestroy(() => {
    value = '';
    acknowledged = true;
  });
</script>

<svelte:window onbeforeunload={onBeforeUnload} />

<!-- The native cancel event (Escape) does not bubble: it is caught in the capture phase. -->
<div class="tt-secret-once" oncancelcapture={onCancel}>
  <Dialog bind:open {title} hideCloseButton onclose={handleClose}>
    <p>{text ?? t('adminComponents.secretOnce.text')}</p>
    <Alert severity="warning" live={false}>
      <p class="tt-text-bold">{t('adminComponents.secretOnce.shownOnce')}</p>
    </Alert>
    <p class="tt-secret-once__label">{secretLabel ?? t('adminComponents.secretOnce.label')}</p>
    <code class="tt-secret-once__value">{value}</code>
    <!-- Only a successful copy counts; a failure is shown by the button itself. -->
    <div class="tt-secret-once__copy">
      <CopyButton
        text={value}
        label={t('adminComponents.secretOnce.copy')}
        oncopy={(ok) => {
          copied = copiedAfter(copied, ok);
        }}
      />
    </div>
    <Checkbox
      id="{uid}-ack"
      label={t('adminComponents.secretOnce.acknowledge')}
      bind:checked={acknowledged}
    />
    {#snippet actions()}
      <p class="tt-secret-once__reason" id="{uid}-reason" hidden={dismissable}>
        {t('adminComponents.secretOnce.closeDisabled')}
      </p>
      <Button
        onclick={close}
        disabled={!dismissable}
        aria-describedby={dismissable ? undefined : `${uid}-reason`}
      >
        {t('adminComponents.secretOnce.close')}
      </Button>
    {/snippet}
  </Dialog>
</div>

<style>
  .tt-secret-once {
    display: contents;
  }

  .tt-secret-once__label {
    margin: var(--tt-space-4) 0 var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-secret-once__value {
    display: block;
    padding: var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
    font-family: var(--tt-font-mono);
    word-break: break-all;
    user-select: all;
  }

  .tt-secret-once__copy {
    margin: var(--tt-space-2) 0 var(--tt-space-4);
  }

  .tt-secret-once__reason {
    flex-basis: 100%;
    margin: 0;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    text-align: right;
  }
</style>
