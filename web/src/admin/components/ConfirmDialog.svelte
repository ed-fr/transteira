<script lang="ts">
  // Confirmation dialog on the shared Dialog (native modal, Escape closes, focus returned to
  // the opener). With confirmText, the confirm button stays disabled until the text is typed
  // exactly (e.g. the name of an entity before its deletion); the reason is linked to the
  // button and to the field by aria-describedby. While onconfirm runs, the button is busy;
  // a returned string is shown as an error and the dialog stays open, otherwise it closes.
  //
  //   <ConfirmDialog bind:open title={text} text={text} danger
  //                  confirmLabel={t('admin.common.delete')} confirmText={tenant.name}
  //                  onconfirm={remove} />
  import type { Snippet } from 'svelte';
  import Alert from '../../shared/components/Alert.svelte';
  import Button from '../../shared/components/Button.svelte';
  import Dialog from '../../shared/components/Dialog.svelte';
  import TextField from '../../shared/components/TextField.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { confirmTextMatches } from './fields';

  interface Props {
    /** Bound open state. */
    open?: boolean;
    /** Title (accessible name of the dialog). */
    title: string;
    /** Explanation shown in the dialog. */
    text?: string;
    /** Richer content, shown after text. */
    children?: Snippet;
    /** Label of the confirm button (default "Confirm"). */
    confirmLabel?: string;
    /** Label of the confirm button while busy (default "Please wait…"). */
    busyLabel?: string;
    /** Label of the cancel button (default "Cancel"). */
    cancelLabel?: string;
    /** Destructive action: the confirm button uses the danger style. */
    danger?: boolean;
    /** Text the user must type exactly to enable the confirm button. */
    confirmText?: string;
    /**
     * Runs the action. A returned (or resolved) string is an error message: the dialog stays
     * open and shows it. Otherwise the dialog closes.
     */
    onconfirm: () => Promise<string | void> | string | void;
    /** Called after the dialog closed, confirmed or not. */
    onclose?: () => void;
  }

  let {
    open = $bindable(false),
    title,
    text,
    children,
    confirmLabel,
    busyLabel,
    cancelLabel,
    danger = false,
    confirmText,
    onconfirm,
    onclose,
  }: Props = $props();

  const uid = $props.id();
  const inputId = `${uid}-typed`;
  // The reason is the hint of the field (TextField links it to the input as <id>-hint).
  const reasonId = `${inputId}-hint`;
  let typed = $state('');
  let busy = $state(false);
  let error = $state('');

  const requiresText = $derived(confirmText !== undefined && confirmText !== '');
  const matches = $derived(confirmTextMatches(typed, confirmText));

  // A new opening starts from a blank state.
  $effect(() => {
    if (open) {
      typed = '';
      error = '';
      busy = false;
    }
  });

  async function confirm(): Promise<void> {
    if (!matches || busy) {
      return;
    }
    busy = true;
    error = '';
    try {
      const result = await onconfirm();
      if (typeof result === 'string' && result !== '') {
        error = result;
        return;
      }
      open = false;
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open {title} {onclose} hideCloseButton={busy}>
  {#if text}<p>{text}</p>{/if}
  {#if children}{@render children()}{/if}
  {#if requiresText}
    <TextField
      id={inputId}
      label={t('adminComponents.confirm.typeLabel')}
      hint={t('adminComponents.confirm.typeToConfirm', { text: confirmText ?? '' })}
      bind:value={typed}
      autocomplete="off"
      spellcheck={false}
    />
  {/if}
  {#if error !== ''}
    <Alert severity="error">{error}</Alert>
  {/if}
  {#snippet actions()}
    <Button
      variant="secondary"
      disabled={busy}
      onclick={() => {
        open = false;
      }}
    >
      {cancelLabel ?? t('admin.common.cancel')}
    </Button>
    <Button
      variant={danger ? 'danger' : 'primary'}
      disabled={!matches}
      loading={busy}
      loadingLabel={busyLabel}
      aria-describedby={requiresText && !matches ? reasonId : undefined}
      onclick={confirm}
    >
      {confirmLabel ?? t('admin.common.confirm')}
    </Button>
  {/snippet}
</Dialog>
