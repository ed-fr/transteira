<script lang="ts">
  // Modal dialog on the native <dialog> element: showModal() makes the rest of the page inert
  // (focus trap) and moves the focus inside; Escape closes it (native cancel); on close, the
  // focus returns to the element that had it before opening.
  import type { Snippet } from 'svelte';
  import { t } from '../i18n/i18n.svelte';
  import { isFocusable } from './helpers';

  interface Props {
    /** Bound open state. */
    open?: boolean;
    /** Title of the dialog (its accessible name). */
    title: string;
    /** Called after the dialog closed (Escape, close button or open set to false). */
    onclose?: () => void;
    /** Hides the close button of the header (the actions must then offer a way out). */
    hideCloseButton?: boolean;
    /** Content. */
    children: Snippet;
    /** Buttons at the bottom of the dialog. */
    actions?: Snippet;
    class?: string;
  }

  let {
    open = $bindable(false),
    title,
    onclose,
    hideCloseButton = false,
    children,
    actions,
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  let dialog: HTMLDialogElement | undefined = $state();
  let returnFocus: unknown = null;

  $effect(() => {
    if (dialog === undefined) {
      return;
    }
    if (open && !dialog.open) {
      returnFocus = document.activeElement;
      dialog.showModal();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  });

  function handleClose(): void {
    open = false;
    const target = returnFocus;
    returnFocus = null;
    if (isFocusable(target)) {
      target.focus();
    }
    onclose?.();
  }
</script>

<dialog bind:this={dialog} class="tt-dialog {className}" aria-labelledby="{uid}-title" onclose={handleClose}>
  <div class="tt-dialog__header">
    <h2 class="tt-dialog__title" id="{uid}-title">{title}</h2>
    {#if !hideCloseButton}
      <button
        type="button"
        class="tt-dialog__close"
        aria-label={t('components.dialog.close')}
        onclick={() => {
          open = false;
        }}
      >
        <span aria-hidden="true">×</span>
      </button>
    {/if}
  </div>
  <div class="tt-dialog__body">
    {@render children()}
  </div>
  {#if actions}
    <div class="tt-dialog__actions">
      {@render actions()}
    </div>
  {/if}
</dialog>

<style>
  .tt-dialog {
    width: min(32rem, calc(100vw - 2rem));
    max-height: calc(100vh - 2rem);
    padding: var(--tt-space-6);
    border: 0;
    border-radius: var(--tt-radius-lg);
    background: var(--tt-surface);
    color: var(--tt-text);
    box-shadow: var(--tt-shadow);
  }

  .tt-dialog::backdrop {
    background: var(--tt-veil);
  }

  .tt-dialog__header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--tt-space-4);
    margin-bottom: var(--tt-space-4);
  }

  .tt-dialog__title {
    margin: 0;
    font-size: var(--tt-font-size-xl);
  }

  .tt-dialog__close {
    flex: none;
    width: 2.25rem;
    height: 2.25rem;
    padding: 0;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
    color: var(--tt-text);
    font-size: var(--tt-font-size-lg);
    line-height: 1;
    cursor: pointer;
  }

  .tt-dialog__actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: var(--tt-space-3);
    margin-top: var(--tt-space-6);
  }
</style>
