<script lang="ts">
  // Header of the download page (CLAUDE.md section 13.2): a round avatar with the initial of the
  // sender (decorative, aria-hidden), the page title (h1, focused by the router and after an
  // unlock or a decryption) and "Sent by" followed by the sender address in its own element.
  //
  // Props:
  //   title        text of the h1 ("3 files for you", "Password required")
  //   senderEmail  verified address of the sender
  //   element      the h1 element (bindable), for focus management
  import { t } from '../../../shared/i18n/i18n.svelte';
  import { senderInitial } from '../outcomes';

  interface Props {
    /** Text of the h1. */
    title: string;
    /** Verified address of the sender. */
    senderEmail: string;
    /** The h1 element, for focus management. */
    element?: HTMLHeadingElement | undefined;
  }

  let { title, senderEmail, element = $bindable() }: Props = $props();
  const initial = $derived(senderInitial(senderEmail));
</script>

<div class="tt-dlhead">
  {#if initial !== ''}
    <span class="tt-dlhead__avatar" aria-hidden="true">{initial}</span>
  {/if}
  <div class="tt-dlhead__text">
    <h1 class="tt-dlhead__title" tabindex="-1" bind:this={element}>{title}</h1>
    <p class="tt-dlhead__sender">
      {t('download.sender')} <span class="tt-dlhead__email">{senderEmail}</span>
    </p>
  </div>
</div>

<style>
  .tt-dlhead {
    display: flex;
    align-items: center;
    gap: var(--tt-space-4);
  }

  .tt-dlhead__avatar {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 3.5rem;
    height: 3.5rem;
    border-radius: var(--tt-radius-full);
    background: var(--tt-chip-bg);
    color: var(--tt-chip-text);
    font-size: var(--tt-font-size-xl);
    font-weight: var(--tt-font-weight-bold);
    line-height: 1;
  }

  .tt-dlhead__text {
    min-width: 0;
  }

  .tt-dlhead__title {
    margin: 0 0 var(--tt-space-1);
    font-size: var(--tt-font-size-2xl);
  }

  .tt-dlhead__sender {
    margin: 0;
    color: var(--tt-text-muted);
    overflow-wrap: anywhere;
  }

  .tt-dlhead__email {
    color: var(--tt-text);
    font-weight: var(--tt-font-weight-bold);
  }

  @media (max-width: 40rem) {
    .tt-dlhead {
      gap: var(--tt-space-3);
    }

    .tt-dlhead__avatar {
      width: 2.75rem;
      height: 2.75rem;
      font-size: var(--tt-font-size-lg);
    }

    .tt-dlhead__title {
      font-size: var(--tt-font-size-xl);
    }
  }

  @media (forced-colors: active) {
    .tt-dlhead__avatar {
      border: var(--tt-border-width) solid CanvasText;
    }
  }
</style>
