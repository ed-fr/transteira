<script lang="ts">
  // Text of a revealed secret (V2.1, and the express secrets of 2.3): always rendered as plain
  // text, the value of a read-only text area, never as HTML or Markdown, and a URL in it is never
  // made clickable (threat model T-397, decision P88; RevealedText.test.ts checks it). It can be
  // hidden from the screen and copied, with a clipboard warning.
  import { Button, CopyButton, TextArea } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** The decrypted text, not empty. */
    text: string;
  }

  let { text }: Props = $props();
  let hidden = $state(false);
</script>

{#if hidden}
  <p id="tt-secret-text-hidden">{t('secret.reveal.revealed.hidden')}</p>
{:else}
  <TextArea
    id="tt-secret-text"
    class="secret-text"
    label={t('secret.reveal.revealed.text')}
    value={text}
    readonly
    rows={8}
    spellcheck={false}
    autocomplete="off"
  />
{/if}
<div class="tt-cluster">
  <Button variant="secondary" aria-pressed={hidden} onclick={() => (hidden = !hidden)}>
    {t('secret.reveal.revealed.hide')}
  </Button>
  <CopyButton {text} label={t('secret.reveal.revealed.copy')} />
</div>
<p class="tt-text-sm tt-text-muted">{t('secret.reveal.revealed.clipboard')}</p>

<style>
  :global(.secret-text .tt-field__input) {
    font-family: var(--tt-font-mono);
    white-space: pre-wrap;
  }
</style>
