<script lang="ts">
  // Abbreviated SHA-256 fingerprint (CLAUDE.md sections 10 and 13.2): shows the first and last
  // characters ("9f2c1a2b…77bda41e", monospace) after a "SHA-256" label, with a Copy button that
  // copies the full value. The full fingerprint stays available: read by screen readers (visually
  // hidden text; the abbreviated text is aria-hidden), shown on hover (title) and copied by the
  // button, whose accessible name names the file ("Copy the SHA-256 fingerprint of report.pdf",
  // starting with its visible label "Copy").
  //
  // Props:
  //   hash        full hexadecimal fingerprint
  //   name        file name, for the accessible name of the Copy button
  //   label       text before the value (default "SHA-256"; "" for none)
  //   copyLabel   accessible name of the Copy button, instead of the default built from name
  //   copy        shows the Copy button (default true)
  //   head, tail  characters kept at each end (default 8 and 8)
  import { t } from '../i18n/i18n.svelte';
  import CopyButton from './CopyButton.svelte';
  import { abbreviateHash } from './helpers';

  interface Props {
    /** Full hexadecimal fingerprint. */
    hash: string;
    /** File name (accessible name of the Copy button). */
    name: string;
    /** Text before the value; "SHA-256" by default, "" for none. */
    label?: string;
    /** Accessible name of the Copy button. */
    copyLabel?: string | undefined;
    /** Shows the Copy button. */
    copy?: boolean;
    /** Characters kept at the start. */
    head?: number;
    /** Characters kept at the end. */
    tail?: number;
    class?: string;
  }

  let {
    hash,
    name,
    label,
    copyLabel,
    copy = true,
    head = 8,
    tail = 8,
    class: className = '',
  }: Props = $props();

  const short = $derived(abbreviateHash(hash, head, tail));
  const prefix = $derived(label ?? t('components.hash.label'));
</script>

<span class="tt-hash {className}">
  {#if prefix}<span class="tt-hash__label">{prefix}</span>{/if}
  <code class="tt-hash__value" title={hash}
    ><span aria-hidden="true">{short}</span><span class="visually-hidden">{hash}</span></code
  >
  {#if copy}
    <CopyButton small text={hash} ariaLabel={copyLabel ?? t('components.hash.copy', { name })} />
  {/if}
</span>

<style>
  .tt-hash {
    display: inline-flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-1) var(--tt-space-2);
    min-width: 0;
  }

  .tt-hash__label {
    font-size: var(--tt-font-size-sm);
  }

  .tt-hash__value {
    font-family: var(--tt-font-mono);
    font-size: var(--tt-font-size-sm);
    white-space: nowrap;
  }
</style>
