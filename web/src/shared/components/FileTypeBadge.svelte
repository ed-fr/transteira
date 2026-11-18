<script lang="ts">
  // File type badge (CLAUDE.md section 13.2): the extension of a file name, uppercase, at most four
  // characters ("PDF", "XLSX"), or a file icon when the name has none, in a rounded square of the
  // neutral chip tokens. Decorative (aria-hidden): the file name next to it carries the information.
  //
  // Props:
  //   name   file name (a folder path before it is ignored)
  //   size   'md' (2.5rem, default) or 'lg' (2.75rem)
  import Icon from './Icon.svelte';
  import { fileTypeLabel } from './helpers';

  interface Props {
    /** File name. */
    name: string;
    /** Size of the square. */
    size?: 'md' | 'lg';
    class?: string;
  }

  let { name, size = 'md', class: className = '' }: Props = $props();
  const label = $derived(fileTypeLabel(name));
</script>

<span class="tt-ftype tt-ftype--{size} {className}" aria-hidden="true">
  {#if label}{label}{:else}<Icon name="file" size="md" />{/if}
</span>

<style>
  .tt-ftype {
    flex: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 2.5rem;
    height: 2.5rem;
    border-radius: var(--tt-radius);
    background: var(--tt-chip-bg);
    color: var(--tt-chip-text);
    font-size: 0.6875rem;
    font-weight: var(--tt-font-weight-bold);
    letter-spacing: 0.02em;
    line-height: 1;
  }

  .tt-ftype--lg {
    width: 2.75rem;
    height: 2.75rem;
  }

  @media (forced-colors: active) {
    .tt-ftype {
      border: var(--tt-border-width) solid CanvasText;
    }
  }
</style>
