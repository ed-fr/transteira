<script lang="ts">
  // Blocks of a help section: paragraphs, lists, notes and screenshots (figure with its
  // alternative text, optional caption and the pixel size of the PNG read at build time, so that
  // the page does not move while the image loads lazily from /assets/), and the real rules of
  // the tenant (HelpRules.svelte, nothing without rules). The blocks never change once loaded:
  // each one is keyed by its own object, not by its index.
  import type { HelpLinks } from './help';
  import HelpInline from './HelpInline.svelte';
  import HelpRules from './HelpRules.svelte';
  import type { HelpTenantRules } from './rules';
  import type { HelpBlock } from './types';

  interface Props {
    blocks: readonly HelpBlock[];
    links: HelpLinks;
    /** Rules of the current tenant (public application), for the rules blocks. */
    rules?: HelpTenantRules | undefined;
  }

  let { blocks, links, rules }: Props = $props();
</script>

{#each blocks as block (block)}
  {#if block.type === 'paragraph'}
    <p><HelpInline nodes={block.content} {links} /></p>
  {:else if block.type === 'list'}
    {#if block.ordered}
      <ol>
        {#each block.items as item (item)}
          <li><HelpInline nodes={item} {links} /></li>
        {/each}
      </ol>
    {:else}
      <ul>
        {#each block.items as item (item)}
          <li><HelpInline nodes={item} {links} /></li>
        {/each}
      </ul>
    {/if}
  {:else if block.type === 'note'}
    <div class="help-note" role="note">
      <p><strong>{block.label}</strong> <HelpInline nodes={block.content} {links} /></p>
    </div>
  {:else if block.type === 'rules'}
    <HelpRules set={block.set} {rules} />
  {:else}
    <figure class="help-figure">
      <img
        src={block.src}
        alt={block.alt}
        loading="lazy"
        decoding="async"
        width={block.width}
        height={block.height}
      />
      {#if block.caption !== undefined}
        <figcaption>{block.caption}</figcaption>
      {/if}
    </figure>
  {/if}
{/each}

<style>
  .help-note {
    margin: var(--tt-space-4) 0;
    padding: var(--tt-space-3) var(--tt-space-4);
    border-left: 4px solid var(--tt-info);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-info-bg);
    color: var(--tt-text);
  }

  .help-note p {
    margin: 0;
  }

  .help-figure {
    margin: var(--tt-space-4) 0;
  }

  .help-figure img {
    display: block;
    max-width: 100%;
    height: auto;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
  }

  .help-figure figcaption {
    margin-top: var(--tt-space-2);
    color: var(--tt-text-muted);
    font-size: var(--tt-font-size-sm);
  }

  @media print {
    .help-note,
    .help-figure {
      break-inside: avoid;
    }

    .help-figure img {
      max-height: 60vh;
      width: auto;
    }
  }
</style>
