<script lang="ts">
  // Inline content of the help (text, bold, italic, code, internal links), rendered recursively
  // as Svelte nodes: the text is always escaped, never interpreted as HTML (no {@html}).
  import HelpInline from './HelpInline.svelte';
  import { sectionDomId, type HelpLinks } from './help';
  import type { HelpInline as Inline } from './types';

  interface Props {
    nodes: readonly Inline[];
    links: HelpLinks;
  }

  let { nodes, links }: Props = $props();
</script>

<!-- prettier-ignore -->
{#each nodes as node (node)}{#if node.type === 'text'}{node.text}{:else if node.type === 'code'}<code>{node.text}</code>{:else if node.type === 'strong'}<strong><HelpInline nodes={node.children} {links} /></strong>{:else if node.type === 'em'}<em><HelpInline nodes={node.children} {links} /></em>{:else if node.type === 'anchor'}<a href="#{sectionDomId(node.target)}" onclick={(event) => links.onanchor(node.target, event)}><HelpInline nodes={node.children} {links} /></a>{:else}<a href={links.topicHref(node.topic)} use:links.link><HelpInline nodes={node.children} {links} /></a>{/if}{/each}

<style>
  code {
    font-family: var(--tt-font-mono);
    font-size: 0.95em;
    overflow-wrap: anywhere;
  }
</style>
