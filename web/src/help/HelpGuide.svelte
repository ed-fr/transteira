<script lang="ts">
  // A user guide: title (the page heading), table of contents in a <nav>, then the sections.
  // Every heading has tabindex="-1" so that the help screen can move the focus to the section of
  // the requested topic (and to the target of a link inside the guide).
  import { t } from '../shared/i18n/i18n.svelte';
  import HelpBlocks from './HelpBlocks.svelte';
  import { sectionDomId, tableOfContents, type HelpLinks } from './help';
  import type { HelpGuide } from './types';

  interface Props {
    guide: HelpGuide;
    links: HelpLinks;
    /** Language of the guide when it differs from the interface (fallback guides). */
    lang?: string | undefined;
  }

  let { guide, links, lang }: Props = $props();
  const uid = $props.id();
  const toc = $derived(tableOfContents(guide));
</script>

<article class="help-guide" {lang}>
  {#each guide.sections as section, i (section.id)}
    <svelte:element
      this={`h${section.level}`}
      id={sectionDomId(section.id)}
      tabindex="-1"
      class="help-heading"
    >
      {section.title}
    </svelte:element>
    <HelpBlocks blocks={section.blocks} {links} />
    {#if i === 0 && toc.length > 0}
      <nav class="help-toc" aria-labelledby="{uid}-toc">
        <p id="{uid}-toc" class="help-toc__title">{t('help.toc')}</p>
        <ol>
          {#each toc as entry (entry.id)}
            <li>
              <a href="#{sectionDomId(entry.id)}" onclick={(event) => links.onanchor(entry.id, event)}>
                {entry.title}
              </a>
              {#if entry.children.length > 0}
                <ol>
                  {#each entry.children as child (child.id)}
                    <li>
                      <a
                        href="#{sectionDomId(child.id)}"
                        onclick={(event) => links.onanchor(child.id, event)}
                      >
                        {child.title}
                      </a>
                    </li>
                  {/each}
                </ol>
              {/if}
            </li>
          {/each}
        </ol>
      </nav>
    {/if}
  {/each}
</article>

<style>
  .help-guide {
    line-height: var(--tt-line-height);
  }

  .help-heading {
    scroll-margin-top: var(--tt-space-4);
  }

  .help-heading:focus {
    outline: none;
  }

  .help-heading:focus-visible {
    outline: var(--tt-focus-width) solid var(--tt-focus);
    outline-offset: 2px;
  }

  .help-toc {
    margin: var(--tt-space-4) 0 var(--tt-space-6);
    padding: var(--tt-space-3) var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface-muted);
  }

  .help-toc__title {
    margin: 0 0 var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .help-toc ol {
    margin: 0;
    padding-left: var(--tt-space-6);
  }

  .help-toc li {
    margin: var(--tt-space-1) 0;
  }
</style>
