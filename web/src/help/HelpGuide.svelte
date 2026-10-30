<script lang="ts">
  // A user guide: title (the page heading), table of contents in a <nav>, then the sections.
  // Every heading has tabindex="-1" so that the help screen can move the focus to the section of
  // the requested topic (and to the target of a link inside the guide). With the rules of a
  // tenant, the sections of the options it does not offer are left out (visibleSections).
  import { t } from '../shared/i18n/i18n.svelte';
  import HelpBlocks from './HelpBlocks.svelte';
  import { sectionDomId, tableOfContents, visibleSections, type HelpLinks } from './help';
  import type { HelpTenantRules } from './rules';
  import type { HelpGuide } from './types';

  interface Props {
    guide: HelpGuide;
    links: HelpLinks;
    /** Language of the guide when it differs from the interface (fallback guides). */
    lang?: string | undefined;
    /** Rules of the current tenant (public application): rules blocks and hidden sections. */
    rules?: HelpTenantRules | undefined;
    /**
     * Printable version: one guide among others under the page heading, so headings one level
     * down, without ids (two guides may share a section id) nor table of contents.
     */
    printable?: boolean;
  }

  let { guide, links, lang, rules, printable = false }: Props = $props();
  const uid = $props.id();
  const sections = $derived(visibleSections(guide, rules?.features));
  const toc = $derived(printable ? [] : tableOfContents({ ...guide, sections }));
</script>

<article class="help-guide" {lang}>
  {#each sections as section, i (section.id)}
    <svelte:element
      this={`h${printable ? section.level + 1 : section.level}`}
      id={printable ? undefined : sectionDomId(section.id)}
      tabindex={printable ? undefined : -1}
      class="help-heading"
    >
      {section.title}
    </svelte:element>
    <HelpBlocks blocks={section.blocks} {links} {rules} />
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

  @media print {
    .help-heading {
      break-after: avoid;
    }

    .help-toc {
      display: none;
    }
  }
</style>
