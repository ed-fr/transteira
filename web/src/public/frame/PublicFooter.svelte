<script lang="ts">
  // Footer of the public pages (CLAUDE.md section 13.2), contentinfo landmark: the legal links
  // (snippet of <li><a> items, in a "Legal information" navigation), the help link "Help" (hidden on
  // the help pages, helpTopic null) and "Powered by TransTeira" as plain text (no external link). It
  // sits on the background image: a discreet glass backing (tokens --tt-glass-*, light text checked
  // at 4.5:1 on any image; surface colours on a page without image). The language and theme
  // controls live in the header (HeaderActions). Keeps the class tt-page__footer, hidden on paper.
  import type { Snippet } from 'svelte';
  import { HelpLink } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Router } from '../../shared/router/router.svelte';

  interface Props {
    /** Legal links, rendered as list items (<li><a ...></a></li>) of the legal navigation. */
    legal?: Snippet;
    /** Help topic of the current screen; the help link is hidden when null. */
    helpTopic?: string | null | undefined;
    /** Router of the application: the help link is then an in-app navigation. */
    nav?: Pick<Router, 'link'> | undefined;
  }

  let { legal, helpTopic, nav }: Props = $props();
</script>

<footer class="tt-page__footer tt-pfooter">
  <div class="tt-pfooter__inner">
    {#if legal}
      <nav aria-label={t('components.footer.legal')}>
        <ul class="tt-pfooter__links">
          {@render legal()}
        </ul>
      </nav>
    {/if}
    {#if helpTopic !== null}
      <HelpLink topic={helpTopic ?? undefined} {nav} />
    {/if}
    <span class="tt-pfooter__powered">{t('common.footer.poweredBy')}</span>
  </div>
</footer>

<style>
  .tt-pfooter {
    display: flex;
    justify-content: center;
    padding: 0 var(--tt-space-4) var(--tt-space-5);
  }

  .tt-pfooter__inner {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    gap: 0 var(--tt-space-5);
    max-width: var(--tt-content-width);
    padding: 0 var(--tt-space-5);
    border: var(--tt-border-width) solid var(--tt-glass-border);
    border-radius: var(--tt-radius-lg);
    background: var(--tt-glass-bg);
    color: var(--tt-glass-text);
    font-size: var(--tt-font-size-sm);
    -webkit-backdrop-filter: blur(0.5rem);
    backdrop-filter: blur(0.5rem);
  }

  .tt-pfooter__links {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 0 var(--tt-space-5);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  /* Links: the glass text colour, underlined, on a 44 px line. */
  .tt-pfooter__inner :global(a) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: var(--tt-control-height);
    min-height: var(--tt-control-height);
    color: var(--tt-glass-text);
  }

  .tt-pfooter__inner :global(a:focus-visible) {
    outline-color: var(--tt-glass-focus);
    box-shadow: 0 0 0 calc(var(--tt-focus-width) + 2px) var(--tt-glass-ring);
  }

  .tt-pfooter__powered {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
  }

  @media (forced-colors: active) {
    .tt-pfooter__inner {
      border-color: CanvasText;
    }
  }
</style>
