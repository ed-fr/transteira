<script lang="ts">
  // Page footer (contentinfo landmark): legal links (snippet, e.g. router links to
  // /legal/legal-notice), help link and language switch. Pass it to PageLayout's footer snippet.
  import type { Snippet } from 'svelte';
  import { t } from '../i18n/i18n.svelte';
  import type { Router } from '../router/router.svelte';
  import HelpLink from './HelpLink.svelte';
  import LanguageSwitch from './LanguageSwitch.svelte';

  interface Props {
    /** Legal links, rendered as list items (<li><a ...></a></li>) of the legal navigation. */
    legal?: Snippet;
    /** Languages offered; the switch is hidden with fewer than two. */
    languages?: readonly string[];
    /** Current language. */
    currentLanguage?: string;
    /** Called with the chosen language. */
    onlanguagechange?: (language: string) => void;
    /** Help topic of the current screen; the help link is hidden when null. */
    helpTopic?: string | null;
    /** Path prefix of the help link: "" (public, default) or "/admin". */
    helpBase?: string;
    /** Router of the application: the help link is then an in-app navigation. */
    nav?: Pick<Router, 'link'> | undefined;
    /** Extra content (e.g. version). */
    children?: Snippet;
    class?: string;
  }

  let {
    legal,
    languages = [],
    currentLanguage = '',
    onlanguagechange,
    helpTopic,
    helpBase = '',
    nav,
    children,
    class: className = '',
  }: Props = $props();
</script>

<footer class="tt-page__footer tt-footer {className}">
  <div class="tt-footer__inner">
    {#if legal}
      <nav aria-label={t('components.footer.legal')}>
        <ul class="tt-footer__links">
          {@render legal()}
        </ul>
      </nav>
    {/if}
    {#if helpTopic !== null}
      <HelpLink topic={helpTopic ?? undefined} base={helpBase} {nav} />
    {/if}
    {#if onlanguagechange}
      <LanguageSwitch {languages} current={currentLanguage} onchange={onlanguagechange} />
    {/if}
    {#if children}{@render children()}{/if}
  </div>
</footer>

<style>
  .tt-footer__inner {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    gap: var(--tt-space-3) var(--tt-space-6);
    max-width: var(--tt-content-width);
    margin: 0 auto;
    padding: var(--tt-space-2) var(--tt-space-4);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
    color: var(--tt-text);
    font-size: var(--tt-font-size-sm);
  }

  .tt-footer__links {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2) var(--tt-space-4);
    margin: 0;
    padding: 0;
    list-style: none;
  }
</style>
