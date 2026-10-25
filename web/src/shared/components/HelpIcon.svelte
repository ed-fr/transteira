<script lang="ts">
  // Contextual help icon placed next to the heading of a complex screen (CLAUDE.md section 4.2):
  // a "?" link to /help/<topic> (under the base path of the router), whose accessible name is
  // "Help: <screen title>". Put the h1 and the icon in an element with the tt-title-row class.
  import { t } from '../i18n/i18n.svelte';
  import type { Router } from '../router/router.svelte';
  import { helpHref } from './helpers';

  interface Props {
    /** Help topic of the screen. */
    topic: string;
    /** Title of the screen, for the accessible name. */
    title: string;
    /** Router of the application (base path, in-app navigation). */
    nav: Pick<Router, 'href' | 'link'>;
  }

  let { topic, title, nav }: Props = $props();
  const label = $derived(t('help.icon', { title }));
</script>

<a class="tt-help-icon" href={nav.href(helpHref(topic))} title={label} use:nav.link>
  <span aria-hidden="true">?</span>
  <span class="visually-hidden">{label}</span>
</a>

<style>
  .tt-help-icon {
    display: inline-flex;
    flex: none;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    border: 2px solid var(--tt-link);
    border-radius: 50%;
    color: var(--tt-link);
    font-weight: var(--tt-font-weight-bold);
    text-decoration: none;
  }

  .tt-help-icon:hover {
    background: var(--tt-surface-muted);
  }
</style>
