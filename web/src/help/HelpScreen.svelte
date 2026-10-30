<script lang="ts">
  // Integrated help screen of both applications (CLAUDE.md section 4.2), for /help and
  // /help/<topic>:
  // - the guides of the application are loaded on demand in the current language (load), and
  //   reloaded when the language changes, at the same topic;
  // - /help lists the guides offered; /help/<topic> shows the guide holding the topic, with its
  //   table of contents, and moves the focus to the section of the topic (heading with
  //   tabindex="-1"); an unknown topic (or one in a guide not offered) shows the list with a
  //   message, which repeats the topic only when it is a well-formed slug (shownTopic);
  // - a failed load shows an error with a retry button, also above a guide already shown (a
  //   failed reload after a language change);
  // - with the rules of the tenant (public application), the rules blocks show them and the
  //   sections of the options it does not offer are hidden (a topic in one opens the guide top);
  //   the index then links to the printable version;
  // - the page title becomes "Section – Guide" (title.svelte.ts, read by the applications);
  // - "back to the previous screen" goes back in history when the previous entry belongs to the
  //   application (an entry added by the router), next to the link to the home page.
  import { onDestroy, tick } from 'svelte';
  import { Alert, Button, Spinner } from '../shared/components';
  import { locale, t } from '../shared/i18n/i18n.svelte';
  import { isRouterEntry, type Router } from '../shared/router/router.svelte';
  import HelpGuide from './HelpGuide.svelte';
  import {
    guideTopic,
    helpPageTitle,
    plainClick,
    resolveHelp,
    sectionDomId,
    shownTopic,
    type HelpLinks,
  } from './help';
  import type { HelpTenantRules } from './rules';
  import { helpTitle } from './title.svelte';
  import type { GuideId, HelpGuideSet } from './types';

  interface Props {
    /** Loads the guides of the application in a language (publicGuides.ts, adminGuides.ts). */
    load: (lang: string) => Promise<HelpGuideSet>;
    /** Requested topic (route parameter), undefined on /help. */
    topic: string | undefined;
    /** Guides offered to the current user. */
    guides: readonly GuideId[];
    /** Router helpers (internal links). */
    nav: Pick<Router, 'href' | 'link'>;
    /** Text of the link to the home page of the application. */
    homeLabel: string;
    /** Rules of the current tenant (public application only). */
    rules?: HelpTenantRules | undefined;
    /** Path of the printable version, linked from the index (public application only). */
    printPath?: string | undefined;
  }

  let { load, topic, guides, nav, homeLabel, rules, printPath }: Props = $props();

  let set = $state.raw<HelpGuideSet | undefined>();
  let failed = $state(false);
  let attempt = $state(0);
  const canGoBack = typeof history === 'undefined' ? false : isRouterEntry(history.state);

  $effect(() => {
    const lang = locale.current;
    void attempt;
    let cancelled = false;
    failed = false;
    load(lang).then(
      (loaded) => {
        if (!cancelled) set = loaded;
      },
      () => {
        if (!cancelled) failed = true;
      },
    );
    return () => {
      cancelled = true;
    };
  });

  const view = $derived(set === undefined ? undefined : resolveHelp(set, topic, guides, rules?.features));
  const guideLang = $derived(set !== undefined && set.lang !== locale.current ? set.lang : undefined);

  $effect(() => {
    helpTitle.current = helpPageTitle(view, t('common.help.title'));
  });
  onDestroy(() => {
    helpTitle.current = undefined;
  });

  function focusSection(sectionId: string, scroll: boolean): void {
    const heading = document.getElementById(sectionDomId(sectionId));
    if (heading === null) return;
    heading.focus({ preventScroll: true });
    if (scroll) heading.scrollIntoView({ block: 'start' });
    else window.scrollTo(0, 0);
  }

  // Focus on the section of the topic once the guide is shown, again after a language change.
  // It runs after the router, which focuses the page heading right after a navigation.
  let focused = '';
  $effect(() => {
    if (view?.kind !== 'guide' || set === undefined) return;
    const key = `${set.lang}/${view.guide.id}/${view.section.id}`;
    if (key === focused) return;
    focused = key;
    const { section } = view;
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    void tick().then(() => {
      if (done) return;
      timer = setTimeout(() => {
        done = true;
        focusSection(section.id, section.level !== 1);
      }, 0);
    });
    return () => {
      if (done) return;
      // Torn down before the focus moved: cancel it, and let the next run schedule it again.
      done = true;
      clearTimeout(timer);
      if (focused === key) focused = '';
    };
  });

  const links: HelpLinks = {
    topicHref: (target) => nav.href(`/help/${target}`),
    link: (node) => nav.link(node),
    onanchor: (sectionId, event) => {
      // A modified or middle click opens the link in a new tab or window, as usual.
      if (!plainClick(event)) return;
      event.preventDefault();
      focusSection(sectionId, true);
    },
  };

  function goBack(event: MouseEvent): void {
    event.preventDefault();
    history.back();
  }

  function describe(id: GuideId): string {
    switch (id) {
      case 'depositor':
        return t('help.guides.depositor');
      case 'recipient':
        return t('help.guides.recipient');
      case 'delegated-admin':
        return t('help.guides.delegatedAdmin');
      default:
        return t('help.guides.superAdmin');
    }
  }
</script>

{#snippet loadError()}
  <Alert severity="error" title={t('help.error')}>
    <Button onclick={() => attempt++}>{t('common.retry')}</Button>
  </Alert>
{/snippet}

{#snippet backLinks()}
  <ul class="help-links">
    {#if canGoBack}
      <li><a href={nav.href('/')} onclick={goBack}>{t('help.back')}</a></li>
    {/if}
    {#if view?.kind === 'guide'}
      <li><a href={nav.href('/help')} use:nav.link>{t('help.indexLink')}</a></li>
    {/if}
    <li><a href={nav.href('/')} use:nav.link>{homeLabel}</a></li>
  </ul>
{/snippet}

<div class="help-screen">
  {#if view?.kind === 'guide'}
    {@render backLinks()}
    {#if failed}
      {@render loadError()}
    {/if}
    <HelpGuide guide={view.guide} {links} lang={guideLang} {rules} />
  {:else}
    <h1 tabindex="-1">{t('common.help.title')}</h1>
    {#if failed}
      {@render loadError()}
    {:else if view === undefined}
      <p><Spinner showLabel label={t('help.loading')} /></p>
    {:else}
      {#if view.unknownTopic !== undefined}
        {@const shown = shownTopic(view.unknownTopic)}
        <Alert severity="warning">
          <p class="tt-break">
            {shown === undefined ? t('help.unknownTopicGeneric') : t('help.unknownTopic', { topic: shown })}
          </p>
        </Alert>
      {/if}
      <p>{t('help.index.intro')}</p>
      <h2>{t('help.index.guides')}</h2>
      <ul class="help-index" lang={guideLang}>
        {#each view.guides as guide (guide.id)}
          <li>
            <a href={nav.href(`/help/${guideTopic(guide)}`)} use:nav.link>{guide.title}</a>
            <p class="tt-text-muted" lang={locale.current}>{describe(guide.id)}</p>
          </li>
        {/each}
      </ul>
      {#if printPath !== undefined}
        <p class="help-print-link">
          <a href={nav.href(printPath)} use:nav.link>{t('help.print.link')}</a>
        </p>
      {/if}
    {/if}
    {@render backLinks()}
  {/if}
</div>

<style>
  .help-screen {
    max-width: 48rem;
  }

  .help-links {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2) var(--tt-space-6);
    margin: var(--tt-space-4) 0;
    padding: 0;
    list-style: none;
  }

  .help-index {
    padding: 0;
    list-style: none;
  }

  .help-index li {
    margin: var(--tt-space-4) 0;
  }

  .help-index a {
    font-size: var(--tt-font-size-lg);
    font-weight: var(--tt-font-weight-bold);
  }

  .help-index p {
    margin: var(--tt-space-1) 0 0;
  }

  .help-print-link {
    margin: var(--tt-space-6) 0 0;
  }

  @media print {
    .help-links,
    .help-print-link {
      display: none;
    }
  }
</style>
