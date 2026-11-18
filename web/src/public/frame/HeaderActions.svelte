<script lang="ts">
  // Actions of the public page header (CLAUDE.md section 13.2), right of the tenant logo: glass
  // pills on the background image (layout.css .tt-glass-btn, tokens --tt-glass-*):
  //   - a "Quick links" navigation: "My transfers" (/me) and, when the tenant offers it, the
  //     express secret (/x, id tt-header-express); aria-current="page" on the current one;
  //   - the language selector (glass variant, accessible name "Language"), the theme switch (glass
  //     variant, "Dark theme" with aria-pressed) and the help link (glass "?" variant, "Help"),
  //     hidden on the help pages (helpTopic null).
  // Every control is at least 44 × 44 px. On narrow screens the link labels collapse to their icons:
  // the text stays in the page as visually hidden text (accessible name, textContent) and as tooltip.
  import { HelpLink, Icon, LanguageSwitch, ThemeSwitch } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Router } from '../../shared/router/router.svelte';
  import type { PublicTenant } from '../bootstrap';
  import { EXPRESS_PATH, expressFeatures, expressOffered } from '../secret/express';

  interface Props {
    /** Public configuration of the tenant (express secret offer). */
    tenant: PublicTenant;
    /** Router of the application: in-app links. */
    nav: Pick<Router, 'href' | 'link'>;
    /** Pattern of the current route (aria-current). */
    pattern: string;
    /** Languages offered; the selector is hidden with fewer than two. */
    languages: readonly string[];
    /** Current language. */
    currentLanguage: string;
    /** Called with the chosen language. */
    onlanguagechange: (language: string) => void;
    /** Help topic of the current screen; the help link is hidden when null (help pages). */
    helpTopic: string | null | undefined;
  }

  let { tenant, nav, pattern, languages, currentLanguage, onlanguagechange, helpTopic }: Props = $props();

  const MY_TRANSFERS_PATH = '/me';
  const express = $derived(expressOffered(expressFeatures(tenant)));
</script>

<div class="tt-hactions">
  <nav class="tt-hactions__nav" aria-label={t('secretExpress.nav.label')}>
    <ul class="tt-hactions__list">
      <li>
        <a
          class="tt-glass-btn tt-hactions__link"
          href={nav.href(MY_TRANSFERS_PATH)}
          title={t('common.header.myTransfers')}
          aria-current={pattern === MY_TRANSFERS_PATH ? 'page' : undefined}
          use:nav.link
        >
          <Icon name="list" />
          <span class="tt-hactions__text">{t('common.header.myTransfers')}</span>
        </a>
      </li>
      {#if express}
        <li>
          <a
            id="tt-header-express"
            class="tt-glass-btn tt-hactions__link"
            href={nav.href(EXPRESS_PATH)}
            title={t('secretExpress.nav.link')}
            aria-current={pattern === EXPRESS_PATH ? 'page' : undefined}
            use:nav.link
          >
            <Icon name="lock" />
            <span class="tt-hactions__text">{t('secretExpress.nav.link')}</span>
          </a>
        </li>
      {/if}
    </ul>
  </nav>
  <div class="tt-hactions__tools">
    <LanguageSwitch variant="glass" {languages} current={currentLanguage} onchange={onlanguagechange} />
    <ThemeSwitch variant="glass" />
    {#if helpTopic !== null}
      <HelpLink variant="glass" topic={helpTopic ?? undefined} {nav} />
    {/if}
  </div>
</div>

<style>
  .tt-hactions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: var(--tt-space-2);
    margin-left: auto;
  }

  .tt-hactions__list,
  .tt-hactions__tools {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2);
  }

  .tt-hactions__list {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  /* Narrow screens: icon-only links, the label stays as visually hidden text. */
  @media (max-width: 40rem) {
    .tt-hactions__link {
      width: var(--tt-control-height);
      padding: 0;
    }

    .tt-hactions__text {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
      border: 0;
    }
  }
</style>
