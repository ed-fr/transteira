<script lang="ts">
  // Document of the printable version (/help/print, screens/HelpPrint.svelte loads its data):
  // - a heading with the tenant logo (shown on paper only: the page header already shows it on
  //   screen) and name, the date of generation and the application version, then the notice
  //   that the rules in force are those applied at deposit time (threat model T-234);
  // - a "Print / Save as PDF" button (window.print(), keyboard reachable) and a link back to the
  //   online help, both hidden on paper;
  // - the guides in full, each starting on a new printed page: sections of the options the
  //   tenant does not offer left out, rules resolved, screenshots kept, internal links as text.
  // Every tenant value (name, rules) is rendered as text (T-232).
  import { Alert, Button, Spinner } from '../shared/components';
  import { formatDate, t } from '../shared/i18n/i18n.svelte';
  import { safeApiHref } from '../shared/safe/href';
  import HelpGuide from './HelpGuide.svelte';
  import { PLAIN_LINKS, UNKNOWN_VERSION, printPage } from './print';
  import type { HelpTenantRules } from './rules';
  import type { HelpGuide as Guide } from './types';

  interface Props {
    /** Rules of the current tenant (GET /tenant). */
    rules: HelpTenantRules;
    /** Logo URL of the tenant from the API, if any. */
    logoUrl?: string | undefined;
    /** Guides to print, in order; undefined while loading. */
    guides: readonly Guide[] | undefined;
    /** Language of the guides when it differs from the interface (fallback guides). */
    guideLang?: string | undefined;
    /** The guides could not be loaded. */
    failed: boolean;
    /** Application version; undefined while loading. */
    version: string | undefined;
    /** Date of generation of the page. */
    generatedAt: Date;
    /** URL of the online help. */
    helpHref: string;
    /** Router action of internal links. */
    link: (node: HTMLAnchorElement) => { destroy(): void };
    /** Retries loading the guides. */
    onretry: () => void;
    /** Opens the print dialog (window.print() by default). */
    onprint?: () => void;
  }

  let {
    rules,
    logoUrl,
    guides,
    guideLang,
    failed,
    version,
    generatedAt,
    helpHref,
    link,
    onretry,
    onprint = () => printPage(window),
  }: Props = $props();

  const logo = $derived(safeApiHref(logoUrl));
</script>

<div class="help-print">
  <div class="help-print__header">
    {#if logo}
      <img class="help-print__logo" src={logo} alt="" />
    {/if}
    <h1 tabindex="-1">{t('help.print.heading', { name: rules.name })}</h1>
    <p class="help-print__meta">
      <span>{t('help.print.generated', { date: formatDate(generatedAt, { dateStyle: 'long' }) })}</span>
      <span>{t('help.print.version', { version: version ?? UNKNOWN_VERSION })}</span>
    </p>
  </div>
  <div class="help-print__notice" role="note">
    <p>{t('help.print.notice')}</p>
  </div>
  <ul class="help-print__actions">
    <li><Button onclick={() => onprint()}>{t('help.print.button')}</Button></li>
    <li><a href={helpHref} use:link>{t('help.print.back')}</a></li>
  </ul>

  {#if failed}
    <Alert severity="error" title={t('help.error')}>
      <Button onclick={onretry}>{t('common.retry')}</Button>
    </Alert>
  {:else if guides === undefined}
    <p><Spinner showLabel label={t('help.loading')} /></p>
  {:else}
    {#each guides as guide (guide.id)}
      <section class="help-print__guide">
        <HelpGuide {guide} links={PLAIN_LINKS} lang={guideLang} {rules} printable />
      </section>
    {/each}
  {/if}
</div>

<style>
  .help-print {
    max-width: 48rem;
  }

  .help-print__logo {
    display: none;
  }

  .help-print__meta {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-1) var(--tt-space-6);
    color: var(--tt-text-muted);
  }

  .help-print__notice {
    margin: var(--tt-space-4) 0;
    padding: var(--tt-space-3) var(--tt-space-4);
    border-left: 4px solid var(--tt-info);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-info-bg);
  }

  .help-print__notice p {
    margin: 0;
  }

  .help-print__actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-3) var(--tt-space-6);
    margin: var(--tt-space-4) 0 var(--tt-space-6);
    padding: 0;
    list-style: none;
  }

  .help-print__guide + .help-print__guide {
    margin-top: var(--tt-space-12);
    padding-top: var(--tt-space-6);
    border-top: var(--tt-border-width) solid var(--tt-border);
  }

  /* Guide titles in the tenant colour when it is legible (--tt-link: the primary when it reaches
     AA on the surface, tokens.css). */
  .help-print :global(h2) {
    color: var(--tt-link);
  }

  @media print {
    .help-print {
      max-width: none;
    }

    .help-print__logo {
      display: block;
      max-height: 3rem;
      width: auto;
      margin-bottom: var(--tt-space-4);
    }

    .help-print__actions {
      display: none;
    }

    .help-print__notice {
      break-inside: avoid;
    }

    .help-print__guide + .help-print__guide {
      break-before: page;
      margin-top: 0;
      padding-top: 0;
      border-top: none;
    }
  }
</style>
