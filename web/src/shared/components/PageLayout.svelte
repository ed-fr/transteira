<script lang="ts">
  // Page frame of both applications (CLAUDE.md section 13): skip link, full-screen decorative
  // background image under a veil, header with the tenant logo (or name), main landmark holding
  // a centred card, footer snippet (use Footer.svelte), and the shared announcer regions.
  //
  // logoUrl and backgroundUrl come from the API (PublicTenant.branding): they are checked here
  // with safeApiHref (src/shared/safe/href.ts); a missing or rejected URL omits the image.
  //
  // Variants (CLAUDE.md section 13.2): "default" (the administration, unchanged: .tt-card, wide
  // for .tt-card--wide) and "public" (.tt-page--public: glass header actions, the public card
  // .tt-pcard sized by cardSize: narrow, medium, split or wide; see styles/layout.css). Without a
  // background image the page is .tt-page--plain, where the glass tokens map to the surface colours.
  import type { Snippet } from 'svelte';
  import { t } from '../i18n/i18n.svelte';
  import { safeApiHref } from '../safe/href';
  import Announcer from './Announcer.svelte';

  interface Props {
    /** Tenant (or application) name: alternative text of the logo, or shown as text. */
    tenantName: string;
    /** Logo URL from the API; the name is shown as text when absent or rejected. */
    logoUrl?: string | null | undefined;
    /** Background image URL from the API; plain background when absent or rejected. */
    backgroundUrl?: string | null | undefined;
    /** Wider card (variant "default" only: administration tables). */
    wide?: boolean;
    /** Frame of the page: "default" (administration) or "public" (tenant pages, section 13.2). */
    variant?: 'default' | 'public';
    /** Width of the public card (variant "public" only); narrow by default. */
    cardSize?: 'narrow' | 'medium' | 'split' | 'wide';
    /** Id of the main landmark, target of the skip link. */
    mainId?: string;
    /**
     * Content of the brand box instead of the tenant logo or name (the administration draws its
     * own logo); the box is then transparent, the snippet being responsible for its contrast.
     * Fixed application content only, never a value of a tenant.
     */
    brand?: Snippet;
    /** Content on the right side of the header (e.g. admin menu). */
    header?: Snippet;
    /** Content above the card inside main (e.g. maintenance banner). */
    banner?: Snippet;
    /** Footer, rendered as is (use Footer.svelte, which renders the contentinfo landmark). */
    footer?: Snippet;
    /** Page content, inside the card. */
    children: Snippet;
  }

  let {
    tenantName,
    logoUrl,
    backgroundUrl,
    wide = false,
    variant = 'default',
    cardSize = 'narrow',
    mainId = 'main',
    brand,
    header,
    banner,
    footer,
    children,
  }: Props = $props();

  const logo = $derived(safeApiHref(logoUrl));
  const background = $derived(safeApiHref(backgroundUrl));
  let main: HTMLElement | undefined = $state();

  // The router uses the History API: move the focus without changing the URL hash.
  function skipToMain(event: MouseEvent): void {
    if (main !== undefined) {
      event.preventDefault();
      main.focus();
      main.scrollIntoView();
    }
  }
</script>

<a class="skip-link" href="#{mainId}" onclick={skipToMain}>{t('components.layout.skipLink')}</a>
<div class="tt-page" class:tt-page--plain={!background} class:tt-page--public={variant === 'public'}>
  {#if background}
    <img class="tt-page__background" src={background} alt="" aria-hidden="true" />
    <div class="tt-page__veil"></div>
  {/if}
  <header class="tt-page__header">
    <div class="tt-page__brand" class:tt-page__brand--custom={brand !== undefined}>
      {#if brand}
        {@render brand()}
      {:else if logo}
        <img class="tt-page__logo" src={logo} alt={tenantName} />
      {:else}
        <span>{tenantName}</span>
      {/if}
    </div>
    {#if header}{@render header()}{/if}
  </header>
  <main class="tt-page__main" id={mainId} tabindex="-1" bind:this={main}>
    {#if banner}
      <div class="tt-page__banner">{@render banner()}</div>
    {/if}
    {#if variant === 'public'}
      <div class="tt-pcard tt-pcard--{cardSize}">
        {@render children()}
      </div>
    {:else}
      <div class="tt-card" class:tt-card--wide={wide}>
        {@render children()}
      </div>
    {/if}
  </main>
  {#if footer}{@render footer()}{/if}
</div>
<Announcer />

<style>
  .tt-page__main {
    flex-direction: column;
    gap: var(--tt-space-4);
  }

  .tt-page__banner {
    width: 100%;
    max-width: var(--tt-content-width);
  }
</style>
