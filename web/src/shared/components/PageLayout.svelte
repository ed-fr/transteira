<script lang="ts">
  // Page frame of both applications (CLAUDE.md section 13): skip link, full-screen decorative
  // background image under a veil, header with the tenant logo (or name), main landmark holding
  // a centred card, footer snippet (use Footer.svelte), and the shared announcer regions.
  //
  // logoUrl and backgroundUrl come from the API (PublicTenant.branding): they are checked here
  // with safeApiHref (src/shared/safe/href.ts); a missing or rejected URL omits the image.
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
    /** Wider card (administration tables, download page with many files). */
    wide?: boolean;
    /** Id of the main landmark, target of the skip link. */
    mainId?: string;
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
    mainId = 'main',
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
<div class="tt-page" class:tt-page--plain={!background}>
  {#if background}
    <img class="tt-page__background" src={background} alt="" aria-hidden="true" />
    <div class="tt-page__veil"></div>
  {/if}
  <header class="tt-page__header">
    <div class="tt-page__brand">
      {#if logo}
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
    <div class="tt-card" class:tt-card--wide={wide}>
      {@render children()}
    </div>
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
