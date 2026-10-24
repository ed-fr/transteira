<script lang="ts">
  // Preview of the public page with the edited colours: a header, a text, a link and a button
  // drawn with the tenant tokens (--tt-primary, --tt-on-primary, --tt-link, --tt-accent,
  // --tt-focus). The colours are applied to the container only, through the CSSOM
  // (applyTenantTheme, style.setProperty; never a style attribute, which the CSP would block),
  // and with the same rules as the public pages: an invalid colour keeps the default, a primary
  // colour without enough contrast is not used for links. The mock is not interactive: the link
  // and the button are plain text, so that keyboard users do not land on fake controls.
  import { t } from '../../shared/i18n/i18n.svelte';
  import { applyTenantTheme } from '../../shared/theme/theme';

  interface Props {
    /** Edited primary colour. */
    primaryColor: string;
    /** Edited accent colour. */
    accentColor: string;
    /** URL of the logo to show (stored image or local preview), if any. */
    logoUrl?: string | null;
  }

  let { primaryColor, accentColor, logoUrl = null }: Props = $props();

  let container: HTMLDivElement | undefined = $state();

  $effect(() => {
    if (container !== undefined) {
      applyTenantTheme({ primaryColor: primaryColor.trim(), accentColor: accentColor.trim() }, container);
    }
  });
</script>

<figure class="tt-preview">
  <figcaption class="tt-preview__caption">{t('adminTenants.branding.preview.label')}</figcaption>
  <div class="tt-preview__page" bind:this={container}>
    <div class="tt-preview__header">
      {#if logoUrl}
        <img class="tt-preview__logo" src={logoUrl} alt={t('adminTenants.branding.logo.alt')} />
      {/if}
      <span class="tt-preview__heading">{t('adminTenants.branding.preview.heading')}</span>
    </div>
    <div class="tt-preview__body">
      <p class="tt-preview__text">{t('adminTenants.branding.preview.text')}</p>
      <p class="tt-preview__text">
        <span class="tt-preview__link">{t('adminTenants.branding.preview.link')}</span>
      </p>
      <span class="tt-preview__button">{t('adminTenants.branding.preview.button')}</span>
    </div>
    <div class="tt-preview__accent" aria-hidden="true"></div>
  </div>
</figure>

<style>
  .tt-preview {
    margin: 0 0 var(--tt-space-6);
  }

  .tt-preview__caption {
    margin-bottom: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-preview__page {
    overflow: hidden;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-preview__header {
    display: flex;
    gap: var(--tt-space-3);
    align-items: center;
    padding: var(--tt-space-3) var(--tt-space-4);
    background: var(--tt-primary);
    color: var(--tt-on-primary);
  }

  .tt-preview__logo {
    max-height: 2.5rem;
    max-width: 8rem;
    object-fit: contain;
  }

  .tt-preview__heading {
    font-size: var(--tt-font-size-lg);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-preview__body {
    padding: var(--tt-space-4);
  }

  .tt-preview__text {
    margin: 0 0 var(--tt-space-3);
  }

  .tt-preview__link {
    color: var(--tt-link);
    text-decoration: underline;
  }

  .tt-preview__button {
    display: inline-block;
    padding: var(--tt-space-2) var(--tt-space-5);
    border: 2px solid var(--tt-primary);
    border-radius: var(--tt-radius);
    background: var(--tt-primary);
    color: var(--tt-on-primary);
    font-weight: var(--tt-font-weight-bold);
    outline: var(--tt-focus-width) solid var(--tt-focus);
    outline-offset: 2px;
  }

  .tt-preview__accent {
    height: var(--tt-space-2);
    background: var(--tt-accent);
  }
</style>
