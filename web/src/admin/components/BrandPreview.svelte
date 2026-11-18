<script lang="ts">
  // Preview of the public page with the edited colours, in the light and dark themes side by side
  // (stacked on narrow screens, CLAUDE.md section 13.1): a header with glass pills, a rounded
  // card with a text, a link, a switch, a segment and a button, drawn with the tenant tokens (--tt-primary, --tt-on-primary, --tt-link, --tt-accent,
  // --tt-focus). Each mock page carries its own data-theme, so that the palette of tokens.css
  // applies to it whatever the theme of the administration, and receives the tenant colours
  // through the CSSOM (applyTenantTheme, style.setProperty; never a style attribute, which the
  // CSP would block): the --tt-brand-* properties are declared on the element matching
  // [data-theme], where the palette maps them. Same rules as the public pages: an invalid colour
  // keeps the default, a primary colour without enough contrast on the background of a theme is
  // not used for links there. The mocks are not interactive: the link, switch, segment and button are
  // plain decorative shapes, so that keyboard users do not land on fake controls.
  import { Icon } from '../../shared/components';
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

  const THEMES = ['light', 'dark'] as const;
  let containers: Partial<Record<(typeof THEMES)[number], HTMLDivElement>> = $state({});

  $effect(() => {
    const colors = { primaryColor: primaryColor.trim(), accentColor: accentColor.trim() };
    for (const theme of THEMES) {
      const container = containers[theme];
      if (container !== undefined) {
        applyTenantTheme(colors, container);
      }
    }
  });
</script>

<figure class="tt-preview">
  <figcaption class="tt-preview__caption">{t('adminTenants.branding.preview.label')}</figcaption>
  <div class="tt-preview__themes">
    {#each THEMES as theme (theme)}
      <figure class="tt-preview__theme">
        <figcaption class="tt-preview__theme-caption">
          {t(`adminTenants.branding.preview.${theme}`)}
        </figcaption>
        <div class="tt-preview__page" data-theme={theme} bind:this={containers[theme]}>
          <div class="tt-preview__header">
            <span class="tt-preview__brand">
              {#if logoUrl}
                <img class="tt-preview__logo" src={logoUrl} alt={t('adminTenants.branding.logo.alt')} />
              {/if}
              <span class="tt-preview__heading">{t('adminTenants.branding.preview.heading')}</span>
            </span>
            <span class="tt-preview__pills" aria-hidden="true">
              <span class="tt-preview__pill"><Icon name="list" size="xs" /></span>
              <span class="tt-preview__pill"><Icon name="globe" size="xs" /></span>
              <span class="tt-preview__pill"><Icon name="moon" size="xs" /></span>
            </span>
          </div>
          <div class="tt-preview__card">
            <p class="tt-preview__text">{t('adminTenants.branding.preview.text')}</p>
            <p class="tt-preview__text">
              <span class="tt-preview__link">{t('adminTenants.branding.preview.link')}</span>
            </p>
            <div class="tt-preview__controls" aria-hidden="true">
              <span class="tt-preview__switch"><span class="tt-preview__thumb"></span></span>
              <span class="tt-preview__segment">{t('adminTenants.branding.preview.segment')}</span>
            </div>
            <span class="tt-preview__button">{t('adminTenants.branding.preview.button')}</span>
          </div>
          <div class="tt-preview__accent" aria-hidden="true"></div>
        </div>
      </figure>
    {/each}
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

  .tt-preview__themes {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
    gap: var(--tt-space-4);
  }

  .tt-preview__theme {
    margin: 0;
    min-width: 0;
  }

  .tt-preview__theme-caption {
    margin-bottom: var(--tt-space-1);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-preview__page {
    overflow: hidden;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius);
    background: var(--tt-veil);
    color: var(--tt-text);
  }

  .tt-preview__header {
    display: flex;
    gap: var(--tt-space-2);
    align-items: center;
    justify-content: space-between;
    padding: var(--tt-space-3);
  }

  .tt-preview__brand {
    display: inline-flex;
    gap: var(--tt-space-2);
    align-items: center;
    padding: var(--tt-space-1) var(--tt-space-3);
    border-radius: var(--tt-radius);
    background: var(--tt-logo-surface);
    color: var(--tt-logo-text);
  }

  .tt-preview__logo {
    max-height: 2rem;
    max-width: 6rem;
    object-fit: contain;
  }

  .tt-preview__heading {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-preview__pills {
    display: inline-flex;
    gap: var(--tt-space-1);
  }

  .tt-preview__pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    border: var(--tt-border-width) solid var(--tt-glass-border);
    border-radius: var(--tt-radius-full);
    background: var(--tt-glass-bg);
    color: var(--tt-glass-text);
  }

  .tt-preview__card {
    margin: 0 var(--tt-space-3) var(--tt-space-3);
    padding: var(--tt-space-4);
    border-radius: var(--tt-radius-xl);
    background: var(--tt-surface);
    box-shadow: var(--tt-shadow-strong);
  }

  .tt-preview__text {
    margin: 0 0 var(--tt-space-3);
  }

  .tt-preview__link {
    color: var(--tt-link);
    text-decoration: underline;
  }

  .tt-preview__controls {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
    align-items: center;
    margin-bottom: var(--tt-space-3);
  }

  .tt-preview__switch {
    display: inline-flex;
    justify-content: flex-end;
    width: 2.75rem;
    padding: 0.125rem;
    border-radius: var(--tt-radius-full);
    background: var(--tt-graphic);
  }

  .tt-preview__thumb {
    width: 1.25rem;
    height: 1.25rem;
    border-radius: var(--tt-radius-full);
    background: var(--tt-surface);
  }

  .tt-preview__segment {
    padding: var(--tt-space-1) var(--tt-space-3);
    border: 2px solid var(--tt-graphic);
    border-radius: var(--tt-radius);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-preview__button {
    display: inline-block;
    padding: var(--tt-space-2) var(--tt-space-5);
    border: 2px solid var(--tt-primary);
    border-radius: var(--tt-radius-full);
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
