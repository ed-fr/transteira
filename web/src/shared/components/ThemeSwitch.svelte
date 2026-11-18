<script lang="ts">
  // Theme switch (CLAUDE.md section 13.1): one native toggle button "Dark theme", pressed
  // (aria-pressed) when the dark theme is shown, with a visible check mark so that the state is
  // not conveyed by the page colours alone. The choice is stored in the technical cookie
  // tt_theme, or deleted when it matches the system setting (mode.svelte.ts); the new theme is
  // announced to screen readers.
  //
  // Variants:
  //   'default'  bordered button with a check box and the visible label (administration)
  //   'glass'    round glass button of the public header (section 13.2): a moon icon (sun when the
  //              dark theme is on), a solid border when pressed, the label "Dark theme" as visually
  //              hidden text (accessible name unchanged) and as tooltip (title)
  import { t } from '../i18n/i18n.svelte';
  import { themeMode } from '../theme/mode.svelte';
  import { announce } from './announce.svelte';
  import Icon from './Icon.svelte';

  interface Props {
    /** Look of the button: default (administration) or glass (public header). */
    variant?: 'default' | 'glass';
    class?: string;
  }

  let { variant = 'default', class: className = '' }: Props = $props();
  const mode = themeMode();
  const dark = $derived(mode.current === 'dark');

  function toggle(): void {
    const next = mode.toggle();
    announce(t(next === 'dark' ? 'components.themeSwitch.on' : 'components.themeSwitch.off'));
  }
</script>

{#if variant === 'glass'}
  <button
    type="button"
    class="tt-glass-btn tt-glass-btn--icon tt-theme--glass {className}"
    aria-pressed={dark ? 'true' : 'false'}
    title={t('components.themeSwitch.label')}
    onclick={toggle}
  >
    <Icon name={dark ? 'sun' : 'moon'} />
    <span class="visually-hidden">{t('components.themeSwitch.label')}</span>
  </button>
{:else}
  <button type="button" class="tt-theme {className}" aria-pressed={dark ? 'true' : 'false'} onclick={toggle}>
    <span class="tt-theme__box" aria-hidden="true">{dark ? '✓' : ''}</span>
    {t('components.themeSwitch.label')}
  </button>
{/if}

<style>
  .tt-theme {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-2);
    min-height: 2.25rem;
    padding: var(--tt-space-1) var(--tt-space-2);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
    color: var(--tt-text);
    cursor: pointer;
  }

  .tt-theme__box {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 1.125rem;
    height: 1.125rem;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    font-weight: var(--tt-font-weight-bold);
    line-height: 1;
  }

  /* Pressed: a solid border in the text colour, on top of the icon change (never colour alone). */
  .tt-theme--glass[aria-pressed='true'] {
    border: 2px solid var(--tt-glass-text);
  }

  :global(.tt-page--public) .tt-theme {
    min-height: 2.75rem;
  }
</style>
