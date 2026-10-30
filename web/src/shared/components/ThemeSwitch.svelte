<script lang="ts">
  // Theme switch (CLAUDE.md section 13.1): one native toggle button "Dark theme", pressed
  // (aria-pressed) when the dark theme is shown, with a visible check mark so that the state is
  // not conveyed by the page colours alone. The choice is stored in the technical cookie
  // tt_theme, or deleted when it matches the system setting (mode.svelte.ts); the new theme is
  // announced to screen readers.
  import { t } from '../i18n/i18n.svelte';
  import { themeMode } from '../theme/mode.svelte';
  import { announce } from './announce.svelte';

  interface Props {
    class?: string;
  }

  let { class: className = '' }: Props = $props();
  const mode = themeMode();
  const dark = $derived(mode.current === 'dark');

  function toggle(): void {
    const next = mode.toggle();
    announce(t(next === 'dark' ? 'components.themeSwitch.on' : 'components.themeSwitch.off'));
  }
</script>

<button type="button" class="tt-theme {className}" aria-pressed={dark ? 'true' : 'false'} onclick={toggle}>
  <span class="tt-theme__box" aria-hidden="true">{dark ? '✓' : ''}</span>
  {t('components.themeSwitch.label')}
</button>

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
</style>
