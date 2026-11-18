<script lang="ts">
  // Language selector: a labelled native <select>, each language offered under its own name
  // with its lang attribute (RGAA 8.7). Renders nothing when only one language is available.
  //
  // Variants:
  //   'default'  visible label "Language" and a bordered select (administration)
  //   'glass'    glass pill of the public header (section 13.2): globe icon, the name of the
  //              current language and a chevron; the label "Language" stays the accessible name
  //              (visually hidden <label>) and the tooltip (title). The options keep the surface
  //              colours, whatever the platform draws them with.
  import { t } from '../i18n/i18n.svelte';
  import { languageName } from './helpers';
  import Icon from './Icon.svelte';

  interface Props {
    /** Languages offered (PublicTenant.availableLanguages). */
    languages: readonly string[];
    /** Current language. */
    current: string;
    /** Called with the chosen language. */
    onchange: (language: string) => void;
    /** Look of the selector: default (administration) or glass (public header). */
    variant?: 'default' | 'glass';
    class?: string;
  }

  let { languages, current, onchange, variant = 'default', class: className = '' }: Props = $props();
  const uid = $props.id();
  const glass = $derived(variant === 'glass');
</script>

{#if languages.length > 1}
  <div class="tt-lang {className}" class:tt-lang--glass={glass}>
    <label class="tt-lang__label" class:visually-hidden={glass} for="{uid}-lang"
      >{t('components.languageSwitch.label')}</label
    >
    <span class="tt-lang__field">
      {#if glass}<span class="tt-lang__icon tt-lang__icon--start"><Icon name="globe" size="sm" /></span>{/if}
      <select
        id="{uid}-lang"
        class="tt-lang__select"
        title={glass ? t('components.languageSwitch.label') : undefined}
        value={current}
        onchange={(event) => onchange(event.currentTarget.value)}
      >
        {#each languages as language (language)}
          <option value={language} lang={language}>{languageName(language)}</option>
        {/each}
      </select>
      {#if glass}<span class="tt-lang__icon tt-lang__icon--end"><Icon name="chevron" size="sm" /></span>{/if}
    </span>
  </div>
{/if}

<style>
  .tt-lang {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-2);
  }

  .tt-lang__field {
    position: relative;
    display: inline-flex;
    align-items: center;
  }

  .tt-lang__select {
    min-height: 2.25rem;
    padding: var(--tt-space-1) var(--tt-space-2);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
  }

  :global(.tt-page--public) .tt-lang__select {
    min-height: 2.75rem;
  }

  /* Glass pill: the icons are drawn over the select and let the clicks through. */
  .tt-lang--glass .tt-lang__select {
    appearance: none;
    min-height: 2.75rem;
    padding: var(--tt-space-1) 2.25rem;
    border-color: var(--tt-glass-border);
    border-radius: var(--tt-radius-full);
    background: var(--tt-glass-bg);
    color: var(--tt-glass-text);
    font-size: var(--tt-font-size-sm);
    font-weight: var(--tt-font-weight-bold);
    cursor: pointer;
    -webkit-backdrop-filter: blur(0.5rem);
    backdrop-filter: blur(0.5rem);
  }

  .tt-lang--glass .tt-lang__select:hover {
    text-decoration: underline;
  }

  .tt-lang--glass .tt-lang__select:focus-visible {
    outline-color: var(--tt-glass-focus);
    box-shadow: 0 0 0 calc(var(--tt-focus-width) + 2px) var(--tt-glass-ring);
  }

  .tt-lang--glass option {
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  /* Above the select, whose backdrop filter makes it a stacking context painted after them. */
  .tt-lang__icon {
    position: absolute;
    z-index: 1;
    top: 50%;
    display: inline-flex;
    color: var(--tt-glass-text);
    transform: translateY(-50%);
    pointer-events: none;
  }

  .tt-lang__icon--start {
    left: 0.875rem;
  }

  .tt-lang__icon--end {
    right: 0.875rem;
  }

  @media (forced-colors: active) {
    .tt-lang--glass .tt-lang__select {
      border-color: ButtonText;
    }

    .tt-lang__icon {
      color: ButtonText;
    }
  }
</style>
