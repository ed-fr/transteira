<script lang="ts">
  // Language selector: a labelled native <select>, each language offered under its own name
  // with its lang attribute (RGAA 8.7). Renders nothing when only one language is available.
  import { t } from '../i18n/i18n.svelte';
  import { languageName } from './helpers';

  interface Props {
    /** Languages offered (PublicTenant.availableLanguages). */
    languages: readonly string[];
    /** Current language. */
    current: string;
    /** Called with the chosen language. */
    onchange: (language: string) => void;
    class?: string;
  }

  let { languages, current, onchange, class: className = '' }: Props = $props();
  const uid = $props.id();
</script>

{#if languages.length > 1}
  <div class="tt-lang {className}">
    <label class="tt-lang__label" for="{uid}-lang">{t('components.languageSwitch.label')}</label>
    <select
      id="{uid}-lang"
      class="tt-lang__select"
      value={current}
      onchange={(event) => onchange(event.currentTarget.value)}
    >
      {#each languages as language (language)}
        <option value={language} lang={language}>{languageName(language)}</option>
      {/each}
    </select>
  </div>
{/if}

<style>
  .tt-lang {
    display: inline-flex;
    align-items: center;
    gap: var(--tt-space-2);
  }

  .tt-lang__select {
    min-height: 2.25rem;
    padding: var(--tt-space-1) var(--tt-space-2);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface);
  }
</style>
