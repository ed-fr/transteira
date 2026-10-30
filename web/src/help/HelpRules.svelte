<script lang="ts">
  // Rules block of a public guide ("<!-- rules: <set> -->"): the real rules of the current
  // tenant (rules.ts), rendered as text nodes only, never {@html} nor Markdown (threat model
  // T-232). Without rules (admin application, tests outside a tenant) it renders nothing, as does
  // the levels set when the tenant offers a single level imposing nothing.
  import { formatBytes, locale, t } from '../shared/i18n/i18n.svelte';
  import { levelViews, limitItems, summaryItems, type HelpTenantRules, type RulesFormat } from './rules';
  import type { RulesSet } from './types';

  interface Props {
    set: RulesSet;
    rules?: HelpTenantRules | undefined;
  }

  let { set, rules }: Props = $props();

  const fmt: RulesFormat = {
    t,
    bytes: formatBytes,
    list: (items) => new Intl.ListFormat(locale.current || 'en', { type: 'conjunction' }).format(items),
  };

  const items = $derived(
    rules === undefined || set === 'levels'
      ? []
      : set === 'summary'
        ? summaryItems(rules, fmt)
        : limitItems(rules, fmt),
  );
  const levels = $derived(rules === undefined || set !== 'levels' ? [] : levelViews(rules, fmt));
</script>

{#if rules !== undefined && set === 'summary'}
  <div class="help-rules">
    <p>{t('help.rules.summary.intro', { name: rules.name })}</p>
    <ul>
      {#each items as item (item)}
        <li>{item}</li>
      {/each}
    </ul>
  </div>
{:else if set === 'limits' && items.length > 0}
  <ul class="help-rules">
    {#each items as item (item)}
      <li>{item}</li>
    {/each}
  </ul>
{:else if levels.length > 0}
  <div class="help-rules">
    <p>{t('help.rules.levels.intro')}</p>
    <ul class="help-rules__levels">
      {#each levels as level (level.key)}
        <li>
          <strong>{level.label}</strong>{#if level.isDefault}{` ${t('help.rules.levels.default')}`}{/if}
          {#if level.description !== undefined}
            <p class="help-rules__description">{level.description}</p>
          {/if}
          <ul>
            {#if level.rules.length === 0}
              <li>{t('help.rules.levels.none')}</li>
            {/if}
            {#each level.rules as rule (rule)}
              <li>{rule}</li>
            {/each}
          </ul>
        </li>
      {/each}
    </ul>
  </div>
{/if}

<style>
  .help-rules {
    margin: var(--tt-space-4) 0;
    padding: var(--tt-space-3) var(--tt-space-4);
    border-left: 4px solid var(--tt-graphic);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
  }

  ul.help-rules {
    padding-left: var(--tt-space-8);
  }

  .help-rules p {
    margin: 0 0 var(--tt-space-2);
  }

  .help-rules__levels > li + li {
    margin-top: var(--tt-space-3);
  }

  .help-rules .help-rules__description {
    margin: var(--tt-space-1) 0;
    white-space: pre-line;
  }

  @media print {
    .help-rules {
      break-inside: avoid;
    }
  }
</style>
