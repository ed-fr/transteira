<script lang="ts">
  // A nullable whole number threshold of the abuse detection screen: a box that enables the
  // rule (unchecked: the rule is disabled, null in the API) and, when enabled, the value field.
  import { Checkbox, TextField } from '../../../shared/components';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import type { OptionalCount } from './abuse';

  interface Props {
    /** Id of the value field (the box has this id plus "-enabled"). */
    id: string;
    /** Name of the rule, label of the box and of the value. */
    label: string;
    /** Help text of the value. */
    hint?: string;
    /** Bound state. */
    value: OptionalCount;
    /** Error of the value. */
    error?: string | undefined;
    inputmode?: 'numeric' | 'decimal';
  }

  let { id, label, hint, value = $bindable(), error, inputmode = 'numeric' }: Props = $props();
</script>

<div class="tt-threshold">
  <Checkbox
    id="{id}-enabled"
    label={t('adminAbuse.thresholds.enable', { rule: label })}
    bind:checked={value.enabled}
  />
  {#if value.enabled}
    <TextField {id} {label} {hint} {inputmode} autocomplete="off" required bind:value={value.text} {error} />
  {/if}
</div>

<style>
  .tt-threshold {
    margin-bottom: var(--tt-space-4);
  }
</style>
