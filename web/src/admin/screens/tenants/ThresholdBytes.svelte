<script lang="ts">
  // A nullable size threshold of the abuse detection screen: a box that enables the rule
  // (unchecked: null in the API) and, when enabled, a size field with its unit (MiB, GiB, TiB).
  import { Checkbox } from '../../../shared/components';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import ByteSizeField from '../../components/ByteSizeField.svelte';
  import type { OptionalBytes } from './abuse';

  interface Props {
    /** Id of the amount field (the box has this id plus "-enabled"). */
    id: string;
    /** Name of the rule, label of the box and of the amount. */
    label: string;
    /** Help text of the amount. */
    hint?: string;
    /** Bound state. */
    value: OptionalBytes;
    /** Error of the amount. */
    error?: string | undefined;
  }

  let { id, label, hint, value = $bindable(), error }: Props = $props();
</script>

<div class="tt-threshold">
  <Checkbox
    id="{id}-enabled"
    label={t('adminAbuse.thresholds.enable', { rule: label })}
    bind:checked={value.enabled}
  />
  {#if value.enabled}
    <ByteSizeField {id} {label} {hint} required bind:bytes={value.bytes} {error} />
  {/if}
</div>

<style>
  .tt-threshold {
    margin-bottom: var(--tt-space-4);
  }
</style>
