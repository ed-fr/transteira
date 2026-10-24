<script lang="ts">
  // Action of an audit event: its translated label, followed by the raw code when the action is
  // known (an unknown action is already shown as its code).
  import { t } from '../../shared/i18n/i18n.svelte';
  import { actionLabel, isKnownAction } from '../screens/ops/auditLabels';

  interface Props {
    /** Action code of the event ("domain.verb"). */
    action: string;
  }

  const { action }: Props = $props();
</script>

{actionLabel(action, t)}
{#if isKnownAction(action)}<code class="tt-audit__code">{action}</code>{/if}

<style>
  .tt-audit__code {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
    font-family: var(--tt-font-mono);
    overflow-wrap: anywhere;
  }
</style>
