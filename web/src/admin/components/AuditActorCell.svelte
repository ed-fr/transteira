<script lang="ts">
  // Actor of an audit event: kind label, identifier and an optional hint (pseudonym of an erased
  // address), as computed by actorView. Plain text only.
  import { t } from '../../shared/i18n/i18n.svelte';
  import { actorView } from '../screens/ops/auditLabels';

  interface Props {
    /** Actor of the event. */
    actor: { kind: string; id: string };
  }

  const { actor }: Props = $props();

  const view = $derived(actorView(actor, t));
</script>

<span class="tt-audit__kind">{view.kind}</span>
<span class="tt-break">{view.id}</span>
{#if view.hint}<span class="tt-audit__hint">{view.hint}</span>{/if}

<style>
  .tt-audit__kind,
  .tt-audit__hint {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
