<script lang="ts">
  // Object of an audit event: kind label and identifier, with an optional hint. A transfer links
  // to its detail page when the tenant of the event is known (objectPath).
  import { t } from '../../shared/i18n/i18n.svelte';
  import { objectPath, objectView } from '../screens/ops/auditLabels';
  import type { Navigation } from '../screens/types';

  interface Props {
    /** Object of the event. */
    object: { kind: string; id: string };
    /** Tenant the object belongs to (the event's tenant); no link without it. */
    tenantId: string | null | undefined;
    /** Router helpers of the screen (href and link action). */
    nav: Navigation;
  }

  const { object, tenantId, nav }: Props = $props();

  const view = $derived(objectView(object, t));
  const path = $derived(objectPath(tenantId, object));
</script>

<span class="tt-audit__kind">{view.kind}</span>
{#if path !== undefined}
  <a
    class="tt-break"
    href={nav.href(path)}
    use:nav.link
    aria-label={t('opsAudit.list.openTransfer', { id: view.id })}>{view.id}</a
  >
{:else}
  <span class="tt-break">{view.id}</span>
{/if}
{#if view.hint}<span class="tt-audit__hint">{view.hint}</span>{/if}

<style>
  .tt-audit__kind,
  .tt-audit__hint {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
