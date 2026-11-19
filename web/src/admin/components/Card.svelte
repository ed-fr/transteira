<script lang="ts">
  // Card of the administration (CLAUDE.md section 13.2): a white surface (--tt-surface) with a
  // decorative --tt-separator border and 16 px corners on the muted page background, holding a
  // block of a screen. With a title, it is a <section> named by its heading (aria-labelledby), the
  // heading level following the outline of the screen (h2 by default); actions (links, buttons,
  // e.g. "See all") sit on the right of the heading and wrap under it on narrow screens.
  //
  //   <Card title={t('…')} headingLevel={2}>
  //     {#snippet actions()}<ActionLink to="/tenants" {nav} variant="secondary">…</ActionLink>{/snippet}
  //     <p>…</p>
  //   </Card>
  //   <Card title={t('…')} flush>
  //     <DataTable variant="plain" captionHidden … />   (a table edge to edge in the card)
  //   </Card>
  //
  // Props:
  //   title         heading of the card (optional: a card without title is a plain <div>)
  //   headingLevel  2 (default), 3 or 4
  //   headingId     id of the heading (default: generated), e.g. to name another element
  //   description   muted text under the heading
  //   actions       snippet on the right of the heading
  //   padding       sm | md (default) | lg: inner spacing
  //   flush         the body has no padding (tables), the header keeps it
  //   tag           section (default with a title) | div (default without) | article
  //   children      content of the card
  import type { Snippet } from 'svelte';

  interface Props {
    title?: string | undefined;
    headingLevel?: 2 | 3 | 4;
    headingId?: string | undefined;
    description?: string | undefined;
    actions?: Snippet;
    padding?: 'sm' | 'md' | 'lg';
    flush?: boolean;
    tag?: 'section' | 'div' | 'article';
    children: Snippet;
    class?: string;
  }

  let {
    title,
    headingLevel = 2,
    headingId,
    description,
    actions,
    padding = 'md',
    flush = false,
    tag,
    children,
    class: className = '',
  }: Props = $props();

  const uid = $props.id();
  const id = $derived(headingId ?? `${uid}-title`);
  const element = $derived(tag ?? (title !== undefined ? 'section' : 'div'));
  const named = $derived(title !== undefined && element !== 'div');
  const hasHeader = $derived(title !== undefined || actions !== undefined);
</script>

<svelte:element
  this={element}
  class="tt-admin-card tt-admin-card--{padding} {className}"
  class:tt-admin-card--flush={flush}
  aria-labelledby={named ? id : undefined}
>
  {#if hasHeader}
    <div class="tt-admin-card__header">
      {#if title !== undefined}
        <svelte:element this={`h${headingLevel}`} {id} class="tt-admin-card__title">{title}</svelte:element>
      {/if}
      {#if actions}
        <div class="tt-admin-card__actions">{@render actions()}</div>
      {/if}
    </div>
  {/if}
  {#if description}
    <p class="tt-admin-card__description">{description}</p>
  {/if}
  <div class="tt-admin-card__body">
    {@render children()}
  </div>
</svelte:element>

<style>
  .tt-admin-card {
    --tt-card-pad: var(--tt-space-5);

    min-width: 0;
    margin-bottom: var(--tt-space-4);
    border: var(--tt-border-width) solid var(--tt-separator);
    border-radius: var(--tt-radius-lg);
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-admin-card--sm {
    --tt-card-pad: var(--tt-space-4);
  }

  .tt-admin-card--lg {
    --tt-card-pad: var(--tt-space-6);
  }

  .tt-admin-card__header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--tt-space-2) var(--tt-space-4);
    padding: var(--tt-card-pad) var(--tt-card-pad) 0;
  }

  .tt-admin-card__title {
    margin: 0;
    font-size: var(--tt-font-size-lg);
    font-weight: var(--tt-font-weight-heading);
  }

  .tt-admin-card__actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2);
  }

  .tt-admin-card__description {
    margin: var(--tt-space-1) 0 0;
    padding: 0 var(--tt-card-pad);
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }

  .tt-admin-card__body {
    padding: var(--tt-card-pad);
  }

  .tt-admin-card__header + .tt-admin-card__body,
  .tt-admin-card__description + .tt-admin-card__body {
    padding-top: var(--tt-space-4);
  }

  .tt-admin-card--flush > .tt-admin-card__body {
    padding: var(--tt-space-3) 0 0;
  }

  /* The last element of the body adds no margin under it. */
  .tt-admin-card__body > :global(:last-child) {
    margin-bottom: 0;
  }

  @media (max-width: 40rem) {
    .tt-admin-card {
      --tt-card-pad: var(--tt-space-4);
    }
  }

  @media (forced-colors: active) {
    .tt-admin-card {
      border-color: CanvasText;
    }
  }
</style>
