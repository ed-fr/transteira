<script lang="ts">
  // Header of an administration screen (CLAUDE.md section 13.2): the page heading (h1 with
  // tabindex="-1", focused by the router after a navigation; its text is the screen title,
  // unchanged), an optional contextual help icon next to it, an optional muted description under
  // it, optional extra content, and the main actions of the screen on the right ("New entity",
  // the search of the home), wrapping under the title on narrow screens.
  //
  // The help icon is a snippet holding a HelpIcon whose topic is a literal string (the user guides
  // test, web/src/help/guides.test.ts, reads it in the screen source), e.g. topic "tenant-smtp".
  //
  //   <PageHeader title={t('adminTenants.smtp.title')} description={t('…')}>
  //     {#snippet help()}
  //       (HelpIcon with topic="tenant-smtp", title={t('adminTenants.smtp.title')} and nav)
  //     {/snippet}
  //     {#snippet actions()}<ActionLink to="/tenants/new" {nav} icon="plus">…</ActionLink>{/snippet}
  //   </PageHeader>
  //
  // Props:
  //   title        text of the h1 (the screen title, unchanged)
  //   description  muted text under the h1 (e.g. "Hello, superadmin · Overview of the instance")
  //   help         snippet next to the h1 (the HelpIcon of the screen)
  //   actions      snippet on the right (ActionLink, Button, a search form)
  //   children     extra content under the description (e.g. a status pill)
  //   element      the h1 element (bindable), for screens that move the focus to it
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    description?: string | undefined;
    help?: Snippet;
    actions?: Snippet;
    children?: Snippet;
    element?: HTMLHeadingElement | undefined;
    class?: string;
  }

  let {
    title,
    description,
    help,
    actions,
    children,
    element = $bindable(),
    class: className = '',
  }: Props = $props();
</script>

<div class="tt-page-header {className}">
  <div class="tt-page-header__text">
    <div class="tt-page-header__title">
      <h1 tabindex="-1" bind:this={element}>{title}</h1>
      {#if help}{@render help()}{/if}
    </div>
    {#if description}
      <p class="tt-page-header__description">{description}</p>
    {/if}
    {#if children}{@render children()}{/if}
  </div>
  {#if actions}
    <div class="tt-page-header__actions">{@render actions()}</div>
  {/if}
</div>

<style>
  /* Top-aligned: an error message under the header search makes the actions taller without
     moving the input or the other actions. */
  .tt-page-header {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--tt-space-4);
    margin-bottom: var(--tt-space-6);
  }

  .tt-page-header__text {
    flex: 1 1 18rem;
    min-width: 0;
  }

  .tt-page-header__title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--tt-space-2) var(--tt-space-3);
  }

  .tt-page-header__title h1 {
    margin: 0;
    font-size: var(--tt-font-size-2xl);
    font-weight: var(--tt-font-weight-heading);
    letter-spacing: -0.01em;
    overflow-wrap: anywhere;
  }

  .tt-page-header__description {
    margin: var(--tt-space-1) 0 0;
    color: var(--tt-muted);
  }

  .tt-page-header__actions {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--tt-space-2);
    max-width: 100%;
  }
</style>
