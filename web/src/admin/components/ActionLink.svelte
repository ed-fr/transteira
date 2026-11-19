<script lang="ts">
  // Link styled like a button (CLAUDE.md section 13.2: "New entity" in the page header, "See all",
  // "Manage the maintenance mode"): a real <a> to an application path, navigated in the
  // application (nav.link), at least 44 × 44 px, with an optional decorative icon before its text.
  // primary: TransTeira green with white text (6.2:1); secondary: surface with an --tt-border
  // outline (3:1). The text names the link; use a link (navigation), a Button for an action.
  //
  //   <ActionLink to="/tenants/new" {nav} icon="plus">{t('…')}</ActionLink>
  //   <ActionLink to="/tenants" {nav} variant="secondary">{t('…')}</ActionLink>
  //
  // Props:
  //   to         application path (without the /admin base)
  //   nav        router helpers (href, link)
  //   variant    primary (default) | secondary
  //   icon       decorative icon of the set (Icon.svelte), e.g. plus
  //   fullWidth  takes the width of its container
  //   current    aria-current of the link (rarely needed)
  //   children   the text of the link
  import type { Snippet } from 'svelte';
  import Icon from '../../shared/components/Icon.svelte';
  import type { IconName } from '../../shared/components/icons';
  import type { Router } from '../../shared/router/router.svelte';
  import type { AriaCurrent } from '../shell';

  interface Props {
    /** Application path of the target. */
    to: string;
    /** Router helpers. */
    nav: Pick<Router, 'href' | 'link'>;
    variant?: 'primary' | 'secondary';
    icon?: IconName | undefined;
    fullWidth?: boolean;
    current?: AriaCurrent;
    children: Snippet;
    class?: string;
  }

  let {
    to,
    nav,
    variant = 'primary',
    icon,
    fullWidth = false,
    current,
    children,
    class: className = '',
  }: Props = $props();
</script>

<a
  class="tt-action-link tt-action-link--{variant} {className}"
  class:tt-action-link--full={fullWidth}
  href={nav.href(to)}
  aria-current={current}
  use:nav.link
>
  {#if icon}<Icon name={icon} size="sm" />{/if}
  <span class="tt-action-link__label">{@render children()}</span>
</a>

<style>
  .tt-action-link {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--tt-space-2);
    min-width: var(--tt-control-height);
    min-height: var(--tt-control-height);
    padding: var(--tt-space-2) 1.125rem;
    border: 2px solid transparent;
    border-radius: 0.625rem;
    font-weight: var(--tt-font-weight-bold);
    line-height: var(--tt-line-height-tight);
    text-align: center;
    text-decoration: none;
  }

  .tt-action-link--full {
    width: 100%;
  }

  .tt-action-link--primary {
    border-color: var(--tt-primary);
    background: var(--tt-primary);
    color: var(--tt-on-primary);
  }

  .tt-action-link--secondary {
    border: var(--tt-border-width) solid var(--tt-border);
    background: var(--tt-surface);
    color: var(--tt-text);
  }

  .tt-action-link:hover .tt-action-link__label {
    text-decoration: underline;
    text-underline-offset: 0.15em;
  }

  @media (forced-colors: active) {
    .tt-action-link {
      border-color: LinkText;
    }
  }
</style>
