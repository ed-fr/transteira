<script lang="ts">
  // "Page not found" page: unknown paths (the server already answers them with HTTP 404), and
  // screens whose resource does not exist. The heading takes the focus after a navigation.
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from './types';

  interface Props {
    /** Router helpers; the home link is a plain link without them. */
    nav?: Navigation;
    /** Heading; defaults to "Page not found". */
    title?: string;
    /** Explanation; defaults to the generic text. */
    text?: string;
    /** Shows the link to the home page (default true). */
    homeLink?: boolean;
  }

  let { nav, title, text, homeLink = true }: Props = $props();
  const noop = (): { destroy(): void } => ({ destroy() {} });
  const link = $derived(nav?.link ?? noop);
</script>

<h1 tabindex="-1">{title ?? t('common.notFound.title')}</h1>
<p>{text ?? t('common.notFound.text')}</p>
{#if homeLink}
  <p><a href={nav?.href('/') ?? '/'} use:link>{t('common.backHome')}</a></p>
{/if}
