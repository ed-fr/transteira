<script lang="ts">
  // Page shown when the deposit session has expired or is missing (401): the user identifies
  // again from the deposit page.
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { Navigation } from './types';

  interface Props {
    nav: Navigation;
    /** Heading; defaults to "Session expired". */
    title?: string;
    /** Explanation; defaults to the generic text. */
    text?: string;
  }

  let { nav, title, text }: Props = $props();
</script>

<h1 tabindex="-1">{title ?? t('common.sessionExpired.title')}</h1>
<p>{text ?? t('common.sessionExpired.text')}</p>
<p><a href={nav.href('/')} use:nav.link>{t('common.sessionExpired.action')}</a></p>
