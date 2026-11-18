<script lang="ts">
  // Banner of the read page of an express secret (CLAUDE.md section 22.2, threat model T-397,
  // decision P88): the text was written by an unverified third party, not by the entity whose
  // name and logo frame the page. A static note (role="note", not a live region: it is part of
  // the page from its first rendering) in the warning colours, which a tenant never overrides;
  // the severity is also spelled out for screen readers (RGAA 3.1).
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Name of the tenant (the entity that is not the author). */
    entity: string;
  }

  let { entity }: Props = $props();
</script>

<div class="express-banner" role="note" id="tt-secret-express-banner" data-testid="secret-express-banner">
  <p class="express-banner__title">
    <span class="visually-hidden">{t('components.alert.warning')}</span>
    {t('secret.reveal.express.banner', { entity })}
  </p>
  <p class="express-banner__hint">{t('secret.reveal.express.hint')}</p>
</div>

<style>
  .express-banner {
    margin-bottom: var(--tt-space-4);
    padding: var(--tt-space-3) var(--tt-space-4);
    border: var(--tt-border-width) solid currentColor;
    border-left-width: 0.375rem;
    border-radius: var(--tt-radius);
    background: var(--tt-warning-bg);
    color: var(--tt-warning);
  }

  .express-banner__title {
    margin: 0 0 var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .express-banner__hint {
    margin: 0;
  }
</style>
