<script lang="ts">
  // Administration home (provisional until step 17): welcome, shortcuts to the sections the
  // admin may open, and a recommendation to enable two-factor authentication when it is off.
  import { Alert } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { adminSession } from '../api';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();
  const me = $derived(adminSession.me);
</script>

<h1 tabindex="-1">{t('admin.home.title')}</h1>
{#if me}
  <p>{t('admin.home.welcome', { username: me.username })}</p>
  {#if !me.totpEnabled}
    <Alert severity="warning" live={false}>
      <p>{t('admin.home.totpRecommended')}</p>
    </Alert>
  {/if}
{/if}
<p>{t('admin.home.intro')}</p>
<ul>
  <li><a href={nav.href('/tenants')} use:nav.link>{t('admin.home.tenantsLink')}</a></li>
  {#if me?.role === 'super_admin'}
    <li><a href={nav.href('/admins')} use:nav.link>{t('admin.home.adminsLink')}</a></li>
  {/if}
  <li><a href={nav.href('/account')} use:nav.link>{t('admin.home.accountLink')}</a></li>
</ul>
