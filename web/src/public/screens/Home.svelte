<script lang="ts">
  // Home route "/": the deposit screen (src/public/deposit, step 15 wave 2E).
  import DepositScreen from '../deposit/DepositScreen.svelte';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { ScreenProps } from './types';

  let { tenant, nav }: ScreenProps = $props();
</script>

<DepositScreen
  {tenant}
  onnavigate={(path) => void nav.navigate(path)}
  addGuard={(guard) => nav.addGuard(guard)}
/>

<p class="tt-text-sm tt-mt-4">
  <a href={nav.href('/me')} use:nav.link>{t('myTransfers.homeLink')}</a>
</p>
