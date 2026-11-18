<script lang="ts">
  // Home route "/": the deposit screen (src/public/deposit, step 15 wave 2E). The "My transfers"
  // link lives in the page header (frame/HeaderActions.svelte) since 2.3.
  import DepositScreen from '../deposit/DepositScreen.svelte';
  import type { ScreenProps } from './types';

  let { tenant, nav }: ScreenProps = $props();
</script>

<DepositScreen
  {tenant}
  onnavigate={(path) => void nav.navigate(path)}
  addGuard={(guard) => nav.addGuard(guard)}
/>
