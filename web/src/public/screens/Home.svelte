<script lang="ts">
  // Home route "/": the deposit screen (src/public/deposit, step 15 wave 2E).
  import DepositScreen from '../deposit/DepositScreen.svelte';
  import type { ScreenProps } from './types';

  let { tenant, nav }: ScreenProps = $props();
</script>

<DepositScreen
  {tenant}
  onnavigate={(path) => void nav.navigate(path)}
  addGuard={(guard) => nav.addGuard(guard)}
/>
