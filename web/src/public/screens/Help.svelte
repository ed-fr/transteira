<script lang="ts">
  // Integrated help of the public application (CLAUDE.md section 4.2): the depositor and
  // recipient guides (src/help/HelpScreen.svelte).
  import HelpScreen from '../../help/HelpScreen.svelte';
  import { PUBLIC_GUIDES } from '../../help/help';
  import { loadPublicGuides } from '../../help/publicGuides';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { ScreenProps } from './types';

  let { params, nav }: ScreenProps = $props();
</script>

<HelpScreen
  load={loadPublicGuides}
  topic={params['topic']}
  guides={PUBLIC_GUIDES}
  {nav}
  homeLabel={t('common.backHome')}
/>
