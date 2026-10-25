<script lang="ts">
  // Integrated help of the administration (CLAUDE.md section 4.2): the delegated-admin guide, and
  // the super-admin guide for a super admin or a visitor not signed in (first-run setup, sign-in,
  // activation), never for a signed-in delegated admin (src/help/HelpScreen.svelte).
  import HelpScreen from '../../help/HelpScreen.svelte';
  import { loadAdminGuides } from '../../help/adminGuides';
  import { adminGuides } from '../../help/help';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { adminSession } from '../api';
  import type { AdminScreenProps } from './types';

  let { params, nav }: AdminScreenProps = $props();
  const guides = $derived(adminGuides(adminSession.me?.role));
</script>

<HelpScreen load={loadAdminGuides} topic={params['topic']} {guides} {nav} homeLabel={t('admin.backHome')} />
