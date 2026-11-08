<script lang="ts">
  // Integrated help of the administration (CLAUDE.md section 4.2): each signed-in role gets its
  // own guide (delegated admin: delegated-admin; auditor: auditor, where a topic of a screen opens
  // its auditor-<topic> counterpart); a super admin and a visitor not signed in (first-run setup,
  // sign-in, activation) get all three (adminGuides, src/help/HelpScreen.svelte).
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
