<script lang="ts">
  // Integrated help of the administration (CLAUDE.md section 4.2): each signed-in role gets its
  // own guide (delegated admin: delegated-admin; auditor: auditor, where a topic of a screen opens
  // its auditor-<topic> counterpart); a super admin and a visitor not signed in (first-run setup,
  // sign-in, activation) get all three (adminGuides, src/help/HelpScreen.svelte).
  // HelpScreen is shared with the public application and renders its own h1. Signed in, the
  // administration frame (AdminShell) has no card of its own, so the help goes in a card like the
  // content of the other screens (CLAUDE.md section 13.2); signed out (setup, sign-in, activation),
  // PageLayout already renders it in its card.
  import HelpScreen from '../../help/HelpScreen.svelte';
  import { loadAdminGuides } from '../../help/adminGuides';
  import { adminGuides } from '../../help/help';
  import { t } from '../../shared/i18n/i18n.svelte';
  import { adminSession } from '../api';
  import Card from '../components/Card.svelte';
  import { inAdminFrame } from '../shell';
  import type { AdminScreenProps } from './types';

  let { params, nav }: AdminScreenProps = $props();
  const guides = $derived(adminGuides(adminSession.me?.role));
  const framed = $derived(inAdminFrame(adminSession));
</script>

{#snippet screen()}
  <HelpScreen load={loadAdminGuides} topic={params['topic']} {guides} {nav} homeLabel={t('admin.backHome')} />
{/snippet}

{#if framed}
  <Card tag="div" padding="lg">{@render screen()}</Card>
{:else}
  {@render screen()}
{/if}
