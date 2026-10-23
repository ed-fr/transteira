<script lang="ts">
  // The two live regions of the shared announcer (announce() in announce.svelte.ts). Mounted
  // once per page by PageLayout; mount it yourself only in a page that does not use PageLayout.
  import { announcer } from './announce.svelte';
  import LiveRegion from './LiveRegion.svelte';
</script>

<LiveRegion message={announcer.state.polite} politeness="polite" />
<LiveRegion message={announcer.state.assertive} politeness="assertive" />
