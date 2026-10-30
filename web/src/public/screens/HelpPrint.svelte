<script lang="ts">
  // Printable version of the public guides (/help/print, CLAUDE.md section 4.2, threat model
  // P29): the depositor and recipient guides of the current language with the real rules of the
  // tenant, printed or saved as PDF by the browser. The guides are loaded like the help screen
  // (reloaded on a language change, retry on failure); the application version is read once
  // from GET /version ("—" when it fails). The document itself is HelpPrintDocument.svelte.
  import { onMount } from 'svelte';
  import HelpPrintDocument from '../../help/HelpPrintDocument.svelte';
  import { loadPublicGuides } from '../../help/publicGuides';
  import { loadVersion, printGuides } from '../../help/print';
  import type { HelpGuide } from '../../help/types';
  import { api } from '../../shared/api/api';
  import { locale } from '../../shared/i18n/i18n.svelte';
  import type { ScreenProps } from './types';

  let { tenant, nav }: ScreenProps = $props();

  let guides = $state.raw<HelpGuide[] | undefined>();
  let guideLang = $state<string | undefined>();
  let failed = $state(false);
  let attempt = $state(0);
  let version = $state<string | undefined>();
  const generatedAt = new Date();

  $effect(() => {
    const lang = locale.current;
    void attempt;
    let cancelled = false;
    failed = false;
    loadPublicGuides(lang).then(
      (set) => {
        if (cancelled) return;
        guides = printGuides(set);
        guideLang = set.lang !== lang ? set.lang : undefined;
      },
      () => {
        if (!cancelled) failed = true;
      },
    );
    return () => {
      cancelled = true;
    };
  });

  onMount(() => {
    void loadVersion(async () => (await api.get('/version')).data).then((v) => {
      version = v;
    });
  });
</script>

<HelpPrintDocument
  rules={tenant}
  logoUrl={tenant.branding.logoUrl}
  {guides}
  {guideLang}
  {failed}
  {version}
  {generatedAt}
  helpHref={nav.href('/help')}
  link={nav.link}
  onretry={() => attempt++}
/>
