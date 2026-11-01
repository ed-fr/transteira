<script lang="ts">
  // Background library of a tenant (CLAUDE.md section 13): a radio group of the images generated
  // by the server (RGAA 11.1, 11.5, 12.8). A native radio group gives the keyboard navigation
  // (arrows, Tab to the group); the thumbnails are the preview endpoint, loaded lazily. The
  // choice is saved with the explicit "Apply" button. An uploaded background takes precedence:
  // the choice then only applies once the custom background is removed.
  import { describeError } from '../../shared/api/problem';
  import { Alert, Spinner } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { adminApi } from '../api';
  import {
    DEFAULT_PRESET,
    choiceChanged,
    normalizeChoice,
    presetToSend,
    type PresetItem,
  } from './backgroundPresets';
  import BackgroundPresetPicker from './BackgroundPresetPicker.svelte';
  import FormSection from './FormSection.svelte';
  import type { SubmitOutcome } from './form';

  interface Props {
    /** Tenant to configure. */
    tenantId: string;
    /** Preset currently saved for the tenant (absent: default). */
    preset?: string | null | undefined;
    /** Whether a custom background is uploaded (it takes precedence over the library). */
    hasBackground: boolean;
    /** Registers a navigation guard (router.addGuard). */
    addGuard?: ((guard: (path: string) => boolean) => () => void) | undefined;
  }

  const { tenantId, preset = undefined, hasBackground, addGuard }: Props = $props();

  let status = $state<'loading' | 'ready' | 'error'>('loading');
  let loadError = $state('');
  let items = $state.raw<PresetItem[]>([]);
  let savedPreset = $state<string | null | undefined>(undefined);
  let choice = $state(DEFAULT_PRESET);

  // Follows the preset given by the parent (re-run only when it changes).
  $effect(() => {
    savedPreset = preset;
    choice = normalizeChoice(preset);
  });

  const dirty = $derived(choiceChanged(choice, savedPreset));

  $effect(() => {
    void loadItems();
  });

  async function loadItems(): Promise<void> {
    status = 'loading';
    try {
      const res = await adminApi.get('/admin/background-presets');
      items = res.data.items;
      status = 'ready';
    } catch (err) {
      loadError = describeError(i18n, err).message;
      status = 'error';
    }
  }

  async function save(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/branding/background-preset', {
        path: { tenantId },
        body: { preset: presetToSend(choice) },
      });
      savedPreset = res.data.backgroundPreset;
      choice = normalizeChoice(res.data.backgroundPreset);
    } catch (err) {
      return { ok: false, errors: [], message: describeError(i18n, err).message };
    }
    return { ok: true, message: t('adminTenants.branding.library.saved') };
  }
</script>

<section class="tt-presets">
  {#if status === 'loading'}
    <h2 class="tt-presets__heading">{t('adminTenants.branding.library.title')}</h2>
    <p><Spinner label={t('admin.common.loading')} showLabel /></p>
  {:else if status === 'error'}
    <h2 class="tt-presets__heading">{t('adminTenants.branding.library.title')}</h2>
    <Alert severity="error">{loadError}</Alert>
  {:else}
    <FormSection
      title={t('adminTenants.branding.library.title')}
      intro={t('adminTenants.branding.library.intro')}
      {dirty}
      {addGuard}
      onsubmit={save}
      saveLabel={t('adminTenants.branding.library.apply')}
      savingLabel={t('adminTenants.branding.library.applying')}
      successMessage={t('adminTenants.branding.library.saved')}
    >
      <p class="tt-presets__note">
        {hasBackground
          ? t('adminTenants.branding.library.customActive')
          : t('adminTenants.branding.library.customNote')}
      </p>
      <BackgroundPresetPicker {items} legend={t('adminTenants.branding.library.legend')} bind:choice />
    </FormSection>
  {/if}
</section>

<style>
  .tt-presets {
    margin-bottom: var(--tt-space-8);
  }

  .tt-presets__heading {
    margin: 0 0 var(--tt-space-2);
  }

  .tt-presets__note {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
