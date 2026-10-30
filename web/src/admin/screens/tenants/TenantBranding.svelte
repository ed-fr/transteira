<script lang="ts">
  // Branding of a tenant (CLAUDE.md section 13): colours with their RGAA contrast, a preview of
  // the public page, then the logo and the background image.
  // - Contrast: computed live while editing (contrast.ts), then replaced by the results of the
  //   server for the saved colours, which are authoritative (contrastView). An insufficient
  //   contrast in the light theme is a warning, never a blocking error: the colours can still be
  //   saved. A dark pair (*-on-dark) below AA only gives an informational note: the dark theme
  //   then keeps its accessible default link and focus colours.
  // - The tenant sub-navigation (TenantNav) is rendered by App.svelte above this screen.
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Spinner } from '../../../shared/components';
  import { i18n, formatNumber, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import BrandPreview from '../../components/BrandPreview.svelte';
  import ColorField from '../../components/ColorField.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import ImageUpload from '../../components/ImageUpload.svelte';
  import { colorChanged, colorError, rowsForPairs, serverFailures } from '../../components/branding';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import {
    contrastFailures,
    contrastView,
    darkFallbacks,
    type ContrastRow,
    type SavedBranding,
  } from '../../forms/contrastView';
  import type { AdminScreenProps } from '../types';

  const { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const ids = { primary: 'branding-primary', accent: 'branding-accent' } as const;
  const hexId = (base: string): string => `${base}-hex`;

  let status = $state<'loading' | 'ready' | 'error'>('loading');
  let loadError = $state('');
  let saved = $state.raw<SavedBranding | null>(null);
  let primary = $state('');
  let accent = $state('');
  let hasLogo = $state(false);
  let hasBackground = $state(false);
  let logoUrl = $state<string | null>(null);
  let errors = $state<SummaryError[]>([]);

  const edited = $derived({ primaryColor: primary.trim(), accentColor: accent.trim() });
  const rows = $derived(contrastView(edited, saved));
  const failing = $derived(contrastFailures(rows));
  const fallbacks = $derived(darkFallbacks(rows));
  const fromServer = $derived(rows.length > 0 && rows.every((r) => r.source === 'server'));
  const dirty = $derived(
    saved !== null && (colorChanged(primary, saved.primaryColor) || colorChanged(accent, saved.accentColor)),
  );

  // (Re)load whenever the tenant of the route changes.
  $effect(() => {
    void load(tenantId);
  });

  async function load(id: string): Promise<void> {
    status = 'loading';
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/branding', { path: { tenantId: id } });
      if (id !== tenantId) {
        return;
      }
      apply(res.data);
      status = 'ready';
    } catch (err) {
      if (id !== tenantId) {
        return;
      }
      loadError = describeError(i18n, err).message;
      status = 'error';
    }
  }

  function apply(data: SavedBranding & { hasLogo: boolean; hasBackground: boolean }): void {
    saved = { primaryColor: data.primaryColor, accentColor: data.accentColor, contrast: data.contrast };
    primary = data.primaryColor;
    accent = data.accentColor;
    hasLogo = data.hasLogo;
    hasBackground = data.hasBackground;
  }

  const fieldLabels = $derived({
    primary: t('adminTenants.branding.colors.primary.label'),
    accent: t('adminTenants.branding.colors.accent.label'),
  });

  function validate(): SummaryError[] {
    const out: SummaryError[] = [];
    const message = t('adminTenants.branding.colors.invalid');
    if (colorError(primary) !== undefined) {
      out.push({ id: hexId(ids.primary), label: fieldLabels.primary, message });
    }
    if (colorError(accent) !== undefined) {
      out.push({ id: hexId(ids.accent), label: fieldLabels.accent, message });
    }
    return out;
  }

  function resultText(row: ContrastRow): string {
    return t('adminTenants.branding.contrast.result', {
      pair: t(`adminTenants.branding.contrast.pair.${row.pair}`),
      ratio: formatNumber(row.ratio, { minimumFractionDigits: 1, maximumFractionDigits: 2 }),
      level: t(`adminTenants.branding.contrast.level.${row.level}`),
    });
  }

  async function save(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/branding', {
        path: { tenantId },
        body: { primaryColor: edited.primaryColor, accentColor: edited.accentColor },
      });
      apply(res.data);
    } catch (err) {
      const view = describeError(i18n, err);
      const fieldErrors: SummaryError[] = [];
      for (const [field, key] of [
        ['primaryColor', 'primary'],
        ['accentColor', 'accent'],
      ] as const) {
        const f = view.fields[field];
        if (f !== undefined) {
          fieldErrors.push({ id: hexId(ids[key]), label: fieldLabels[key], message: f.message });
        }
      }
      return fieldErrors.length > 0
        ? { ok: false, errors: fieldErrors }
        : { ok: false, errors: [], message: view.message };
    }
    // The server results are now shown; an insufficient contrast is announced with the success.
    const warnings = serverFailures(contrastView(edited, saved));
    const message = t('adminTenants.branding.saved');
    return {
      ok: true,
      message: warnings.length > 0 ? `${message} ${t('adminTenants.branding.contrast.warning')}` : message,
    };
  }
</script>

<h1 tabindex="-1">{t('adminTenants.branding.title')}</h1>
<p class="tt-branding__intro">{t('adminTenants.branding.intro')}</p>

{#if status === 'loading'}
  <p><Spinner label={t('admin.common.loading')} showLabel /></p>
{:else if status === 'error'}
  <Alert severity="error">{loadError}</Alert>
{:else}
  {#key tenantId}
    <FormSection
      title={t('adminTenants.branding.colors.title')}
      {dirty}
      addGuard={(guard) => nav.addGuard(guard)}
      {validate}
      onsubmit={save}
      bind:errors
      successMessage={t('adminTenants.branding.saved')}
    >
      <ColorField
        id={ids.primary}
        label={fieldLabels.primary}
        hint={t('adminTenants.branding.colors.primary.hint')}
        bind:value={primary}
        rows={rowsForPairs(rows, ['primary-on-light', 'primary-on-dark', 'text-on-primary'])}
        error={errorFor(errors, hexId(ids.primary))}
      />
      <ColorField
        id={ids.accent}
        label={fieldLabels.accent}
        hint={t('adminTenants.branding.colors.accent.hint')}
        bind:value={accent}
        rows={rowsForPairs(rows, ['accent-on-light', 'accent-on-dark'])}
        error={errorFor(errors, hexId(ids.accent))}
      />

      <section class="tt-branding__contrast" aria-labelledby="branding-contrast-heading">
        <h3 id="branding-contrast-heading">{t('adminTenants.branding.contrast.title')}</h3>
        <p>{t('adminTenants.branding.contrast.intro')}</p>
        {#if !fromServer}
          <p class="tt-branding__note">{t('adminTenants.branding.contrast.serverNote')}</p>
        {/if}
        {#if failing.length > 0}
          <Alert severity="warning" live={false}>
            <p>{t('adminTenants.branding.contrast.warning')}</p>
            <ul>
              {#each failing as row (row.pair)}
                <li>{resultText(row)}</li>
              {/each}
            </ul>
          </Alert>
        {/if}
        {#if fallbacks.length > 0}
          <p class="tt-branding__note tt-branding__dark-note">
            {t('adminTenants.branding.contrast.darkNote')}
          </p>
        {/if}
      </section>

      <BrandPreview primaryColor={primary} accentColor={accent} {logoUrl} />
    </FormSection>

    <ImageUpload
      {tenantId}
      asset="logo"
      headingLevel={2}
      title={t('adminTenants.branding.logo.title')}
      hint={t('adminTenants.branding.logo.hint')}
      alt={t('adminTenants.branding.logo.alt')}
      bind:has={hasLogo}
      onurlchange={(url) => {
        logoUrl = url;
      }}
    />
    <ImageUpload
      {tenantId}
      asset="background"
      headingLevel={2}
      title={t('adminTenants.branding.background.title')}
      hint={t('adminTenants.branding.background.hint')}
      alt={t('adminTenants.branding.background.alt')}
      bind:has={hasBackground}
    />
  {/key}
{/if}

<style>
  .tt-branding__intro {
    margin: 0 0 var(--tt-space-6);
    color: var(--tt-muted);
  }

  .tt-branding__contrast {
    margin-bottom: var(--tt-space-6);
  }

  .tt-branding__note {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
