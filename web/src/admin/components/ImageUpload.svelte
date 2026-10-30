<script lang="ts">
  // Logo or background image of a tenant (RGAA 1.1, 11.1):
  // - the stored image, shown from GET /admin/tenants/{tenantId}/branding/{asset} (same origin,
  //   admin session cookie, no-store), with a cache-busting version changed after each upload or
  //   deletion;
  // - the choice of a new image (FileDrop), checked client side for its media type and size
  //   (indicative only, T-166: the server re-encodes), then previewed locally from a data: URL
  //   (FileReader; the admin CSP allows img-src data:) for the chosen file only;
  // - upload (PUT with the file as body), with a busy button; 413, 415 and 400 have their own
  //   messages; deletion after confirmation (ConfirmDialog).
  // has is bound: the parent learns when an image is stored or removed.
  //
  //   <ImageUpload {tenantId} asset="logo" title={text} hint={text} alt={text} bind:has={hasLogo} />
  import { onDestroy } from 'svelte';
  import Alert from '../../shared/components/Alert.svelte';
  import Button from '../../shared/components/Button.svelte';
  import FileDrop from '../../shared/components/FileDrop.svelte';
  import LiveRegion from '../../shared/components/LiveRegion.svelte';
  import { problemMessage } from '../../shared/api/problem';
  import { i18n, locale, t } from '../../shared/i18n/i18n.svelte';
  import { adminApi } from '../api';
  import {
    ACCEPT_ATTRIBUTE,
    ASSET_MAX_BYTES,
    assetUrl,
    readPreviewUrl,
    uploadErrorMessage,
    validateImageFile,
    type BrandingAsset,
    type DataUrlReader,
  } from './branding';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import { formatBytes as formatBinaryBytes } from '../forms/bytes';

  // Sizes are shown with the binary units of the size fields (MiB, GiB, TiB).
  const formatBytes = (n: number): string => formatBinaryBytes(n, locale.current);

  interface Props {
    /** Tenant of the image. */
    tenantId: string;
    /** Which image. */
    asset: BrandingAsset;
    /** Heading of the block. */
    title: string;
    /** Help text. */
    hint?: string;
    /** Text alternative of the image (stored or chosen). */
    alt: string;
    /** Whether an image is stored (bound). */
    has?: boolean;
    /** Level of the heading (default 3). */
    headingLevel?: 2 | 3 | 4;
    /** Called with the URL of the stored image (null when there is none), e.g. for a preview. */
    onurlchange?: (url: string | null) => void;
  }

  let {
    tenantId,
    asset,
    title,
    hint,
    alt,
    has = $bindable(false),
    headingLevel = 3,
    onurlchange,
  }: Props = $props();

  const uid = $props.id();
  const headingId = `${uid}-heading`;
  const inputId = `${uid}-file`;

  let version = $state(Date.now());
  let pending = $state.raw<File | null>(null);
  let previewUrl = $state<string | null>(null);
  let fileError = $state<string | undefined>(undefined);
  let failure = $state('');
  let success = $state('');
  let uploading = $state(false);
  let confirmOpen = $state(false);
  let broken = $state(false);
  // Guards against a slow FileReader finishing after a newer choice.
  let readToken = 0;

  const maxSize = $derived(formatBytes(ASSET_MAX_BYTES[asset]));
  const storedUrl = $derived(has ? assetUrl(tenantId, asset, version) : null);

  $effect(() => {
    onurlchange?.(broken ? null : storedUrl);
  });

  function clearPending(): void {
    readToken++;
    pending = null;
    previewUrl = null;
  }

  onDestroy(clearPending);

  async function choose(files: File[]): Promise<void> {
    const file = files[0];
    success = '';
    failure = '';
    clearPending();
    if (file === undefined) {
      return;
    }
    const error = validateImageFile(file, asset);
    if (error !== undefined) {
      fileError =
        error === 'too-large'
          ? t('adminTenants.branding.image.tooLarge', { size: maxSize })
          : t('adminTenants.branding.image.badType');
      return;
    }
    fileError = undefined;
    pending = file;
    const token = readToken;
    const url = await readPreviewUrl(file, () => new FileReader() as unknown as DataUrlReader);
    if (token === readToken) {
      previewUrl = url;
    }
  }

  async function upload(): Promise<void> {
    if (pending === null || uploading) {
      return;
    }
    uploading = true;
    success = '';
    failure = '';
    try {
      await adminApi.put('/admin/tenants/{tenantId}/branding/{asset}', {
        path: { tenantId, asset },
        body: pending,
      });
    } catch (err) {
      failure = uploadErrorMessage(i18n, err);
      return;
    } finally {
      uploading = false;
    }
    clearPending();
    has = true;
    broken = false;
    version = Date.now();
    success = t('adminTenants.branding.image.uploaded');
  }

  async function remove(): Promise<string | void> {
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/branding/{asset}', { path: { tenantId, asset } });
    } catch (err) {
      return problemMessage(i18n, err);
    }
    has = false;
    broken = false;
    version = Date.now();
    failure = '';
    success = t('adminTenants.branding.image.deleted');
  }
</script>

<section class="tt-image" aria-labelledby={headingId}>
  <svelte:element this={`h${headingLevel}`} id={headingId} class="tt-image__heading">{title}</svelte:element>
  {#if hint}<p class="tt-image__hint">{hint}</p>{/if}

  <div class="tt-image__current">
    <p class="tt-image__label">{t('adminTenants.branding.image.current')}</p>
    {#if storedUrl !== null && !broken}
      <img
        class="tt-image__img tt-image__img--{asset}"
        src={storedUrl}
        {alt}
        onerror={() => {
          broken = true;
        }}
      />
    {:else}
      <p>{t('adminTenants.branding.image.none')}</p>
    {/if}
  </div>

  <FileDrop
    id={inputId}
    label={t('adminTenants.branding.image.choose')}
    hint={t('adminTenants.branding.image.types', { size: maxSize })}
    multiple={false}
    accept={ACCEPT_ATTRIBUTE}
    disabled={uploading}
    error={fileError}
    onfiles={(files) => void choose(files)}
  />

  {#if pending !== null}
    <div class="tt-image__pending">
      <p class="tt-image__label">{t('adminTenants.branding.image.localPreview')}</p>
      <p class="tt-image__name">{pending.name} ({formatBytes(pending.size)})</p>
      {#if previewUrl !== null}
        <img class="tt-image__img tt-image__img--{asset}" src={previewUrl} {alt} />
      {/if}
    </div>
  {/if}

  {#if failure !== ''}
    <Alert severity="error">{failure}</Alert>
  {/if}

  <div class="tt-image__actions">
    {#if pending !== null}
      <Button loading={uploading} loadingLabel={t('adminTenants.branding.image.uploading')} onclick={upload}>
        {uploading ? t('adminTenants.branding.image.uploading') : t('adminTenants.branding.image.upload')}
      </Button>
    {/if}
    {#if has}
      <Button
        variant="danger"
        disabled={uploading}
        onclick={() => {
          success = '';
          confirmOpen = true;
        }}
      >
        {t('adminTenants.branding.image.delete')}
      </Button>
    {/if}
  </div>
  <div class="tt-image__result">
    <LiveRegion message={success} visible />
  </div>
</section>

<ConfirmDialog
  bind:open={confirmOpen}
  title={t('adminTenants.branding.image.deleteConfirmTitle')}
  text={t('adminTenants.branding.image.deleteConfirmText')}
  danger
  confirmLabel={t('adminTenants.branding.image.delete')}
  busyLabel={t('admin.common.deleting')}
  onconfirm={remove}
/>

<style>
  .tt-image {
    margin-bottom: var(--tt-space-8);
  }

  .tt-image__heading {
    margin: 0 0 var(--tt-space-2);
  }

  .tt-image__hint {
    margin: 0 0 var(--tt-space-3);
    color: var(--tt-muted);
  }

  .tt-image__current,
  .tt-image__pending {
    margin-bottom: var(--tt-space-4);
  }

  .tt-image__label {
    margin: 0 0 var(--tt-space-1);
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-image__name {
    margin: 0 0 var(--tt-space-2);
    overflow-wrap: anywhere;
  }

  .tt-image__img {
    display: block;
    max-width: 100%;
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
    object-fit: contain;
  }

  .tt-image__img--logo {
    max-height: 6rem;
    /* Shown on the same light box as in the page header, in both themes. */
    background: var(--tt-logo-surface);
  }

  .tt-image__img--background {
    max-height: 14rem;
  }

  .tt-image__actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-3);
  }

  .tt-image__result {
    margin-top: var(--tt-space-2);
    font-weight: var(--tt-font-weight-bold);
  }
</style>
