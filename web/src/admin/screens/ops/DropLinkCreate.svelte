<script lang="ts">
  // Creation of a permanent drop link (POST /admin/tenants/{id}/drop-links; since 2.0): label,
  // internal recipients (1 to 20), validity (1, 7 or 30 days), optional confidentiality level and
  // enabled switch. On success the URL of the link is shown once in SecretOnceModal; closing it
  // goes back to the list.
  // The URL holds the token: it lives only in this component's state, is cleared when the modal
  // closes and when the screen goes away, and is never put in the browser URL, in storage, in a log
  // or in an announcement (same rule as the API token secret).
  import { onDestroy, onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { HelpIcon } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import SecretOnceModal from '../../components/SecretOnceModal.svelte';
  import type { SubmitOutcome, SummaryError } from '../../components/form';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import DropLinkFormFields from './DropLinkFormFields.svelte';
  import {
    dropCreateBody,
    dropFormTouched,
    dropLinkErrorOutcome,
    emptyDropLinkForm,
    levelOptions,
    validateDropLink,
    type TenantLevel,
  } from './dropLinks';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    label: `${uid}-label`,
    recipients: `${uid}-recipients`,
    validity: `${uid}-validity`,
    level: `${uid}-level`,
    expiry: `${uid}-expiry`,
    cap: `${uid}-cap`,
  };

  const tenantId = $derived(params['id'] ?? '');
  const listPath = $derived(tenantPath(tenantId, 'dropLinks'));

  let form = $state(emptyDropLinkForm());
  let errors = $state<SummaryError[]>([]);
  let created = $state(false);
  let levels = $state.raw<TenantLevel[]>([]);
  // The URL of the created link, shown once.
  let secret = $state('');
  let secretTitle = $state('');
  let secretOpen = $state(false);

  const fields = $derived({
    label: { id: ids.label, label: t('opsDropLinks.form.label.label') },
    recipients: { id: ids.recipients, label: t('opsDropLinks.form.recipients.label') },
    validityDays: { id: ids.validity, label: t('opsDropLinks.form.validity.legend') },
    confidentialityLevel: { id: ids.level, label: t('opsDropLinks.form.level.label') },
    expiresAt: { id: ids.expiry, label: t('opsDropLinks.form.expiry.label') },
    maxDepositsPerHour: { id: ids.cap, label: t('opsDropLinks.form.cap.label') },
  });
  const options = $derived(levelOptions(levels, locale.current, t('opsDropLinks.form.level.default')));
  const dirty = $derived(!created && dropFormTouched(form));

  onMount(() => {
    // The levels only fill the select: without them the tenant default stays available.
    adminApi
      .get('/admin/tenants/{tenantId}/confidentiality-levels', { path: { tenantId } })
      .then((res) => {
        levels = res.data.items;
      })
      .catch(() => undefined);
  });

  async function submit(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/drop-links', {
        path: { tenantId },
        body: dropCreateBody(form),
      });
      created = true;
      secretTitle = t('opsDropLinks.secret.title', { label: res.data.label });
      secret = res.data.url;
      secretOpen = true;
      return { ok: true, message: t('opsDropLinks.form.created') };
    } catch (err) {
      return dropLinkErrorOutcome(describeError(i18n, err), fields, t);
    }
  }

  function secretClosed(): void {
    secret = '';
    void nav.navigate(listPath);
  }

  onDestroy(() => {
    secret = '';
  });
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminOps.dropLinks.createTitle')}</h1>
  <HelpIcon topic="tenant-drop-links" title={t('adminOps.dropLinks.createTitle')} {nav} />
</div>
<p>{t('adminOps.dropLinks.intro')}</p>

<FormSection
  title={t('opsDropLinks.form.title')}
  {dirty}
  addGuard={(guard) => nav.addGuard(guard)}
  validate={() => validateDropLink(form, fields, t)}
  onsubmit={submit}
  saveLabel={t('opsDropLinks.form.submit')}
  savingLabel={t('admin.common.creating')}
  disabled={created}
  bind:errors
>
  <DropLinkFormFields bind:form {ids} {errors} levels={options} />
</FormSection>

<p class="tt-mt-6"><a href={nav.href(listPath)} use:nav.link>{t('opsDropLinks.form.back')}</a></p>

{#if secret !== ''}
  <SecretOnceModal
    bind:open={secretOpen}
    title={secretTitle}
    {secret}
    text={t('opsDropLinks.secret.text')}
    secretLabel={t('opsDropLinks.secret.label')}
    addGuard={(guard) => nav.addGuard(guard)}
    onclose={secretClosed}
  />
{/if}
