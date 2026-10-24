<script lang="ts">
  // Creation of an API token of a tenant (POST /admin/tenants/{id}/api-tokens; CLAUDE.md section
  // 16.4): name, allowed ranges (mandatory, with an "Any address" shortcut adding 0.0.0.0/0 and
  // ::/0 and a warning while a catch-all range is listed), allowed senders (empty: any address of
  // the internal domains) and an optional expiry (end of the chosen day, local time, in the
  // future). On success the secret is shown once in SecretOnceModal; closing it goes back to the
  // list.
  // Threat model T-167: the secret lives only in this component's state, is cleared when the
  // modal closes and when the screen goes away (navigation, sign-out), and is never put in the
  // URL, in storage, in a log or in an announcement.
  // The tenant sub-navigation is rendered by App.svelte.
  import { onDestroy } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import SecretOnceModal from '../../components/SecretOnceModal.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { parseCidr } from '../../forms/cidr';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import {
    createBody,
    createFormTouched,
    emptyCreateForm,
    hasAllAnyAddress,
    hasAnyAddress,
    MAX_TOKEN_CIDRS,
    MAX_TOKEN_SENDERS,
    parseSender,
    parseTokenCidrList,
    senderLineMessage,
    todayInput,
    TOKEN_NAME_MAX,
    tokenCidrLineMessage,
    tokenErrorOutcome,
    validateCreate,
    withAnyAddress,
  } from './tokens';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    name: `${uid}-name`,
    cidrs: `${uid}-cidrs`,
    senders: `${uid}-senders`,
    expiry: `${uid}-expiry`,
  };

  const tenantId = $derived(params['id'] ?? '');
  const listPath = $derived(tenantPath(tenantId, 'tokens'));

  let form = $state(emptyCreateForm());
  let errors = $state<SummaryError[]>([]);
  let created = $state(false);
  // The secret of the created token, shown once (T-167).
  let secret = $state('');
  let secretTitle = $state('');
  let secretOpen = $state(false);

  const fields = $derived({
    name: { id: ids.name, label: t('opsTokens.form.name.label') },
    allowedCidrs: { id: ids.cidrs, label: t('opsTokens.form.cidrs.label') },
    allowedSenders: { id: ids.senders, label: t('opsTokens.form.senders.label') },
    expiresAt: { id: ids.expiry, label: t('opsTokens.form.expiry.label') },
  });
  const cidrValues = $derived(parseTokenCidrList(form.cidrText).values);
  // Warning as soon as one catch-all range is listed; the shortcut stays available until both are.
  const anyAddress = $derived(hasAnyAddress(cidrValues));
  const allAnyAddress = $derived(hasAllAnyAddress(cidrValues));
  const sendersEmpty = $derived(form.senderText.trim() === '');
  const dirty = $derived(!created && createFormTouched(form));
  const minDate = $derived(todayInput(new Date()));

  async function submit(): Promise<SubmitOutcome> {
    const body = createBody(form);
    const sent = { cidrText: form.cidrText, senderText: form.senderText };
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/api-tokens', { path: { tenantId }, body });
      created = true;
      secretTitle = t('opsTokens.secret.title', { name: res.data.name });
      secret = res.data.token;
      secretOpen = true;
      return { ok: true, message: t('opsTokens.form.created') };
    } catch (err) {
      return tokenErrorOutcome(describeError(i18n, err), fields, sent, t);
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

<h1 tabindex="-1">{t('adminOps.tokens.createTitle')}</h1>
<p>{t('adminOps.tokens.intro')}</p>

<FormSection
  title={t('opsTokens.form.title')}
  {dirty}
  addGuard={(guard) => nav.addGuard(guard)}
  validate={() => validateCreate(form, fields, t, new Date())}
  onsubmit={submit}
  saveLabel={t('opsTokens.form.submit')}
  savingLabel={t('admin.common.creating')}
  disabled={created}
  bind:errors
>
  <TextField
    id={ids.name}
    label={t('opsTokens.form.name.label')}
    hint={t('opsTokens.form.name.hint')}
    bind:value={form.name}
    required
    maxlength={TOKEN_NAME_MAX}
    autocomplete="off"
    error={errorFor(errors, ids.name)}
  />

  <LineListEditor
    id={ids.cidrs}
    label={t('opsTokens.form.cidrs.label')}
    hint={t('opsTokens.form.cidrs.hint')}
    bind:value={form.cidrText}
    parse={parseCidr}
    max={MAX_TOKEN_CIDRS}
    required
    rows={4}
    message={(e) => {
      const m = tokenCidrLineMessage(e);
      return t(m.key, m.params);
    }}
    error={errorFor(errors, ids.cidrs)}
  />
  <p class="tt-tokens__shortcut">
    <Button
      variant="secondary"
      disabled={allAnyAddress}
      onclick={() => (form.cidrText = withAnyAddress(form.cidrText))}
    >
      {t('opsTokens.form.anyAddress')}
    </Button>
  </p>
  {#if anyAddress}
    <Alert severity="warning" live={false}>{t('opsTokens.form.anyAddressWarning')}</Alert>
  {/if}

  <LineListEditor
    id={ids.senders}
    label={t('opsTokens.form.senders.label')}
    hint={t('opsTokens.form.senders.hint')}
    bind:value={form.senderText}
    parse={parseSender}
    max={MAX_TOKEN_SENDERS}
    rows={4}
    message={(e) => {
      const m = senderLineMessage(e);
      return t(m.key, m.params);
    }}
    error={errorFor(errors, ids.senders)}
  />
  {#if sendersEmpty}
    <Alert severity="info" live={false}>{t('opsTokens.form.senders.empty')}</Alert>
  {/if}

  <TextField
    id={ids.expiry}
    label={t('opsTokens.form.expiry.label')}
    hint={t('opsTokens.form.expiry.hint')}
    type="date"
    min={minDate}
    bind:value={form.expiry}
    error={errorFor(errors, ids.expiry)}
  />
</FormSection>

<p class="tt-mt-6"><a href={nav.href(listPath)} use:nav.link>{t('opsTokens.form.back')}</a></p>

{#if secret !== ''}
  <SecretOnceModal
    bind:open={secretOpen}
    title={secretTitle}
    {secret}
    text={t('opsTokens.secret.text')}
    secretLabel={t('opsTokens.secret.label')}
    addGuard={(guard) => nav.addGuard(guard)}
    onclose={secretClosed}
  />
{/if}

<style>
  .tt-tokens__shortcut {
    margin: 0 0 var(--tt-space-4);
  }
</style>
