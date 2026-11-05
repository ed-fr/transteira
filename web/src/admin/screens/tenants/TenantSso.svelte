<script lang="ts">
  // Single sign-on (OpenID Connect) of a tenant, version 2.0 (GET, PUT, DELETE and POST .../test
  // of /admin/tenants/{id}/sso; 404 when none is configured).
  // - Super admin: editable form (enabled, issuer, client ID, client secret, e-mail domains,
  //   enforced, multi-factor authentication required), test of the discovery, removal with a
  //   confirmation. The secret is write-only: the field stays empty and a note says when one is
  //   stored; it must be typed again when the issuer or the client ID changes.
  // - Delegated admin and auditor: read-only view of the configuration.
  // The result of the test only shows translated text from closed lists, never a remote message.
  // The tenant sub-navigation is rendered by App.svelte.
  import { tick } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import {
    Alert,
    Button,
    Checkbox,
    HelpIcon,
    Spinner,
    TextField,
    announce,
  } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { parseDomain } from '../../forms/domain';
  import type { AdminScreenProps } from '../types';
  import { domainLineMessage } from './network';
  import {
    SSO_MAX_DOMAINS,
    canEditSso,
    emptySsoForm,
    mapSsoSaveError,
    parseSsoDomains,
    secretRequired,
    ssoDirty,
    ssoFormFrom,
    ssoTestView,
    ssoUpdateBody,
    validateSso,
    type SsoForm,
    type SsoTestView,
    type TenantSso,
  } from './sso';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    enabled: `${uid}-enabled`,
    issuer: `${uid}-issuer`,
    clientId: `${uid}-client-id`,
    clientSecret: `${uid}-client-secret`,
    emailDomains: `${uid}-domains`,
    enforced: `${uid}-enforced`,
    requireMfa: `${uid}-require-mfa`,
  };

  let loading = $state(true);
  let loadError = $state('');
  let saved = $state.raw<TenantSso | undefined>(undefined);
  let form = $state<SsoForm>(emptySsoForm());
  let errors = $state<SummaryError[]>([]);
  let removeOpen = $state(false);
  let testing = $state(false);
  let testView = $state.raw<SsoTestView | undefined>(undefined);
  let testError = $state('');
  let notice = $state('');
  let resultBox: HTMLDivElement | undefined = $state();

  const tenantId = $derived(params['id'] ?? '');
  const editable = $derived(canEditSso(adminSession.me?.role));
  const domains = $derived(parseSsoDomains(form.domainsText));
  const dirty = $derived(editable && ssoDirty(saved, form, domains));
  const needsSecret = $derived(secretRequired(saved, form));
  const fields = $derived({
    issuer: { id: ids.issuer, label: t('adminTenants.sso.issuer.label') },
    clientId: { id: ids.clientId, label: t('adminTenants.sso.clientId.label') },
    clientSecret: { id: ids.clientSecret, label: t('adminTenants.sso.clientSecret.label') },
    emailDomains: { id: ids.emailDomains, label: t('adminTenants.sso.emailDomains.label') },
  });

  function show(sso: TenantSso | undefined): void {
    saved = sso;
    form = ssoFormFrom(sso);
  }

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    testView = undefined;
    testError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/sso', { path: { tenantId: id } });
      show(res.data);
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 404) {
        show(undefined);
      } else {
        loadError = describeError(i18n, err).message;
      }
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load(tenantId);
  });

  async function save(): Promise<SubmitOutcome> {
    notice = '';
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/sso', {
        path: { tenantId },
        body: ssoUpdateBody(form, domains),
      });
      show(res.data);
      testView = undefined;
      return { ok: true, message: t('adminTenants.sso.saved') };
    } catch (err) {
      const mapped = mapSsoSaveError(describeError(i18n, err), fields, t);
      return mapped.message === undefined
        ? { ok: false, errors: mapped.errors }
        : { ok: false, errors: mapped.errors, message: mapped.message };
    }
  }

  async function runTest(): Promise<void> {
    testing = true;
    testView = undefined;
    testError = '';
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/sso/test', { path: { tenantId } });
      testView = ssoTestView(res.data, t);
      announce(testView.summary);
    } catch (err) {
      const view = describeError(i18n, err);
      testError = view.code === 'state-conflict' ? t('adminTenants.sso.test.notSaved') : view.message;
    } finally {
      testing = false;
    }
    await tick();
    resultBox?.focus();
  }

  async function remove(): Promise<string | void> {
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/sso', { path: { tenantId } });
    } catch (err) {
      return describeError(i18n, err).message;
    }
    show(undefined);
    testView = undefined;
    notice = t('adminTenants.sso.removed');
    announce(notice);
  }
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminTenants.sso.title')}</h1>
  <HelpIcon topic="tenant-sso" title={t('adminTenants.sso.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">{loadError}</Alert>
{:else}
  {#if notice !== ''}
    <Alert severity="success">{notice}</Alert>
  {/if}

  {#if !editable}
    <p>{t('adminTenants.sso.readOnlyIntro')}</p>
    {#if saved === undefined}
      <Alert severity="info" live={false}>{t('adminTenants.sso.notConfigured')}</Alert>
    {:else}
      <dl class="tt-dl">
        <dt>{t('adminTenants.sso.status.label')}</dt>
        <dd>
          <StatusBadge
            variant={saved.enabled ? 'ok' : 'info'}
            label={t(saved.enabled ? 'adminTenants.sso.status.enabled' : 'adminTenants.sso.status.disabled')}
          />
        </dd>
        <dt>{t('adminTenants.sso.issuer.label')}</dt>
        <dd class="tt-break">{saved.issuer}</dd>
        <dt>{t('adminTenants.sso.clientId.label')}</dt>
        <dd class="tt-break">{saved.clientId}</dd>
        <dt>{t('adminTenants.sso.clientSecret.label')}</dt>
        <dd>
          {t(saved.hasClientSecret ? 'adminTenants.sso.secretStored' : 'adminTenants.sso.secretMissing')}
        </dd>
        <dt>{t('adminTenants.sso.emailDomains.label')}</dt>
        <dd>
          <ul class="tt-list-plain">
            {#each saved.emailDomains as domain (domain)}
              <li>{domain}</li>
            {/each}
          </ul>
        </dd>
        <dt>{t('adminTenants.sso.enforced.label')}</dt>
        <dd>{t(saved.enforced ? 'adminTenants.sso.yes' : 'adminTenants.sso.no')}</dd>
        <dt>{t('adminTenants.sso.requireMfa.label')}</dt>
        <dd>{t(saved.requireMfa ? 'adminTenants.sso.yes' : 'adminTenants.sso.no')}</dd>
      </dl>
    {/if}
  {:else}
    <FormSection
      title={t('adminTenants.sso.form.title')}
      intro={t('adminTenants.sso.intro')}
      {dirty}
      addGuard={(guard) => nav.addGuard(guard)}
      validate={() => validateSso(form, domains, saved, fields, t)}
      onsubmit={save}
      bind:errors
    >
      <Checkbox
        id={ids.enabled}
        label={t('adminTenants.sso.enabled.label')}
        hint={t('adminTenants.sso.enabled.hint')}
        bind:checked={form.enabled}
      />
      <TextField
        id={ids.issuer}
        type="url"
        label={t('adminTenants.sso.issuer.label')}
        hint={t('adminTenants.sso.issuer.hint')}
        required
        autocomplete="off"
        spellcheck={false}
        maxlength={512}
        bind:value={form.issuer}
        error={errorFor(errors, ids.issuer)}
      />
      <TextField
        id={ids.clientId}
        label={t('adminTenants.sso.clientId.label')}
        hint={t('adminTenants.sso.clientId.hint')}
        required
        autocomplete="off"
        spellcheck={false}
        maxlength={255}
        bind:value={form.clientId}
        error={errorFor(errors, ids.clientId)}
      />
      <TextField
        id={ids.clientSecret}
        type="password"
        label={t('adminTenants.sso.clientSecret.label')}
        hint={saved?.hasClientSecret === true && !needsSecret
          ? t('adminTenants.sso.clientSecret.hintStored')
          : t('adminTenants.sso.clientSecret.hintRequired')}
        required={needsSecret}
        autocomplete="off"
        spellcheck={false}
        maxlength={1024}
        bind:value={form.clientSecret}
        error={errorFor(errors, ids.clientSecret)}
      />
      {#if saved?.hasClientSecret === true}
        <p class="tt-text-sm tt-text-muted">
          <StatusBadge variant="ok" label={t('adminTenants.sso.secretStored')} />
          {t('adminTenants.sso.secretChangeNote')}
        </p>
      {/if}
      <LineListEditor
        id={ids.emailDomains}
        label={t('adminTenants.sso.emailDomains.label')}
        hint={t('adminTenants.sso.emailDomains.hint')}
        bind:value={form.domainsText}
        parse={parseDomain}
        max={SSO_MAX_DOMAINS}
        required
        rows={4}
        message={(e) => {
          const m = domainLineMessage(e);
          return t(m.key, m.params);
        }}
        error={errorFor(errors, ids.emailDomains)}
      />
      <Checkbox
        id={ids.requireMfa}
        label={t('adminTenants.sso.requireMfa.label')}
        hint={t('adminTenants.sso.requireMfa.hint')}
        bind:checked={form.requireMfa}
      />
      <Checkbox
        id={ids.enforced}
        label={t('adminTenants.sso.enforced.label')}
        hint={t('adminTenants.sso.enforced.hint')}
        bind:checked={form.enforced}
      />
      {#if form.enforced}
        <Alert severity="warning" live={false}>{t('adminTenants.sso.enforced.warning')}</Alert>
      {/if}
    </FormSection>

    {#if saved !== undefined}
      <section aria-labelledby="{uid}-test-title" class="tt-mt-6">
        <h2 id="{uid}-test-title">{t('adminTenants.sso.test.title')}</h2>
        <p>{t('adminTenants.sso.test.intro')}</p>
        {#if dirty}
          <p class="tt-text-muted">{t('adminTenants.sso.test.saveFirst')}</p>
        {/if}
        <div class="tt-cluster">
          <Button
            variant="secondary"
            loading={testing}
            loadingLabel={t('adminTenants.sso.test.running')}
            onclick={() => void runTest()}
          >
            {t('adminTenants.sso.test.action')}
          </Button>
        </div>
        <div bind:this={resultBox} tabindex="-1">
          {#if testError !== ''}
            <Alert severity="error">{testError}</Alert>
          {/if}
          {#if testView !== undefined}
            <Alert severity={testView.success ? 'success' : 'error'} live={false}>
              <p>{testView.summary}</p>
              <p>{t('adminTenants.sso.test.stage', { stage: testView.stage })}</p>
              {#if testView.error !== undefined}
                <p>{testView.error}</p>
              {/if}
            </Alert>
          {/if}
        </div>
      </section>

      <section aria-labelledby="{uid}-remove-title" class="tt-mt-6">
        <h2 id="{uid}-remove-title">{t('adminTenants.sso.remove.title')}</h2>
        <p>{t('adminTenants.sso.remove.text')}</p>
        <Button variant="danger" onclick={() => (removeOpen = true)}
          >{t('adminTenants.sso.remove.action')}</Button
        >
      </section>
      <ConfirmDialog
        bind:open={removeOpen}
        title={t('adminTenants.sso.remove.confirmTitle')}
        text={t('adminTenants.sso.remove.confirmText')}
        confirmLabel={t('adminTenants.sso.remove.confirmAction')}
        busyLabel={t('admin.common.deleting')}
        danger
        onconfirm={remove}
      />
    {/if}
  {/if}
{/if}
