<script lang="ts">
  // Creation of a delegated admin (super admin only; CLAUDE.md section 6.5): username, email,
  // attached entities (at least one), two-factor authentication required by default. A super
  // admin is never created directly: an activated delegated admin with TOTP is promoted from
  // the edit screen. The activation link is mailed through the system SMTP (default) or shown
  // once to copy (ActivationLinkPanel); a shown link stays in this component's memory only and
  // is cleared when the screen goes away (threat model T-162). Without system SMTP (503) the
  // form keeps its values so that the copy delivery can be chosen and submitted again.
  import { onDestroy, onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Checkbox, TextField } from '../../../shared/components';
  import { i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import ActivationLinkPanel from '../../components/ActivationLinkPanel.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import InvitationFields from '../../components/InvitationFields.svelte';
  import InvitationSent from '../../components/InvitationSent.svelte';
  import { deepEqual } from '../../forms/patch';
  import type { AdminScreenProps } from '../types';
  import {
    createBody,
    defaultInvitationLanguage,
    emptyCreateForm,
    invitationErrorMessage,
    loadAllPages,
    splitCreated,
    type InvitationResult,
    validateCreate,
    type ActivationLink,
    type FieldIssue,
  } from './admins';
  import TenantChecklist from './TenantChecklist.svelte';

  const { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    username: `${uid}-username`,
    email: `${uid}-email`,
    tenants: `${uid}-tenants`,
    requireTotp: `${uid}-require-totp`,
    invitation: `${uid}-invitation`,
  };

  const initialLanguage = defaultInvitationLanguage(locale.current);
  let form = $state(emptyCreateForm(initialLanguage));
  let errors = $state<SummaryError[]>([]);
  let tenants = $state<{ id: string; name: string }[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let created = $state<InvitationResult | undefined>(undefined);
  let link = $state<ActivationLink | undefined>(undefined);

  const dirty = $derived(
    created === undefined && !deepEqual($state.snapshot(form), emptyCreateForm(initialLanguage)),
  );

  const fieldRefs = $derived({
    username: { id: ids.username, label: t('adminAccounts.form.username.label') },
    email: { id: ids.email, label: t('adminAccounts.form.email.label') },
    tenantIds: { id: `${ids.tenants}-0`, label: t('adminAccounts.form.tenants.legend') },
    requireTotp: { id: ids.requireTotp, label: t('adminAccounts.form.requireTotp.label') },
  });

  function summaryOf(issues: readonly FieldIssue[]): SummaryError[] {
    return issues.map((issue) => ({ ...fieldRefs[issue.field], message: t(issue.key) }));
  }

  async function loadTenants(): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const all = await loadAllPages(async (cursor) => {
        const res = await adminApi.get('/admin/tenants', {
          params: cursor === undefined ? { limit: 200 } : { limit: 200, cursor },
        });
        return res.data;
      });
      tenants = all
        .filter((tenant) => tenant.status !== 'deleting')
        .map((tenant) => ({ id: tenant.id, name: tenant.name }))
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  async function submit(): Promise<SubmitOutcome> {
    try {
      const res = await adminApi.post('/admin/admins', { body: createBody(form) });
      const result = splitCreated(res.data);
      created = result;
      link = result.link;
      return { ok: true };
    } catch (err) {
      const view = describeError(i18n, err);
      const invitation = invitationErrorMessage(view, t);
      if (invitation !== undefined) {
        return { ok: false, message: invitation };
      }
      if (view.code === 'already-exists') {
        return {
          ok: false,
          errors: [{ ...fieldRefs.username, message: t('adminAccounts.form.username.taken') }],
        };
      }
      const { errors: fieldErrors, unmatched } = summaryFromFields(view.fields, fieldRefs);
      if (fieldErrors.length > 0 && unmatched.length === 0) {
        return { ok: false, errors: fieldErrors };
      }
      return { ok: false, message: view.message, errors: fieldErrors };
    }
  }

  function finish(): void {
    link = undefined;
    void nav.navigate('/admins');
  }

  onMount(() => {
    void loadTenants();
  });

  onDestroy(() => {
    link = undefined;
  });
</script>

<h1 tabindex="-1">{t('adminAccounts.form.createTitle')}</h1>

{#if created !== undefined}
  <Alert severity="success">{t('adminAccounts.form.created', { username: created.account.username })}</Alert>
  {#if link !== undefined}
    <ActivationLinkPanel
      {link}
      username={created.account.username}
      addGuard={(guard) => nav.addGuard(guard)}
      ondone={finish}
    />
  {:else if created.delivery === 'mail'}
    <InvitationSent
      email={created.account.email}
      expiresAt={created.expiresAt}
      totpRequired={created.account.requireTotp === true}
      doneLabel={t('adminAccounts.invitation.sent.done')}
      ondone={finish}
    />
  {/if}
{:else}
  <p>{t('adminAccounts.form.createIntro')}</p>
  {#if loadError !== ''}
    <Alert severity="error">
      <p>{loadError}</p>
      <Button variant="secondary" small onclick={() => void loadTenants()}>{t('common.retry')}</Button>
    </Alert>
  {:else}
    <FormSection
      title={t('adminAccounts.form.createLegend')}
      as="fieldset"
      {dirty}
      addGuard={(guard) => nav.addGuard(guard)}
      validate={() => summaryOf(validateCreate(form))}
      onsubmit={submit}
      bind:errors
      saveLabel={t('adminAccounts.form.submitCreate')}
      savingLabel={t('admin.common.creating')}
      disabled={loading}
    >
      <TextField
        id={ids.username}
        label={t('adminAccounts.form.username.label')}
        hint={t('adminAccounts.form.username.hint')}
        required
        autocomplete="off"
        autocapitalize="none"
        spellcheck="false"
        maxlength={64}
        bind:value={form.username}
        error={errorFor(errors, ids.username)}
      />
      <TextField
        id={ids.email}
        type="email"
        label={t('adminAccounts.form.email.label')}
        hint={t('adminAccounts.form.email.hint')}
        required
        autocomplete="off"
        bind:value={form.email}
        error={errorFor(errors, ids.email)}
      />
      {#if loading}
        <p>{t('admin.common.loading')}</p>
      {:else}
        <TenantChecklist
          {tenants}
          idPrefix={ids.tenants}
          bind:selected={form.tenantIds}
          error={errorFor(errors, `${ids.tenants}-0`)}
        />
      {/if}
      <Checkbox
        id={ids.requireTotp}
        label={t('adminAccounts.form.requireTotp.label')}
        hint={form.delivery === 'mail'
          ? t('adminAccounts.form.requireTotp.mailHint')
          : t('adminAccounts.form.requireTotp.hint')}
        disabled={form.delivery === 'mail'}
        bind:checked={
          () => form.requireTotp || form.delivery === 'mail', (value) => (form.requireTotp = value)
        }
      />
      <InvitationFields
        idPrefix={ids.invitation}
        bind:delivery={form.delivery}
        bind:language={form.language}
      />
    </FormSection>
  {/if}
  <p><a href={nav.href('/admins')} use:nav.link>{t('admin.common.back')}</a></p>
{/if}
