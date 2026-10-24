<script lang="ts">
  // Edition of an admin account (super admin only; CLAUDE.md section 6.5):
  // - summary: role, status, two-factor status, last sign-in;
  // - merge patch (buildAdminPatch) of the email address, role, entities, two-factor
  //   requirement and disabling; promotion to super admin is offered only to an activated
  //   account with TOTP (the server checks it too), demotion requires entities;
  // - credentials reset (confirmation) giving a new activation link, shown once by
  //   ActivationLinkPanel and kept in this component's memory only (threat model T-162);
  // - deletion (confirmation);
  // - on one's own account, no role change, disabling, reset or deletion (the server refuses
  //   them); the password and TOTP are managed from My account.
  // A 409 state-conflict answer gets a contextual message (own account, last usable super
  // admin, account not promotable, disabled account).
  import { onDestroy, onMount, tick } from 'svelte';
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Checkbox, RadioGroup, TextField, announce } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ActivationLinkPanel from '../../components/ActivationLinkPanel.svelte';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { isEmptyPatch } from '../../forms/patch';
  import type { AdminScreenProps } from '../types';
  import {
    accountActions,
    accountErrorMessage,
    accountStatus,
    buildAdminPatch,
    canPromote,
    editFormFrom,
    loadAllPages,
    roleKey,
    splitActivation,
    statusVariant,
    totpStatus,
    validateEdit,
    type AccountAction,
    type ActivationLink,
    type Admin,
    type AdminRole,
    type EditForm,
    type FieldIssue,
  } from './admins';
  import TenantChecklist from './TenantChecklist.svelte';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    email: `${uid}-email`,
    role: `${uid}-role`,
    tenants: `${uid}-tenants`,
    requireTotp: `${uid}-require-totp`,
    disabled: `${uid}-disabled`,
  };
  const adminId = $derived(params['id'] ?? '');

  let admin = $state<Admin | undefined>(undefined);
  let form = $state<EditForm | undefined>(undefined);
  let tenants = $state<{ id: string; name: string }[]>([]);
  let loading = $state(true);
  let notFound = $state(false);
  let loadError = $state('');
  let errors = $state<SummaryError[]>([]);
  let link = $state<ActivationLink | undefined>(undefined);
  let resetOpen = $state(false);
  let deleteOpen = $state(false);
  let notice = $state('');
  let heading: HTMLHeadingElement | undefined = $state();

  const meId = $derived(adminSession.me?.id);
  const actions = $derived(admin === undefined ? undefined : accountActions(admin, meId));
  const patch = $derived(admin !== undefined && form !== undefined ? buildAdminPatch(admin, form) : {});
  const dirty = $derived(!isEmptyPatch(patch));
  const promotable = $derived(admin !== undefined && (admin.role === 'super_admin' || canPromote(admin)));

  const roleOptions = $derived<{ value: AdminRole; label: string; hint?: string; disabled?: boolean }[]>([
    {
      value: 'delegated_admin',
      label: t('admin.role.delegated_admin'),
      ...(admin?.role === 'super_admin' ? { hint: t('adminAccounts.promotion.demoteHint') } : {}),
    },
    {
      value: 'super_admin',
      label: t('admin.role.super_admin'),
      hint: t('adminAccounts.promotion.hint'),
      disabled: !promotable,
    },
  ]);

  const fieldRefs = $derived({
    email: { id: ids.email, label: t('adminAccounts.form.email.label') },
    role: { id: ids.role, label: t('adminAccounts.form.role.label') },
    tenantIds: { id: `${ids.tenants}-0`, label: t('adminAccounts.form.tenants.legend') },
    requireTotp: { id: ids.requireTotp, label: t('adminAccounts.form.requireTotp.label') },
    disabled: { id: ids.disabled, label: t('adminAccounts.form.disabled.label') },
  });

  function summaryOf(issues: readonly FieldIssue[]): SummaryError[] {
    return issues.flatMap((issue) =>
      issue.field === 'username' ? [] : [{ ...fieldRefs[issue.field], message: t(issue.key) }],
    );
  }

  function show(account: Admin): void {
    admin = account;
    form = editFormFrom(account);
  }

  async function loadTenants(): Promise<void> {
    const all = await loadAllPages(async (cursor) => {
      const res = await adminApi.get('/admin/tenants', {
        params: cursor === undefined ? { limit: 200 } : { limit: 200, cursor },
      });
      return res.data;
    });
    tenants = all
      .map((tenant) => ({ id: tenant.id, name: tenant.name }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async function load(): Promise<void> {
    loading = true;
    loadError = '';
    notFound = false;
    try {
      const [res] = await Promise.all([
        adminApi.get('/admin/admins/{adminId}', { path: { adminId } }),
        loadTenants(),
      ]);
      show(res.data);
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 404) {
        notFound = true;
      } else {
        loadError = describeError(i18n, err).message;
      }
    } finally {
      loading = false;
    }
  }

  function messageOf(err: unknown, current: Admin, action: AccountAction): string {
    return accountErrorMessage(describeError(i18n, err), current, action, meId, t);
  }

  async function save(): Promise<SubmitOutcome> {
    const current = admin;
    if (current === undefined || form === undefined) {
      return { ok: false };
    }
    const body = buildAdminPatch(current, form);
    try {
      const res = await adminApi.patch('/admin/admins/{adminId}', { path: { adminId }, body });
      show(res.data);
      if (res.data.id === meId) {
        await adminSession.refreshMe().catch(() => undefined);
      }
      return { ok: true, message: t('adminAccounts.form.saved') };
    } catch (err) {
      const view = describeError(i18n, err);
      if (view.code === 'validation-failed') {
        const { errors: fieldErrors, unmatched } = summaryFromFields(view.fields, fieldRefs);
        if (fieldErrors.length > 0 && unmatched.length === 0) {
          return { ok: false, errors: fieldErrors };
        }
        return { ok: false, message: view.message, errors: fieldErrors };
      }
      return { ok: false, message: messageOf(err, current, { kind: 'update', patch: body }) };
    }
  }

  async function reset(): Promise<string | void> {
    const current = admin;
    if (current === undefined) {
      return;
    }
    try {
      const res = await adminApi.post('/admin/admins/{adminId}/reset-credentials', { path: { adminId } });
      const { account, link: activation } = splitActivation(res.data);
      show(account);
      errors = [];
      notice = t('adminAccounts.reset.done', { username: account.username });
      link = activation;
    } catch (err) {
      return messageOf(err, current, { kind: 'reset' });
    }
  }

  async function remove(): Promise<string | void> {
    const current = admin;
    if (current === undefined) {
      return;
    }
    try {
      await adminApi.delete('/admin/admins/{adminId}', { path: { adminId } });
    } catch (err) {
      return messageOf(err, current, { kind: 'delete' });
    }
    // The account is gone: no unsaved changes to keep.
    form = editFormFrom(current);
    announce(t('adminAccounts.delete.done', { username: current.username }));
    void nav.navigate('/admins');
  }

  async function linkDone(): Promise<void> {
    link = undefined;
    notice = '';
    await tick();
    heading?.focus();
  }

  onMount(() => {
    void load();
  });

  onDestroy(() => {
    link = undefined;
  });
</script>

{#if loading}
  <h1 tabindex="-1">{t('adminAccounts.list.title')}</h1>
  <p>{t('admin.common.loading')}</p>
{:else if notFound}
  <h1 tabindex="-1">{t('adminAccounts.notFound.title')}</h1>
  <p>{t('adminAccounts.notFound.text')}</p>
  <p><a href={nav.href('/admins')} use:nav.link>{t('admin.common.back')}</a></p>
{:else if admin === undefined || form === undefined || actions === undefined}
  <h1 tabindex="-1">{t('adminAccounts.list.title')}</h1>
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" small onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <h1 tabindex="-1" bind:this={heading}>{t('adminAccounts.form.editTitle', { username: admin.username })}</h1>

  {#if link !== undefined}
    {#if notice !== ''}<Alert severity="success">{notice}</Alert>{/if}
    <ActivationLinkPanel
      {link}
      username={admin.username}
      addGuard={(guard) => nav.addGuard(guard)}
      ondone={() => void linkDone()}
    />
  {:else}
    <dl class="tt-dl">
      <dt>{t('adminAccounts.list.columns.email')}</dt>
      <dd>{admin.email}</dd>
      <dt>{t('adminAccounts.list.columns.role')}</dt>
      <dd>{t(roleKey(admin.role))}</dd>
      <dt>{t('adminAccounts.list.columns.status')}</dt>
      <dd>
        <StatusBadge
          variant={statusVariant(accountStatus(admin))}
          label={t(`adminAccounts.status.${accountStatus(admin)}`)}
        />
      </dd>
      <dt>{t('adminAccounts.list.columns.totp')}</dt>
      <dd>
        <StatusBadge
          variant={statusVariant(totpStatus(admin))}
          label={t(`adminAccounts.totp.${totpStatus(admin)}`)}
        />
      </dd>
      <dt>{t('adminAccounts.list.columns.lastLogin')}</dt>
      <dd>
        {admin.lastLoginAt ? i18n.formatDate(admin.lastLoginAt) : t('adminAccounts.list.never')}
      </dd>
    </dl>

    {#if actions.self}
      <Alert severity="info" live={false}><p>{t('adminAccounts.ownAccountNote')}</p></Alert>
    {/if}

    <FormSection
      title={t('adminAccounts.form.editLegend')}
      {dirty}
      addGuard={(guard) => nav.addGuard(guard)}
      validate={() => (form === undefined ? [] : summaryOf(validateEdit(form)))}
      onsubmit={save}
      bind:errors
      saveLabel={t('adminAccounts.form.save')}
    >
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
      {#if actions.changeRole}
        <div id={ids.role} tabindex="-1">
          <RadioGroup
            legend={t('adminAccounts.form.role.label')}
            hint={t('adminAccounts.form.role.hint')}
            options={roleOptions}
            bind:value={form.role}
            error={errorFor(errors, ids.role)}
          />
        </div>
      {/if}
      {#if form.role === 'delegated_admin'}
        <TenantChecklist
          {tenants}
          idPrefix={ids.tenants}
          bind:selected={form.tenantIds}
          error={errorFor(errors, `${ids.tenants}-0`)}
        />
        <Checkbox
          id={ids.requireTotp}
          label={t('adminAccounts.form.requireTotp.label')}
          hint={t('adminAccounts.form.requireTotp.hint')}
          bind:checked={form.requireTotp}
          error={errorFor(errors, ids.requireTotp)}
        />
      {/if}
      {#if actions.disable}
        <Checkbox
          id={ids.disabled}
          label={t('adminAccounts.form.disabled.label')}
          hint={t('adminAccounts.form.disabled.hint')}
          bind:checked={form.disabled}
          error={errorFor(errors, ids.disabled)}
        />
      {/if}
    </FormSection>

    {#if actions.reset || actions.remove}
      <section aria-labelledby="{uid}-actions">
        <h2 id="{uid}-actions">{t('admin.common.actions')}</h2>
        <div class="tt-cluster">
          {#if actions.reset}
            <Button variant="secondary" onclick={() => (resetOpen = true)}
              >{t('adminAccounts.reset.action')}</Button
            >
          {/if}
          {#if actions.remove}
            <Button variant="danger" onclick={() => (deleteOpen = true)}
              >{t('adminAccounts.delete.action')}</Button
            >
          {/if}
        </div>
      </section>
    {/if}

    <p class="tt-mt-6"><a href={nav.href('/admins')} use:nav.link>{t('admin.common.back')}</a></p>
  {/if}

  <ConfirmDialog
    bind:open={resetOpen}
    title={t('adminAccounts.reset.confirmTitle', { username: admin.username })}
    text={t('adminAccounts.reset.confirmText')}
    confirmLabel={t('adminAccounts.reset.confirmAction')}
    danger
    onconfirm={reset}
  />
  <ConfirmDialog
    bind:open={deleteOpen}
    title={t('adminAccounts.delete.confirmTitle', { username: admin.username })}
    text={t('adminAccounts.delete.confirmText')}
    confirmLabel={t('adminAccounts.delete.confirmAction')}
    busyLabel={t('admin.common.deleting')}
    danger
    onconfirm={remove}
  />
{/if}
