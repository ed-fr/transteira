<script lang="ts">
  // Permanent drop links of a tenant (GET /admin/tenants/{id}/drop-links; since 2.0, CLAUDE.md
  // section 22): label, recipients, validity, level, status (active, disabled, revoked) and last
  // use. Delegated admins and the super admin can create, edit, enable or disable, rotate (new
  // token, the old URL stops working) and revoke a link; the auditor only reads the list (no
  // button, no creation link). The token and the URL of a link are never available here: only the
  // creation and the rotation answer with them, shown once in SecretOnceModal.
  // The tenant sub-navigation is rendered by App.svelte.
  import { onDestroy, onMount, tick, untrack } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, HelpIcon, announce } from '../../../shared/components';
  import { formatDate, i18n, locale, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import SecretOnceModal from '../../components/SecretOnceModal.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { isAuditor, tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import DropLinkEditDialog from './DropLinkEditDialog.svelte';
  import {
    dropActionErrorMessage,
    dropLinkStatus,
    dropStatusView,
    isDropLinkManageable,
    levelLabel,
    levelOptions,
    sortDropLinks,
    withoutSecret,
    type DropLink,
    type TenantLevel,
  } from './dropLinks';

  const { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');
  const readOnly = $derived(isAuditor(adminSession.me?.role));

  let links = $state.raw<DropLink[]>([]);
  let levels = $state.raw<TenantLevel[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let editing = $state.raw<DropLink | undefined>(undefined);
  let editOpen = $state(false);
  let rotating = $state.raw<DropLink | undefined>(undefined);
  let rotateOpen = $state(false);
  let revoking = $state.raw<DropLink | undefined>(undefined);
  let revokeOpen = $state(false);
  let revoked = false;
  let actionError = $state('');
  let levelsError = $state('');
  // Ids of the links whose enable/disable request is pending (one request per link at a time).
  let toggling = $state.raw<readonly string[]>([]);
  // The URL of a rotated link, shown once.
  let secret = $state('');
  let secretTitle = $state('');
  let secretOpen = $state(false);
  let heading = $state<HTMLHeadingElement | undefined>();

  const rows = $derived(sortDropLinks(links));
  const options = $derived(levelOptions(levels, locale.current, t('opsDropLinks.form.level.default')));

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/drop-links', { path: { tenantId: id } });
      links = res.data.items;
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  // Reload when the tenant changes; the loader itself (adminApi reads the locale) is untracked.
  $effect(() => {
    const id = tenantId;
    untrack(() => void load(id));
  });

  onMount(() => {
    // The level labels and the edition select; the auditor may not read them (the keys are shown).
    if (!readOnly) {
      adminApi
        .get('/admin/tenants/{tenantId}/confidentiality-levels', { path: { tenantId } })
        .then((res) => {
          levels = res.data.items;
        })
        .catch((err: unknown) => {
          levelsError = `${t('opsDropLinks.levelsError')} ${describeError(i18n, err).message}`;
        });
    }
  });

  onDestroy(() => {
    secret = '';
  });

  function replace(updated: DropLink): void {
    links = links.map((l) => (l.id === updated.id ? updated : l));
  }

  function startEdit(link: DropLink): void {
    editing = link;
    editOpen = true;
  }

  function startRotate(link: DropLink): void {
    rotating = link;
    rotateOpen = true;
  }

  function startRevoke(link: DropLink): void {
    revoking = link;
    revoked = false;
    revokeOpen = true;
  }

  function saved(link: DropLink): void {
    replace(link);
    announce(t('opsDropLinks.edit.saved'));
  }

  async function toggle(link: DropLink): Promise<void> {
    if (toggling.includes(link.id)) {
      return;
    }
    // The target state is computed once, before the request.
    const enabled = !link.enabled;
    actionError = '';
    toggling = [...toggling, link.id];
    try {
      const res = await adminApi.patch('/admin/tenants/{tenantId}/drop-links/{dropLinkId}', {
        path: { tenantId, dropLinkId: link.id },
        body: { enabled },
      });
      replace(res.data);
      announce(
        t(res.data.enabled ? 'opsDropLinks.toggle.enabledDone' : 'opsDropLinks.toggle.disabledDone', {
          label: link.label,
        }),
      );
    } catch (err) {
      actionError = dropActionErrorMessage(describeError(i18n, err), t);
    } finally {
      toggling = toggling.filter((id) => id !== link.id);
    }
  }

  async function rotate(): Promise<string | void> {
    const link = rotating;
    if (link === undefined) {
      return;
    }
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/drop-links/{dropLinkId}/rotate', {
        path: { tenantId, dropLinkId: link.id },
      });
      replace(withoutSecret(res.data));
      secretTitle = t('opsDropLinks.secret.rotatedTitle', { label: link.label });
      secret = res.data.url;
    } catch (err) {
      return dropActionErrorMessage(describeError(i18n, err), t);
    }
  }

  async function rotateClosed(): Promise<void> {
    // The confirmation is gone: the new URL is shown, once.
    if (secret !== '') {
      await tick();
      secretOpen = true;
    }
  }

  async function revoke(): Promise<string | void> {
    const link = revoking;
    if (link === undefined) {
      return;
    }
    try {
      await adminApi.delete('/admin/tenants/{tenantId}/drop-links/{dropLinkId}', {
        path: { tenantId, dropLinkId: link.id },
      });
    } catch (err) {
      return dropActionErrorMessage(describeError(i18n, err), t);
    }
    revoked = true;
    announce(t('opsDropLinks.revoke.done', { label: link.label }));
    // Reload to show the revocation date recorded by the server.
    void load(tenantId);
  }

  async function revokeClosed(): Promise<void> {
    // The buttons of the row are gone: the focus goes back to the page heading.
    if (revoked) {
      revoked = false;
      await tick();
      heading?.focus();
    }
  }

  const date = (value: string): string => formatDate(value, { dateStyle: 'medium', timeStyle: 'short' });
</script>

{#snippet labelCell(row: DropLink)}
  <span class="tt-break">{row.label}</span>
{/snippet}

{#snippet recipientsCell(row: DropLink)}
  <ul class="tt-list-plain tt-droplinks__values">
    {#each row.recipients as recipient (recipient)}
      <li class="tt-break">{recipient}</li>
    {/each}
  </ul>
{/snippet}

{#snippet validityCell(row: DropLink)}
  {t('opsDropLinks.form.validity.days', { count: row.validityDays })}
{/snippet}

{#snippet levelCell(row: DropLink)}
  {#if row.confidentialityLevel}
    {levelLabel(levels, row.confidentialityLevel, locale.current)}
  {:else}
    <span class="tt-text-muted">{t('opsDropLinks.list.defaultLevel')}</span>
  {/if}
{/snippet}

{#snippet expiryCell(row: DropLink)}
  {#if row.expiresAt}
    {date(row.expiresAt)}
  {:else}
    <span class="tt-text-muted">{t('opsDropLinks.list.noExpiry')}</span>
  {/if}
{/snippet}

{#snippet capCell(row: DropLink)}
  {t('opsDropLinks.list.capValue', { count: row.maxDepositsPerHour })}
{/snippet}

{#snippet statusCell(row: DropLink)}
  {@const view = dropStatusView(dropLinkStatus(row))}
  <StatusBadge variant={view.variant} label={t(view.key)} />
  {#if row.revokedAt}
    <span class="tt-droplinks__when">{date(row.revokedAt)}</span>
  {/if}
  {#if row.unused && dropLinkStatus(row) !== 'revoked'}
    <StatusBadge variant="warning" label={t('opsDropLinks.list.unused')} />
    <span class="tt-droplinks__when">{t('opsDropLinks.list.unusedHint')}</span>
  {/if}
{/snippet}

{#snippet lastUsedCell(row: DropLink)}
  {row.lastUsedAt ? date(row.lastUsedAt) : t('opsDropLinks.list.neverUsed')}
{/snippet}

{#snippet actionsCell(row: DropLink)}
  {#if isDropLinkManageable(row)}
    <div class="tt-cluster">
      <Button variant="secondary" onclick={() => startEdit(row)}>
        {t('opsDropLinks.list.edit')}<span class="visually-hidden"> {row.label}</span>
      </Button>
      <Button variant="secondary" disabled={toggling.includes(row.id)} onclick={() => void toggle(row)}>
        {row.enabled ? t('opsDropLinks.list.disable') : t('opsDropLinks.list.enable')}<span
          class="visually-hidden"
        >
          {row.label}</span
        >
      </Button>
      <Button variant="secondary" onclick={() => startRotate(row)}>
        {t('opsDropLinks.list.rotate')}<span class="visually-hidden"> {row.label}</span>
      </Button>
      <Button variant="danger" onclick={() => startRevoke(row)}>
        {t('opsDropLinks.list.revoke')}<span class="visually-hidden"> {row.label}</span>
      </Button>
    </div>
  {/if}
{/snippet}

<div class="tt-title-row">
  <h1 tabindex="-1" bind:this={heading}>{t('adminOps.dropLinks.title')}</h1>
  <HelpIcon topic="tenant-drop-links" title={t('adminOps.dropLinks.title')} {nav} />
</div>
<p>{t(readOnly ? 'adminOps.dropLinks.introReadOnly' : 'adminOps.dropLinks.intro')}</p>

{#if !readOnly}
  <p>
    <a href={nav.href(`${tenantPath(tenantId, 'dropLinks')}/new`)} use:nav.link
      >{t('opsDropLinks.list.create')}</a
    >
  </p>
{/if}

{#if actionError !== ''}
  <Alert severity="error">{actionError}</Alert>
{/if}

{#if levelsError !== ''}
  <Alert severity="error">{levelsError}</Alert>
{/if}

{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load(tenantId)}>{t('common.retry')}</Button>
  </Alert>
{:else}
  <DataTable
    caption={t('opsDropLinks.list.caption')}
    captionHidden
    {rows}
    key={(row) => row.id}
    {loading}
    emptyText={t('opsDropLinks.list.empty')}
    columns={[
      { id: 'label', header: t('opsDropLinks.list.columns.label'), cell: labelCell, rowHeader: true },
      { id: 'recipients', header: t('opsDropLinks.list.columns.recipients'), cell: recipientsCell },
      { id: 'validity', header: t('opsDropLinks.list.columns.validity'), cell: validityCell },
      { id: 'level', header: t('opsDropLinks.list.columns.level'), cell: levelCell },
      { id: 'expiry', header: t('opsDropLinks.list.columns.expiry'), cell: expiryCell },
      { id: 'cap', header: t('opsDropLinks.list.columns.cap'), cell: capCell },
      { id: 'status', header: t('opsDropLinks.list.columns.status'), cell: statusCell },
      { id: 'lastUsed', header: t('opsDropLinks.list.columns.lastUsed'), cell: lastUsedCell },
      ...(readOnly
        ? []
        : [
            {
              id: 'actions',
              header: t('opsDropLinks.list.columns.actions'),
              cell: actionsCell,
              headerHidden: true,
            },
          ]),
    ]}
  />
  {#if !loading && links.length > 0}
    <p class="tt-text-sm tt-text-muted">{t('opsDropLinks.list.lastUsedNote')}</p>
  {/if}
{/if}

{#if editing !== undefined}
  <DropLinkEditDialog
    bind:open={editOpen}
    link={editing}
    {tenantId}
    levels={options}
    addGuard={(guard) => nav.addGuard(guard)}
    onsaved={saved}
  />
{/if}

<ConfirmDialog
  bind:open={rotateOpen}
  title={t('opsDropLinks.rotate.title', { label: rotating?.label ?? '' })}
  text={t('opsDropLinks.rotate.text')}
  confirmLabel={t('opsDropLinks.rotate.confirm')}
  onconfirm={rotate}
  onclose={() => void rotateClosed()}
/>

<ConfirmDialog
  bind:open={revokeOpen}
  title={t('opsDropLinks.revoke.title', { label: revoking?.label ?? '' })}
  text={t('opsDropLinks.revoke.text')}
  confirmLabel={t('opsDropLinks.revoke.confirm')}
  danger
  onconfirm={revoke}
  onclose={() => void revokeClosed()}
/>

{#if secret !== ''}
  <SecretOnceModal
    bind:open={secretOpen}
    title={secretTitle}
    {secret}
    text={t('opsDropLinks.secret.rotatedText')}
    secretLabel={t('opsDropLinks.secret.label')}
    addGuard={(guard) => nav.addGuard(guard)}
    onclose={() => {
      secret = '';
    }}
  />
{/if}

<style>
  .tt-droplinks__values {
    margin: 0;
  }

  .tt-droplinks__when {
    display: block;
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
