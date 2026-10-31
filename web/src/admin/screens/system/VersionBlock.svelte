<script lang="ts">
  // "Version" block of the system overview (super admin, since 1.2): running version and commit,
  // latest published version, date of the last successful check, last error as a translated
  // sentence, the disabled state (TT_UPDATE_CHECK=false) and a "Check now" button. The release
  // link is plain text in an <a> (never HTML). Nothing here updates the instance: the block only
  // points to the CHANGELOG and the update procedure. The result of a check is announced politely.
  import { onMount } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Spinner, announce } from '../../../shared/components';
  import { formatDate, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import {
    checkFailureText,
    checkResultText,
    lastErrorKey,
    loadSystemVersion,
    runVersionCheck,
    updateNotice,
    type SystemVersion,
  } from '../../version';
  import { adminVersion } from '../../version.svelte';

  let info = $state.raw<SystemVersion | undefined>(undefined);
  let loadError = $state('');
  let checkError = $state('');
  let checking = $state(false);

  const check = $derived(info?.updateCheck);
  const errorKey = $derived(check === undefined ? undefined : lastErrorKey(check.lastError));
  const notice = $derived(updateNotice(info));

  function record(next: SystemVersion): void {
    info = next;
    adminVersion.setSystem(next);
  }

  async function load(): Promise<void> {
    loadError = '';
    try {
      record(await loadSystemVersion(adminApi));
    } catch {
      loadError = t('sysVersion.loadError');
    }
  }

  async function checkNow(): Promise<void> {
    checking = true;
    checkError = '';
    try {
      const next = await runVersionCheck(adminApi);
      record(next);
      announce(checkResultText(next, t), 'polite');
    } catch (err) {
      const view = describeError(i18n, err);
      checkError = checkFailureText(view.code, view.message, t);
      if (view.code === 'update-check-disabled') {
        void load();
      }
    } finally {
      checking = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<h2>{t('sysVersion.title')}</h2>
{#if loadError !== ''}
  <Alert severity="error">
    <p>{loadError}</p>
    <Button variant="secondary" onclick={() => void load()}>{t('common.retry')}</Button>
  </Alert>
{:else if info === undefined || check === undefined}
  <Spinner />
{:else}
  <dl class="tt-version__list">
    <dt>{t('sysVersion.running')}</dt>
    <dd>{info.version}</dd>
    {#if info.commit !== undefined && info.commit !== ''}
      <dt>{t('sysVersion.commit')}</dt>
      <dd class="tt-break"><code>{info.commit}</code></dd>
    {/if}
    {#if check.enabled}
      <dt>{t('sysVersion.latest')}</dt>
      <dd>{check.latestVersion ?? t('sysVersion.latestNone')}</dd>
      <dt>{t('sysVersion.checkedAt')}</dt>
      <dd>
        {check.checkedAt === null
          ? t('sysVersion.checkedAtNone')
          : formatDate(check.checkedAt, { dateStyle: 'medium', timeStyle: 'short' })}
      </dd>
    {/if}
  </dl>

  {#if !check.enabled}
    <Alert severity="info" live={false}><p>{t('sysVersion.disabled')}</p></Alert>
  {:else}
    {#if notice.visible}
      <Alert severity="info" live={false}>
        <p>
          <strong>{t('sysVersion.available', { version: notice.latest })}</strong>
          {#if notice.releaseUrl !== undefined}
            <a href={notice.releaseUrl} target="_blank" rel="noopener noreferrer">
              {t('sysVersion.releaseLink', { version: notice.latest })}
              <span class="visually-hidden">{t('sysVersion.newWindow')}</span>
            </a>
          {/if}
        </p>
        <p>{t('sysVersion.procedure')}</p>
      </Alert>
    {:else if errorKey === undefined && check.checkedAt !== null}
      <p>{t('sysVersion.upToDate')}</p>
    {/if}
    {#if errorKey !== undefined}
      <Alert severity="warning" live={false}><p>{t(errorKey)}</p></Alert>
    {/if}
    {#if checkError !== ''}
      <Alert severity="error"><p>{checkError}</p></Alert>
    {/if}
    <p>
      <Button
        variant="secondary"
        loading={checking}
        loadingLabel={t('sysVersion.checking')}
        onclick={() => void checkNow()}
      >
        {t('sysVersion.check')}
      </Button>
    </p>
  {/if}
{/if}

<style>
  .tt-version__list {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--tt-space-1) var(--tt-space-4);
  }

  .tt-version__list dt {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-version__list dd {
    margin: 0;
  }
</style>
