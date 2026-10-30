// Labels of the audit log, shared by the tenant audit log and the instance audit log: action
// groups and translated action labels, actor and object display, and the flattening of the free
// "details" object into text pairs. Nothing here assumes a single tenant: the tenant of an event
// is passed explicitly where it matters (link to a transfer). The enumerations are extensible
// (CLAUDE.md, API contract): an unknown action, actor kind or object kind is shown as its raw
// code, never hidden.
import { auditActionValues, auditEventActorKindValues, type components } from '../../../shared/api/schema';
import { detailPath } from './transfers';
import type { SelectGroup, SelectOption } from '../../components/select';
import type { Translate } from '../../../shared/i18n/messages';

/** Translation function (the t of the i18n module). */
export type { Translate };

/** An audit action known to this version of the specification. */
export type AuditAction = components['schemas']['AuditAction'];
/** An audit event. */
export type AuditEvent = components['schemas']['AuditEvent'];
/** Kind of the actor of an audit event known to this version. */
export type AuditActorKind = AuditEvent['actor']['kind'];

/** Identifier of a group of audit actions (the grouping of docs/operations/admin.md). */
export type AuditGroupId =
  | 'transfers'
  | 'invitations'
  | 'antivirus'
  | 'quotas'
  | 'abuse'
  | 'blocklist'
  | 'tokens'
  | 'privacy'
  | 'tenant'
  | 'accounts'
  | 'instance';

/** A group of audit actions, in display order. */
export interface AuditActionGroup {
  id: AuditGroupId;
  actions: readonly AuditAction[];
}

/** Every audit action, by group, in display order (each action of the specification once). */
export const AUDIT_ACTION_GROUPS = [
  {
    id: 'transfers',
    actions: [
      'transfer.created',
      'transfer.finalized',
      'transfer.downloaded',
      'transfer.notification_resent',
      'transfer.expired',
      'transfer.deleted',
      'transfer.extended',
      'transfer.reminder_sent',
      'transfer.reply_created',
      'transfer.recipient_refused',
    ],
  },
  {
    id: 'invitations',
    actions: [
      'invitation.created',
      'invitation.used',
      'invitation.revoked',
      'address.verified',
      'recipient.verified',
      'my_transfers.link_requested',
      'my_transfers.signed_in',
    ],
  },
  { id: 'antivirus', actions: ['file.infected', 'file.not_scanned'] },
  { id: 'quotas', actions: ['quota.warning', 'quota.reached'] },
  {
    id: 'abuse',
    actions: [
      'abuse.threshold_exceeded',
      'abuse.unusual_activity',
      'abuse.reported',
      'abuse.report_closed',
      'abuse.report_reopened',
    ],
  },
  { id: 'blocklist', actions: ['blocklist.updated'] },
  {
    id: 'tokens',
    actions: ['api_token.created', 'api_token.updated', 'api_token.used', 'api_token.revoked'],
  },
  { id: 'privacy', actions: ['data_subject.searched', 'data_subject.erased'] },
  {
    id: 'tenant',
    actions: [
      'tenant.created',
      'tenant.updated',
      'tenant.branding_updated',
      'tenant.asset_uploaded',
      'tenant.asset_deleted',
      'tenant.network_updated',
      'tenant.smtp_updated',
      'tenant.smtp_tested',
      'tenant.template_updated',
      'tenant.template_reset',
      'tenant.legal_updated',
      'tenant.confidentiality_updated',
      'tenant.recipient_rules_updated',
      'tenant.abuse_settings_updated',
      'tenant.antivirus_disabled',
      'tenant.antivirus_enabled',
      'webhook.created',
      'webhook.updated',
      'webhook.deleted',
      'webhook.tested',
      'tenant.deletion_started',
      'tenant.deleted',
    ],
  },
  {
    id: 'accounts',
    actions: [
      'setup.completed',
      'admin.login',
      'admin.login_failed',
      'admin.logout',
      'admin.totp_enrolled',
      'admin.totp_disabled',
      'admin.recovery_code_used',
      'admin.password_changed',
      'admin.created',
      'admin.updated',
      'admin.deleted',
      'admin.credentials_reset',
      'admin.activated',
      'admin.totp_reset_local',
      'admin.password_reset_local',
    ],
  },
  {
    id: 'instance',
    actions: [
      'maintenance.enabled',
      'maintenance.disabled',
      'config.updated',
      'disk.alert_raised',
      'disk.alert_cleared',
      'antivirus.alert_raised',
      'antivirus.alert_cleared',
      'antivirus.scans_released',
      'antivirus.self_test',
      'master_key.rotation_started',
      'master_key.rotation_completed',
      'master_key.rotation_failed',
    ],
  },
] as const satisfies readonly AuditActionGroup[];

type GroupedAction = (typeof AUDIT_ACTION_GROUPS)[number]['actions'][number];
type MustBeNever<T extends never> = T;
/**
 * Compile-time check that every AuditAction of the generated schema belongs to a group: adding an
 * action to the specification without grouping it here fails the type check.
 */
export type UngroupedAuditActions = MustBeNever<Exclude<AuditAction, GroupedAction>>;

/** Every known action (the list generated from the specification). */
export const AUDIT_ACTIONS: readonly AuditAction[] = auditActionValues;
/** Every known actor kind. */
export const AUDIT_ACTOR_KINDS: readonly AuditActorKind[] = auditEventActorKindValues;
/** Object kinds with a translated label (the audit package of the server); others show raw. */
export const AUDIT_OBJECT_KINDS = [
  'transfer',
  'file',
  'invitation',
  'api_token',
  'admin',
  'tenant',
  'blocklist_entry',
  'data_subject',
  'deposit_session',
  'master_key_rotation',
  'system',
] as const;

/** Prefix of the pseudonym that replaces an erased address (GDPR erasure). */
export const ERASED_PREFIX = 'erased-';

/** Reports whether value is an action of this version of the specification. */
export function isKnownAction(value: string): value is AuditAction {
  return (AUDIT_ACTIONS as readonly string[]).includes(value);
}

/** Translation key of a known action. */
export function actionKey(action: AuditAction): string {
  return `opsAudit.actions.${action}`;
}

/** Label of an action: translated when known, the raw code otherwise. */
export function actionLabel(action: string, t: Translate): string {
  return isKnownAction(action) ? t(actionKey(action)) : action;
}

/** Options of auditActionGroups. */
export interface ActionGroupOptions {
  /** Groups left out (e.g. the instance actions in a tenant log). */
  exclude?: readonly AuditGroupId[];
}

/** Groups of the action select field (optgroups), labels translated. */
export function auditActionGroups(t: Translate, options: ActionGroupOptions = {}): SelectGroup[] {
  const exclude = options.exclude ?? [];
  return AUDIT_ACTION_GROUPS.filter((g) => !exclude.includes(g.id)).map((g) => ({
    group: g.id,
    label: t(`opsAudit.groups.${g.id}`),
    options: g.actions.map((action): SelectOption => ({ value: action, label: actionLabel(action, t) })),
  }));
}

/** Label of an actor kind: translated when known, the raw kind otherwise. */
export function actorKindLabel(kind: string, t: Translate): string {
  return (AUDIT_ACTOR_KINDS as readonly string[]).includes(kind) ? t(`opsAudit.actorKinds.${kind}`) : kind;
}

/** Label of an object kind: translated when known, the raw kind otherwise. */
export function objectKindLabel(kind: string, t: Translate): string {
  return (AUDIT_OBJECT_KINDS as readonly string[]).includes(kind) ? t(`opsAudit.objectKinds.${kind}`) : kind;
}

/** Reports whether an identifier is the pseudonym of an erased address. */
export function isErased(id: string): boolean {
  return id.startsWith(ERASED_PREFIX);
}

/** Display of an actor or an object: kind label, identifier text and an optional hint. */
export interface PartyView {
  kind: string;
  id: string;
  hint?: string;
}

/**
 * Display of the actor of an event: the kind label and its identifier (admin username, address,
 * token id, system component). A recipient through the shared transfer link ("link") is written
 * out; a pseudonym of an erased address is shown as is, with a hint.
 */
export function actorView(actor: { kind: string; id: string }, t: Translate): PartyView {
  const view: PartyView = { kind: actorKindLabel(actor.kind, t), id: actor.id };
  if (actor.kind === 'recipient' && actor.id === 'link') {
    view.id = t('opsAudit.actor.recipientLink');
  }
  if (isErased(actor.id)) {
    view.hint = t('opsAudit.actor.erasedHint');
  }
  return view;
}

/** Display of the object of an event (a pseudonym of an erased address gets the same hint). */
export function objectView(object: { kind: string; id: string }, t: Translate): PartyView {
  const view: PartyView = { kind: objectKindLabel(object.kind, t), id: object.id };
  if (isErased(object.id)) {
    view.hint = t('opsAudit.actor.erasedHint');
  }
  return view;
}

/**
 * Application path of the object of an event, when the interface has a page for it: the detail of
 * a transfer of the event's tenant. Undefined otherwise (no tenant, other kinds, empty id).
 */
export function objectPath(
  tenantId: string | null | undefined,
  object: { kind: string; id: string },
): string | undefined {
  if (
    object.kind !== 'transfer' ||
    object.id === '' ||
    tenantId === undefined ||
    tenantId === null ||
    tenantId === ''
  ) {
    return undefined;
  }
  return detailPath(tenantId, object.id);
}

/** One line of the details of an event. */
export interface DetailEntry {
  key: string;
  value: string;
}

/** Text of a detail value: strings as is, scalars with String, objects and arrays as JSON. */
export function detailValue(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  if (value === null || value === undefined) {
    return String(value);
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value as number | boolean | bigint);
}

/**
 * Lines of the free details of an event, in their order: always text (rendered as text by the
 * screen, never as HTML). Empty when there are no details.
 */
export function detailEntries(details: Record<string, unknown> | null | undefined): DetailEntry[] {
  if (details === undefined || details === null || typeof details !== 'object') {
    return [];
  }
  return Object.entries(details).map(([key, value]) => ({ key, value: detailValue(value) }));
}
