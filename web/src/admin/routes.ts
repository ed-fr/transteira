// Route table of the admin application (admin host, under the base path /admin). Each route
// declares its access level, checked by resolveAccess (auth/guard.ts) on every navigation and
// every change of the authentication state, and its help topic.
//
//   setup      first-run setup only (and the setup flow that follows it)
//   anonymous  sign-in screen; an authenticated admin goes to the return path
//   any        always rendered (activation link, help, not found)
//   auth       authenticated admin; a tenant outside the admin's scope is "not found"
//   super      super admin only; "not found" for another role
//
// Screens are imported eagerly: the router focuses the page heading right after a navigation,
// which a lazily loaded screen would not have rendered yet.
import type { Route } from '../shared/router/router.svelte';
import type { RouteAccess } from './auth/guard';
import Account from './screens/Account.svelte';
import AdminCreate from './screens/admins/AdminCreate.svelte';
import AdminEdit from './screens/admins/AdminEdit.svelte';
import AdminList from './screens/admins/AdminList.svelte';
import Activate from './screens/auth/Activate.svelte';
import Login from './screens/auth/Login.svelte';
import Setup from './screens/auth/Setup.svelte';
import Help from './screens/Help.svelte';
import Home from './screens/Home.svelte';
import NotFound from './screens/NotFound.svelte';
import AuditLog from './screens/ops/AuditLog.svelte';
import Blocklist from './screens/ops/Blocklist.svelte';
import InvitationList from './screens/ops/InvitationList.svelte';
import Privacy from './screens/ops/Privacy.svelte';
import TenantStats from './screens/ops/TenantStats.svelte';
import TokenCreate from './screens/ops/TokenCreate.svelte';
import TokenList from './screens/ops/TokenList.svelte';
import TransferDetail from './screens/ops/TransferDetail.svelte';
import TransferList from './screens/ops/TransferList.svelte';
import GlobalAudit from './screens/system/GlobalAudit.svelte';
import Maintenance from './screens/system/Maintenance.svelte';
import MasterKey from './screens/system/MasterKey.svelte';
import SystemOverview from './screens/system/SystemOverview.svelte';
import SystemSettings from './screens/system/SystemSettings.svelte';
import LegalEdit from './screens/tenants/LegalEdit.svelte';
import LegalList from './screens/tenants/LegalList.svelte';
import TemplateEdit from './screens/tenants/TemplateEdit.svelte';
import TemplateList from './screens/tenants/TemplateList.svelte';
import TenantBranding from './screens/tenants/TenantBranding.svelte';
import TenantCreate from './screens/tenants/TenantCreate.svelte';
import TenantGeneral from './screens/tenants/TenantGeneral.svelte';
import TenantList from './screens/tenants/TenantList.svelte';
import TenantNetwork from './screens/tenants/TenantNetwork.svelte';
import TenantSmtp from './screens/tenants/TenantSmtp.svelte';
import type { AdminScreenComponent } from './screens/types';

/** Base path of the admin application. */
export const ADMIN_BASE = '/admin';

/** A route of the admin application. */
export interface AdminRoute extends Route<AdminScreenComponent> {
  /** Access level, checked by resolveAccess. */
  access: RouteAccess;
  /** Shows the tenant sub-navigation (TenantNav) above the screen; the route has an :id. */
  tenantNav?: boolean;
  /** Shows the system sub-navigation (SystemNav) above the screen; never with tenantNav. */
  systemNav?: boolean;
}

/** Routes of the admin application (without the base path). */
export const routes: readonly AdminRoute[] = [
  {
    pattern: '/setup',
    component: Setup,
    titleKey: 'adminAuth.setup.title',
    access: 'setup',
    helpTopic: 'setup',
  },
  {
    pattern: '/login',
    component: Login,
    titleKey: 'adminAuth.login.title',
    access: 'anonymous',
    helpTopic: 'login',
  },
  {
    pattern: '/activate',
    component: Activate,
    titleKey: 'adminAuth.activation.title',
    access: 'any',
    helpTopic: 'activation',
  },
  { pattern: '/', component: Home, titleKey: 'admin.home.title', access: 'auth', helpTopic: 'admin' },
  {
    pattern: '/account',
    component: Account,
    titleKey: 'adminAuth.account.title',
    access: 'auth',
    helpTopic: 'account',
  },
  {
    pattern: '/tenants',
    component: TenantList,
    titleKey: 'adminTenants.list.title',
    access: 'auth',
    helpTopic: 'tenants',
  },
  {
    pattern: '/tenants/new',
    component: TenantCreate,
    titleKey: 'adminTenants.create.title',
    access: 'super',
    helpTopic: 'tenants',
  },
  {
    pattern: '/tenants/:id/general',
    component: TenantGeneral,
    titleKey: 'adminTenants.general.title',
    access: 'auth',
    helpTopic: 'tenant-general',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/branding',
    component: TenantBranding,
    titleKey: 'adminTenants.branding.title',
    access: 'auth',
    helpTopic: 'tenant-branding',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/network',
    component: TenantNetwork,
    titleKey: 'adminTenants.network.title',
    access: 'auth',
    helpTopic: 'tenant-network',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/smtp',
    component: TenantSmtp,
    titleKey: 'adminTenants.smtp.title',
    access: 'auth',
    helpTopic: 'tenant-smtp',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/templates',
    component: TemplateList,
    titleKey: 'adminTenants.templates.title',
    access: 'auth',
    helpTopic: 'tenant-templates',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/templates/:key/:lang',
    component: TemplateEdit,
    titleKey: 'adminTenants.templates.title',
    access: 'auth',
    helpTopic: 'tenant-templates',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/legal',
    component: LegalList,
    titleKey: 'adminTenants.legal.title',
    access: 'auth',
    helpTopic: 'tenant-legal',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/legal/:document/:lang',
    component: LegalEdit,
    titleKey: 'adminTenants.legal.title',
    access: 'auth',
    helpTopic: 'tenant-legal',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/transfers',
    component: TransferList,
    titleKey: 'adminOps.transfers.title',
    access: 'auth',
    helpTopic: 'tenant-transfers',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/transfers/:transferId',
    component: TransferDetail,
    titleKey: 'adminOps.transfers.detailTitle',
    access: 'auth',
    helpTopic: 'tenant-transfers',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/invitations',
    component: InvitationList,
    titleKey: 'adminOps.invitations.title',
    access: 'auth',
    helpTopic: 'tenant-invitations',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/blocklist',
    component: Blocklist,
    titleKey: 'adminOps.blocklist.title',
    access: 'auth',
    helpTopic: 'tenant-blocklist',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/tokens',
    component: TokenList,
    titleKey: 'adminOps.tokens.title',
    access: 'auth',
    helpTopic: 'tenant-tokens',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/tokens/new',
    component: TokenCreate,
    titleKey: 'adminOps.tokens.createTitle',
    access: 'auth',
    helpTopic: 'tenant-tokens',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/audit',
    component: AuditLog,
    titleKey: 'adminOps.audit.title',
    access: 'auth',
    helpTopic: 'tenant-audit',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/stats',
    component: TenantStats,
    titleKey: 'adminOps.stats.title',
    access: 'auth',
    helpTopic: 'tenant-stats',
    tenantNav: true,
  },
  {
    pattern: '/tenants/:id/privacy',
    component: Privacy,
    titleKey: 'adminOps.privacy.title',
    access: 'auth',
    helpTopic: 'tenant-privacy',
    tenantNav: true,
  },
  {
    pattern: '/admins',
    component: AdminList,
    titleKey: 'adminAccounts.list.title',
    access: 'super',
    helpTopic: 'admins',
  },
  {
    pattern: '/admins/new',
    component: AdminCreate,
    titleKey: 'adminAccounts.form.createTitle',
    access: 'super',
    helpTopic: 'admins',
  },
  {
    pattern: '/admins/:id',
    component: AdminEdit,
    titleKey: 'adminAccounts.list.title',
    access: 'super',
    helpTopic: 'admins',
  },
  {
    pattern: '/system',
    component: SystemOverview,
    titleKey: 'adminSystem.overview.title',
    access: 'super',
    helpTopic: 'system-overview',
    systemNav: true,
  },
  {
    pattern: '/system/maintenance',
    component: Maintenance,
    titleKey: 'adminSystem.maintenance.title',
    access: 'super',
    helpTopic: 'system-maintenance',
    systemNav: true,
  },
  {
    pattern: '/system/settings',
    component: SystemSettings,
    titleKey: 'adminSystem.settings.title',
    access: 'super',
    helpTopic: 'system-settings',
    systemNav: true,
  },
  {
    pattern: '/system/audit',
    component: GlobalAudit,
    titleKey: 'adminSystem.audit.title',
    access: 'super',
    helpTopic: 'system-audit',
    systemNav: true,
  },
  {
    pattern: '/system/master-key',
    component: MasterKey,
    titleKey: 'adminSystem.masterKey.title',
    access: 'super',
    helpTopic: 'system-master-key',
    systemNav: true,
  },
  { pattern: '/help', component: Help, titleKey: 'common.help.title', access: 'any' },
  { pattern: '/help/:topic', component: Help, titleKey: 'common.help.title', access: 'any' },
];

/** Route of unknown paths. */
export const notFoundRoute: AdminRoute = {
  pattern: '*',
  component: NotFound,
  titleKey: 'common.notFound.title',
  access: 'any',
  helpTopic: 'admin',
};

/** The admin route of a match (the router only knows the base Route type). */
export function adminRoute(route: Route<AdminScreenComponent>): AdminRoute {
  return 'access' in route ? (route as AdminRoute) : notFoundRoute;
}

/** Reports whether a route is the help itself (no help link in its footer). */
export function isHelpRoute(route: Pick<Route, 'pattern'>): boolean {
  return route.pattern === '/help' || route.pattern.startsWith('/help/');
}
