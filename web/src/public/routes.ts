// Route table of the public application (tenant hosts). The server serves the application
// shell on the same paths (internal/httpserver/webui.go) and answers other paths with 404.
import type { Route } from '../shared/router/router.svelte';
import Download from './screens/Download.svelte';
import Help from './screens/Help.svelte';
import HelpPrint from './screens/HelpPrint.svelte';
import Home from './screens/Home.svelte';
import InvitationLanding from './screens/InvitationLanding.svelte';
import Invite from './screens/Invite.svelte';
import Legal from './screens/Legal.svelte';
import MyTransfers from './screens/MyTransfers.svelte';
import NotFound from './screens/NotFound.svelte';
import ReplyScreen from './screens/ReplyScreen.svelte';
import type { ScreenComponent } from './screens/types';

/** Routes of the public application. */
export const routes: readonly Route<ScreenComponent>[] = [
  { pattern: '/', component: Home, titleKey: 'common.home.title', helpTopic: 'deposit' },
  { pattern: '/d/:token', component: Download, titleKey: 'download.title', helpTopic: 'download' },
  {
    pattern: '/d/:token/reply',
    component: ReplyScreen,
    titleKey: 'download.reply.page.title',
    helpTopic: 'download',
  },
  {
    pattern: '/i/:token',
    component: InvitationLanding,
    titleKey: 'invitation.landing.title',
    helpTopic: 'invitation',
  },
  { pattern: '/invite', component: Invite, titleKey: 'invitation.invite.title', helpTopic: 'invite' },
  { pattern: '/me', component: MyTransfers, titleKey: 'myTransfers.title', helpTopic: 'my-transfers' },
  { pattern: '/legal/:document', component: Legal, titleKey: 'legal.title', helpTopic: 'legal' },
  { pattern: '/help', component: Help, titleKey: 'common.help.title' },
  // Before /help/:topic: "print" is reserved, no guide declares it as a topic.
  { pattern: '/help/print', component: HelpPrint, titleKey: 'help.print.title' },
  { pattern: '/help/:topic', component: Help, titleKey: 'common.help.title' },
];

/** Route of unknown paths. */
export const notFoundRoute: Route<ScreenComponent> = {
  pattern: '*',
  component: NotFound,
  titleKey: 'common.notFound.title',
  helpTopic: 'deposit',
};

/** Reports whether a route is the help itself (no help link in its footer). */
export function isHelpRoute(route: Pick<Route, 'pattern'>): boolean {
  return route.pattern === '/help' || route.pattern.startsWith('/help/');
}
