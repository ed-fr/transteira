// Route table of the admin application (admin host, under the base path /admin). Shell only
// in step 15: the admin screens arrive in step 16.
import type { Route } from '../shared/router/router.svelte';
import Help from './screens/Help.svelte';
import NotFound from './screens/NotFound.svelte';
import Placeholder from './screens/Placeholder.svelte';
import type { AdminScreenComponent } from './screens/types';

/** Base path of the admin application. */
export const ADMIN_BASE = '/admin';

/** Routes of the admin application (without the base path). */
export const routes: readonly Route<AdminScreenComponent>[] = [
  { pattern: '/', component: Placeholder, titleKey: 'admin.placeholder.title', helpTopic: 'admin' },
  { pattern: '/help', component: Help, titleKey: 'common.help.title' },
  { pattern: '/help/:topic', component: Help, titleKey: 'common.help.title' },
];

/** Route of unknown paths. */
export const notFoundRoute: Route<AdminScreenComponent> = {
  pattern: '*',
  component: NotFound,
  titleKey: 'common.notFound.title',
  helpTopic: 'admin',
};
