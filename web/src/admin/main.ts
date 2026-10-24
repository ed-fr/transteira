// Entry point of the admin application (admin host, under /admin/). Served by
// internal/httpserver/webui.go under the admin UI CSP.
import { mount } from 'svelte';
import '../styles/tokens.css';
import '../styles/base.css';
import App from './App.svelte';
import { captureActivationToken } from './auth/activationToken';
import { ADMIN_BASE } from './routes';

// Before the router and the session bootstrap (App): the activation token leaves the URL now,
// so that it is neither kept while the bootstrap runs nor seen by the router (T-162).
captureActivationToken(window, `${ADMIN_BASE}/activate`);

const target = document.getElementById('app');
if (target === null) {
  throw new Error('missing #app mount point');
}

export default mount(App, { target });
