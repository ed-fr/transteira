// Entry point of the admin application (admin host, under /admin/). Served by
// internal/httpserver/webui.go under the admin UI CSP. Shell only in step 15.
import { mount } from 'svelte';
import '../styles/tokens.css';
import '../styles/base.css';
import App from './App.svelte';

const target = document.getElementById('app');
if (target === null) {
  throw new Error('missing #app mount point');
}

export default mount(App, { target });
