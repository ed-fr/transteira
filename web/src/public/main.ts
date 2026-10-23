// Entry point of the public application (tenant hosts): deposit, download, invitations, legal
// pages. Served by internal/httpserver/webui.go under the public UI CSP.
import { mount } from 'svelte';
import '../styles/tokens.css';
import '../styles/base.css';
import App from './App.svelte';

const target = document.getElementById('app');
if (target === null) {
  throw new Error('missing #app mount point');
}

export default mount(App, { target });
