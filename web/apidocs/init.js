// Starts the vendored Scalar API reference (see README.md) on the OpenAPI document of the
// instance. It is an external script because the Content-Security-Policy of /api/docs forbids
// inline scripts. Every option that could make the page reach a third-party service is turned
// off; the CSP (connect-src, font-src and img-src limited to the same origin) blocks them anyway.
(function () {
  'use strict';
  window.Scalar.createApiReference('#app', {
    url: '/api/openapi.yaml',
    // No fonts from fonts.scalar.com: the system fonts are used.
    withDefaultFonts: false,
    telemetry: false,
    // "Try it" requests go straight to this origin, never through proxy.scalar.com.
    proxyUrl: '',
    // No button opening the specification in client.scalar.com.
    hideClientButton: true,
    showDeveloperTools: 'never',
    // Credentials typed in the page are never kept in the local storage.
    persistAuth: false,
    // No AI agent nor MCP integration (Scalar hosted services).
    agent: { disabled: true },
    mcp: { disabled: true }
  });
}());
