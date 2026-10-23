# Interactive API documentation (vendored Scalar)

`/api/docs` serves an interactive reference generated in the browser from `/api/openapi.yaml`
by [Scalar](https://github.com/scalar/scalar). Everything is embedded in the binary
(`embed.go`): the page never loads anything from a CDN or another origin.

| File | Origin |
|---|---|
| `index.html` | TransTeira (no inline script nor event handler) |
| `init.js` | TransTeira: starts Scalar, disables remote fonts, telemetry, the request proxy, the client button, the developer tools, the agent and MCP |
| `scalar.js` | vendored, unmodified (see below) |
| `LICENSE.scalar` | MIT license of Scalar |

## Vendored files

| File | Value |
|---|---|
| Package | `@scalar/api-reference` **1.73.1** (published 2026-10-07 on the npm registry) |
| Tarball | <https://registry.npmjs.org/@scalar/api-reference/-/api-reference-1.73.1.tgz> |
| Tarball integrity (npm) | `sha512-YatOueurjdSAbE3K51L0NkyzdQEpksnjvzCpJTSMPaYd6VWpXMrycDfTBY0myuhszgxk+PcOehExyIXc20yXhw==` |
| `scalar.js` | `package/dist/browser/standalone.js` of the tarball, 4 431 523 bytes |
| `scalar.js` SHA-256 | `62c34a0dda38945864011ebaf6e7fa7812a332429120d18922b34d01c4f7ccc8` |
| `LICENSE.scalar` | <https://raw.githubusercontent.com/scalar/scalar/main/LICENSE> (the tarball ships none) |
| `LICENSE.scalar` SHA-256 | `380cd0a6ad700e1f821f2a509f0dd9ff835041cee2d43daf5dedc1adb2bcc620` |

`scalar.js` is self-contained (no lazy-loaded chunk) and injects its own styles, hence
`style-src 'self' 'unsafe-inline'` in the Content-Security-Policy of this page only. Its last
line references `standalone.js.map`, which is not vendored: browsers request it only when the
developer tools are open, and get a 404.

## License

Scalar is distributed under the MIT license (`LICENSE.scalar`), compatible with the AGPL-3.0 of
TransTeira. The bundle also contains third-party components under permissive licenses (Vue,
highlight.js, Tailwind CSS, focus-trap, etc.), whose notices are kept in the file.

## Remote resources

The bundle contains hardcoded URLs of Scalar services, all disabled or unused with this
configuration, and blocked anyway by the page's CSP (`connect-src`, `font-src` and `img-src`
limited to the same origin):

- `fonts.scalar.com` (Inter and a monospace font): `withDefaultFonts: false`;
- `proxy.scalar.com`, `api.scalar.com/request-proxy`: `proxyUrl: ''`;
- `client.scalar.com`: `hideClientButton: true` (a link, never loaded by itself);
- `dashboard.scalar.com`, `registry.scalar.com`, `api.scalar.com`: agent, MCP and registry
  features, off (`agent.disabled`, `mcp.disabled`, no agent key);
- `galaxy.scalar.com`, `picsum.photos`, `loremflickr.com`: placeholders and example data only;
- the `telemetry` option exists in the configuration schema but no telemetry code is present in
  the browser build; it is set to `false` anyway.

## Updating

1. Pick a version published at least two weeks earlier.
2. Download the tarball into an empty scratch directory, check its integrity against
   `npm view @scalar/api-reference@<version> dist.integrity`, and never run anything from it.
3. Copy `package/dist/browser/standalone.js` to `scalar.js`, unmodified.
4. Search it for new external URLs and new configuration options that reach remote services,
   and adjust `init.js`.
5. Update this file (version, URLs, sizes, SHA-256) and check the page in a browser with the
   developer tools open: no request may leave the origin.
