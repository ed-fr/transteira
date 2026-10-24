# TransTeira web interface

Two static Svelte 5 applications, built with Vite and embedded in the Go binary (`embed.go`):

| Application                                          | Served on                       | Entry         |
| ---------------------------------------------------- | ------------------------------- | ------------- |
| Public (deposit, download, invitations, legal pages) | every tenant host               | `src/public/` |
| Administration                                       | the admin host, under `/admin/` | `src/admin/`  |

There is no SvelteKit, no component library and no CDN. The applications only talk to the REST API
(`/api/v1`), through a typed client built on types generated from `api/openapi.yaml`.

## Layout

| Path                                             | Content                                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------------------ |
| `src/public/`, `src/admin/`                      | entry pages (`index.html`, `main.ts`, `App.svelte`), routes and screens        |
| `src/admin/{auth,forms,components,screens}/`     | admin session and guard, pure form logic, admin components, screens            |
| `src/shared/api/`                                | `schema.ts` (generated, committed), API client, Problem mapping, CSRF store    |
| `src/shared/router/`, `i18n/`, `theme/`, `safe/` | router, translations, tenant theme and contrast, `safeApiHref`                 |
| `src/shared/upload/`                             | resumable upload engine (tus 1.0.0) and its transport                          |
| `src/shared/validation/`                         | client-side checks shared by both applications (`isEmail`, `EMAIL_MAX_LENGTH`) |
| `src/shared/components/`                         | accessible components shared by both applications                              |
| `src/styles/`                                    | design tokens (CSS variables) and base styles                                  |
| `src/locales/`                                   | `<lang>/<area>.json`, mounted under the area name (`upload.json`: `upload.*`)  |
| `src/help/`                                      | reserved for the integrated help (step 19)                                     |
| `static/`                                        | files copied as is to the root of `dist/` (`favicon.svg`, `robots.txt`)        |
| `scripts/`                                       | `gen-types.mjs`, `check-dist.mjs`, `keep-dist.mjs`                             |
| `dist/`                                          | build output, embedded by `embed.go`; only `dist/.gitkeep` is committed        |

## Prerequisites

Node 24 and npm 11 (`engines` is enforced by `.npmrc`). Make targets run from Git Bash on Windows.

## Build and checks

From the repository root:

```sh
make web-install   # npm ci --ignore-scripts, rerun only when package-lock.json changes
make web-gen       # regenerate src/shared/api/schema.ts after a change of api/openapi.yaml
make web-check     # generated types up to date, svelte-check (warnings fail, a11y included),
                   # eslint, prettier, vitest with coverage, npm audit --audit-level=high
                   # (NPM_AUDIT=0 skips the audit, see below)
make web-build     # vite build, then scripts/check-dist.mjs on the output
make build         # builds the web interface, then the binary that embeds it
```

`make check` runs `web-install`, `web-check` and `web-build` first. Without a web build, `go build`,
`go vet` and `go test` still work (`dist/.gitkeep`), and the server answers the interface routes
with a fallback page; `make build` never produces a binary without the interface.

Unit tests (`*.test.ts`, Vitest) run in Node, without jsdom: the router, translations, API client
and upload engine receive their browser dependencies (history, fetch, storage, transport, timers)
by injection. Coverage must stay at 90 % or more on
`src/shared/{api,router,i18n,upload,safe,theme,validation}`
and on the `.ts` logic files of `src/public` and `src/admin` (the entry points `main.ts` excepted;
`.svelte` components are not measured, so the logic of a screen lives in a `.ts` module next to it,
for example `src/admin/auth/`, `src/admin/forms/`, `src/admin/components/*.ts`).

## API client and navigation

The typed client (`src/shared/api/client.ts`) is shared by both applications:

- **Bodies** are JSON, except a `Blob`, which is sent as is with its own type as `Content-Type`
  (branding images: `PUT /admin/tenants/{id}/branding/{asset}`). Typed `PATCH` bodies are sent as
  `application/merge-patch+json`.
- **Optional hooks**, declared by the admin application only (`src/admin/api.ts`); the public
  application declares none, so its behaviour is unchanged:
  - `onUnauthenticated` is called on `401 unauthenticated` (never on `invalid-credentials`, which
    stays a form error): the admin session goes back to the sign-in screen with a message and
    clears every in-memory store;
  - `recoverCsrf` is called on `403 csrf-invalid` for an unsafe method: when the admin is
    authenticated, it reloads `GET /admin/me` (whose answer carries the current CSRF token, for
    example after a master key switch) and the request is retried **exactly once**.
- **Sign-out** (`POST /admin/auth/logout`) clears the CSRF token and every in-memory store.
  Secrets shown by the admin screens (TOTP secret, recovery codes, activation link) stay in
  component memory, are cleared on destroy and on sign-out, and are never written to storage, to
  the URL or to an announcement (threat model T-162). The only `localStorage` entry is `tt.lang`.

The router (`src/shared/router/router.svelte.ts`) runs navigation guards (unsaved changes, an
activation link not yet handed over, an upload in progress). `navigate(path, { force: true })`
bypasses them: it is reserved for redirects the user cannot refuse (session expired, signed out,
access lost), which the admin shell (`src/admin/App.svelte`) performs with a replaced history
entry; never use it for a user navigation. The admin return path after sign-in (`?next=`) always
goes through `safeNext` (`src/admin/auth/guard.ts`), which only accepts internal paths (T-164).

Admin screens receive `params` and `nav` (`src/admin/screens/types.ts`). `nav.current` is the
reactive current location: `nav.current.path` (without the `/admin` base) and
`nav.current.search` (the query string, with its leading `?`). The filters of the operation lists
and the period of the statistics live in the query string (`src/admin/screens/ops/filters.ts`,
`stats.ts`), so that a filtered view can be bookmarked and restored by the back button. App keys
the screens on the path only, so a screen is **not** remounted when only the query string
changes: derive the filters with `$derived(parseFilters(SPEC, nav.current.search))`, reload in an
`$effect` when they change, and apply new filters with
`nav.navigate(pathWithFilters(nav.current.path, SPEC, next))`. Never put a secret or a value typed
for the data subject rights in the query string (T-168).

## Admin components

Besides the layout, data table, confirmation dialog, form sections and status badges, the admin
application has the following components in `src/admin/components/`, each with its logic in a
tested `.ts` module:

| Component                           | Purpose                                                                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `SelectField` (`select.ts`)         | labelled native `<select>`, flat options or option groups, hint and error                                                            |
| `FilterBar` (`filterBar.ts`)        | filter form of a list: apply and reset buttons, busy state, result text announced after apply or reset                               |
| `StatCard`                          | key figure (label, value, optional hint and variant)                                                                                 |
| `QuotaMeter` (`quota.ts`)           | storage used against the quota: native `<meter>`, written text and badge (warning from 80 %, full from 100 %)                        |
| `BarChart` (`charts.ts`)            | vertical bar chart in SVG with an accessible summary and an equivalent table of every value                                          |
| `SecretOnceModal` (`secretOnce.ts`) | secret shown once (new API token): closable once copied successfully or acknowledged, navigation guard and `beforeunload` until then |

Status and levels are always written out (text and badge), never conveyed by colour alone. The
screens of the tenant operations are in `src/admin/screens/ops/` (one pure `.ts` module per
screen, plus `filters.ts` and `paging.ts` shared by the lists), the dashboard in
`src/admin/screens/Home.svelte` and `home.ts`.

## Development loop

The browser must see one HTTPS origin per host, as in production: the session cookies are
`__Host-` cookies (HTTPS only), the API checks `Origin` and the tenant is resolved from `Host`.
`web/dev/Caddyfile` provides it with three processes:

| Process         | Command (from the repository root)     | Listens on                                           |
| --------------- | -------------------------------------- | ---------------------------------------------------- |
| Go server       | `go run ./cmd/transteira serve`        | `127.0.0.1:8080`                                     |
| Vite dev server | `cd web && npm run dev`                | `127.0.0.1:5173`                                     |
| Caddy           | `caddy run --config web/dev/Caddyfile` | `127.0.0.1` and `[::1]`, ports 443 and 80 (redirect) |

Caddy serves `https://transfer.entity-a.localhost`, `https://transfer.entity-b.localhost` and
`https://admin.localhost` with certificates from its local CA (`tls internal`; run `caddy trust`
once so that the browser trusts it). On every host, `/api`, `/api/*` and `/healthz` go to the Go
server and everything else to Vite, WebSocket included (hot module replacement). The routes of each
application are rewritten to its entry page (`/public/index.html` on the tenant hosts,
`/admin/index.html` under `/admin/` on the admin host, `/` redirected to `/admin/`), as the
production server does. Browsers resolve `*.localhost` to the loopback address, so no `hosts`
entry is needed. Caddy listens on the loopback interfaces only (`default_bind 127.0.0.1 [::1]`):
the development loop, which trusts its own proxy and accepts deposits from `127.0.0.1`, is never
reachable from the network.

Go server settings for this loop (in `.env` or the environment, besides the usual database, data
directory and master key):

```sh
TT_LISTEN_ADDR=127.0.0.1:8080
TT_TRUSTED_PROXIES=127.0.0.1    # Caddy connects from 127.0.0.1 and sets X-Forwarded-For
TT_ADMIN_HOSTS=admin.localhost
```

Then create the tenants `transfer.entity-a.localhost` and `transfer.entity-b.localhost` in the
administration, with `127.0.0.1/32` and `::1/128` as internal ranges to deposit from this
machine, and an SMTP server pointing to Mailpit to read the verification codes. Listing a trusted
proxy inside an internal range is acceptable here only because everything runs on one machine.

Caveats:

- Vite serves the sources without the production CSP (it injects styles for hot reload). The CSP
  rules below are checked by eslint and `check-dist`; check the console for CSP violations with
  the built binary (`make build`) behind Caddy before a commit.
- This Caddyfile needs Vite. To try the built binary instead, use a site block per host that
  proxies everything to `127.0.0.1:8080` (`tls internal` then `reverse_proxy 127.0.0.1:8080`):
  the binary serves the interface itself, with its CSP.

## Dependency policy

The interface is part of the attack surface (threat model T-159), so its supply chain is kept small
and reproducible:

- **One runtime dependency: `svelte`.** Everything else is a development tool, absent from the
  embedded build.
- **Exact versions** (`save-exact=true`) and a committed `package-lock.json`; installs always use
  `npm ci`.
- **No install scripts**: `ignore-scripts=true` in `.npmrc`, and `--ignore-scripts` in the Makefile.
  The native tools (Rolldown, Lightning CSS) ship prebuilt platform packages as optional
  dependencies and need no postinstall step.
- **Only versions published at least 14 days ago**, so that a compromised release has time to be
  detected and withdrawn before it reaches the project.
- `npm audit --audit-level=high` is part of `make check`. It queries the npm registry: offline,
  `make check NPM_AUDIT=0` (or `make web-check NPM_AUDIT=0`) skips it explicitly and says so.
  Run the full check, audit included, before a release and after any dependency change.

### Updating dependencies

1. Compute the cutoff date: today minus 14 days (`YYYY-MM-DD`).
2. List the newest eligible version of a package (`npm view` ignores `--before`, so filter its
   publication dates): `npm view <package> time --json`.
3. Install with the cutoff, which also applies to every transitive dependency:

   ```sh
   cd web
   npm install --before=<cutoff> --save-exact --ignore-scripts --no-audit <package>@<version>
   ```

4. Read the changelogs of the updated packages, then run `make web-check web-build` (and
   `make check` before the commit). Commit `package.json` and `package-lock.json` together.

Never add a runtime dependency without a review of its necessity, its maintenance and its size.

## CSP rules for contributors

The interface is served with a strict Content Security Policy (`internal/httpserver/webui.go`):
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'` (plus `data:` images on
the admin host, for the TOTP QR code and the local preview of a chosen branding image, each
validated before use), no inline script or style. Svelte builds the DOM from HTML template strings, so an
inline style written in a component would be blocked in production. The rules, checked by eslint
and by `scripts/check-dist.mjs` on the build output:

- **No `style="..."` attribute and no `style:` directive.** Use classes and the CSS variables of
  `src/styles/tokens.css`. Dynamic values go through the CSSOM
  (`element.style.setProperty('--tt-...', value)`, which the CSP does not govern), after strict
  validation (tenant colours must match `^#[0-9a-fA-F]{6}$`).
- **Charts are drawn with SVG attributes**: the geometry computed by `src/admin/components/charts.ts`
  is applied as `x`, `y`, `width` and `height` attributes of the SVG elements, never as inline
  styles or the `style:` directive; colours come from classes and theme variables.
- **No Svelte transitions or animations** (`transition:`, `in:`, `out:`): they write inline
  styles. Use CSS classes, and honour `prefers-reduced-motion`.
- **No `{@html}`**, except in exactly two components, each carrying one eslint disable comment
  (`svelte/no-at-html-tags`), the only ones of the code base:
  - `src/shared/components/LegalContent.svelte` renders a legal text already sanitised by the
    server (`internal/markup`), on the public legal page and in the admin preview;
  - `src/admin/components/TemplatePreview.svelte` renders the preview of a mail template,
    sanitised by the server (`internal/mail` allowlist); once rendered, its links lose their
    `href`, the roles, ids and tabindex of the email are removed and its headings are nested
    below the preview sub-heading with `role="heading"` and `aria-level` (`neutralizePreview`),
    and a visible note says that the inline styles of the templates are not applied: every
    template has some, the default ones included, so the CSP blocks them on every preview and
    the browser console reports these expected violations.

  No third exception may be added. Every other text, including texts from the API (messages,
  tenant names, file names), is rendered as text.

- **No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`,
  `createContextualFragment`, `DOMParser`, `eval` or `new Function`.**
- **Every URL received from the API** (download links, logo, background image) goes through
  `safeApiHref` (`src/shared/safe/href.ts`), which only accepts same-origin relative paths under
  `/api/v1/downloads/` or `/api/v1/tenant/assets/`. Svelte does not filter `href` values. The tus
  upload URLs go through `safeUploadUrl` (same rules, under `/api/v1/uploads/`) before any byte is
  sent. In the administration, the URL of a stored branding image is built by `assetUrl`
  (`src/admin/components/branding.ts`) from a validated tenant ID and image name, never taken from
  an answer.
- **No external URL and no CDN**: fonts are system fonts, images are served by the application,
  and Vite never inlines assets as `data:` URIs (`assetsInlineLimit: 0`). Stylesheets have no
  `@import`, and their `url(...)` only target `/assets/` or relative same-origin paths.
- **Only served file types in the build**: `check-dist` refuses any file whose extension is not
  served by `internal/httpserver/webui.go` (`.html .js .css .svg .png .ico .txt`).
