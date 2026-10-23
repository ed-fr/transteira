// Package apidocs embeds the interactive API documentation served at /api/docs: a vendored,
// pinned build of Scalar (see README.md for its version, origin and checksums), the page that
// hosts it and its start script. Nothing is loaded from a CDN.
package apidocs

import _ "embed"

// IndexHTML is the documentation page. It has no inline script nor event handler.
//
//go:embed index.html
var IndexHTML []byte

// InitJS starts Scalar on /api/openapi.yaml with every remote service disabled.
//
//go:embed init.js
var InitJS []byte

// ScalarJS is the standalone browser build of @scalar/api-reference, byte for byte as published
// on the npm registry.
//
//go:embed scalar.js
var ScalarJS []byte
