// Package api embeds the OpenAPI specification of TransTeira, the single source of truth of
// the HTTP contract. It is served at /api/openapi.yaml and used to generate internal/api/gen.
package api

import _ "embed"

//go:generate go tool oapi-codegen -config oapi-codegen.yaml openapi.yaml

// OpenAPISpec is the raw OpenAPI 3.1 document (YAML).
//
//go:embed openapi.yaml
var OpenAPISpec []byte
