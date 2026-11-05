package admin

import (
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/strictjson"
)

// FuzzDecodeImport checks that decodeImport, the parsing path of an import
// body, never panics, that it refuses only with the answers importTenant
// declares for a document (422 import-invalid with one field error, 422
// import-schema-unsupported, 400 validation-failed), and that what it
// accepts passes the strict check and has schemaVersion 1.
func FuzzDecodeImport(f *testing.F) {
	for _, s := range []string{
		validImport,
		`{}`, `null`, `[]`, `{`, `{"config":{}}`, `{"config":{"schemaVersion":2}}`, `{"config":{"schemaVersion":"1"}}`,
		`{"config":{"schemaVersion":1},"config":{"schemaVersion":1}}`,
		`{"config":{"schemaVersion":1,"network":{"internalCidrs":[[[]]]}}}`,
		`{"config":{"schemaVersion":1,"abuseThresholds":{"officeHours":null,"unusualVolumeFactor":1e999}}}`,
		`{"config":{"schemaVersion":1,"confidentialityLevels":{"items":[{"labels":{"fr":"a","de":"b"}}]}}}`,
		`{"delegatedAdmin":{"delivery":"none"},"config":{"schemaVersion":1}}`,
		`{"name":"\u0000","config":{"schemaVersion":1,"settings":{"maxTransferBytes":-1}}}`,
		`{"config":{"schemaVersion":1,"abuseThresholds":{"timeZone":"UTC"}}}`,
		`{"config":{"schemaVersion":1,"legalDocuments":[{},{},{},{},{}]}}`,
		`{"config":{"schemaVersion":true}}`, `{"config":{"schemaVersion":-3}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		in, err := decodeImport(raw)
		if err != nil {
			var p *problem.Problem
			if !errors.As(err, &p) {
				t.Fatalf("decodeImport(%q) error %v is not a Problem", raw, err)
			}
			switch p.Code {
			case problem.CodeImportInvalid, problem.CodeValidationFailed:
				if len(p.Errors) != 1 {
					t.Fatalf("decodeImport(%q): %s with errors %+v", raw, p.Code, p.Errors)
				}
			case problem.CodeImportSchemaUnsupported:
			default:
				t.Fatalf("decodeImport(%q): undeclared code %s", raw, p.Code)
			}
			return
		}
		if err := strictjson.Check(raw, importSchema, importMaxDepth); err != nil {
			t.Fatalf("decodeImport(%q) accepted a document the strict check refuses: %v", raw, err)
		}
		if in.Config.SchemaVersion != 1 {
			t.Fatalf("decodeImport(%q) accepted schemaVersion %d", raw, in.Config.SchemaVersion)
		}
	})
}
