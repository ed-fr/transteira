package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/strictjson"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// Export and import of the configuration of a tenant (since API 2.0,
// CLAUDE.md section 22): exportTenantConfig and importTenant.

// ImportBodyLimit is the body limit of importTenant (32 MiB): the
// configuration with its base64 branding images. The route policy of the
// HTTP server applies it (413 payload-too-large beyond).
const ImportBodyLimit int64 = 32 << 20

// importMaxDepth bounds the nesting of the objects and arrays of an import
// body (T-306); the schema itself is far shallower.
const importMaxDepth = 32

// fieldInvalidValue is the field code of an import value refused by the
// validators (out of its limits, malformed, duplicate entry...).
const fieldInvalidValue = "invalid-value"

// errNoImportBody reports a server built without CaptureRawBody for the
// import route: a wiring error, answered 500.
var errNoImportBody = errors.New("admin: raw body of a tenant import missing (CaptureRawBody not installed)")

// --- Export --------------------------------------------------------------------

// ExportTenantConfig returns the configuration of a tenant as a JSON
// attachment (super admin or delegated admin of the tenant; an auditor
// gets 403 read-only-role, a tenant out of reach 404). The answer is never
// cached.
func (s *Server) ExportTenantConfig(ctx context.Context, req gen.ExportTenantConfigRequestObject) (gen.ExportTenantConfigResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	tid := tenant.ID(req.TenantId)
	out, err := svc.ExportConfig(ctx, p, tid, deref(req.Params.IncludeBranding), middleware.ClientIP(ctx))
	if err != nil {
		return nil, tenantError(err)
	}
	// The FQDN names the file; the access was checked by the export.
	v, err := svc.GetTenant(ctx, p, tid)
	if err != nil {
		return nil, tenantError(err)
	}
	return configExportResponse{body: out, fileName: exportFileName(v.FQDN)}, nil
}

// exportFileName returns the name of the export file of the tenant fqdn.
// An FQDN holds only letters, digits, dots and hyphens; anything else is
// replaced so that the name never needs quoting.
func exportFileName(fqdn string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, fqdn)
	return "tenant-" + safe + "-config.json"
}

// configExportResponse renders a tenantadmin.ConfigExport, whose JSON
// members are those of the OpenAPI TenantConfigExport, as the 200 answer of
// exportTenantConfig: a JSON attachment never stored by a cache.
type configExportResponse struct {
	body     tenantadmin.ConfigExport
	fileName string
}

// VisitExportTenantConfigResponse implements
// gen.ExportTenantConfigResponseObject, as the generated 200 response does.
func (r configExportResponse) VisitExportTenantConfigResponse(w http.ResponseWriter) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(r.body); err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Disposition", `attachment; filename="`+r.fileName+`"`)
	w.WriteHeader(http.StatusOK)
	_, err := buf.WriteTo(w)
	return err
}

// --- Import --------------------------------------------------------------------

// importBody is the body of importTenant (OpenAPI TenantImport), decoded
// after the strict check of its raw form.
type importBody struct {
	Name              string                   `json:"name"`
	FQDN              string                   `json:"fqdn"`
	StorageQuotaBytes int64                    `json:"storageQuotaBytes"`
	Config            tenantadmin.ConfigExport `json:"config"`
	DelegatedAdmin    *gen.NewDelegatedAdmin   `json:"delegatedAdmin"`
}

// ImportTenant creates a tenant in the setup state from an exported
// configuration (super admin, 201). The checks run in this order, so that
// each refusal tells nothing to whom may not know it, and so that no
// unbounded allocation happens before the document is known to be bounded:
//
//  1. the role, by the HTTP server before the body is read (route policy
//     superAdminOnly): another admin gets 403 forbidden, an auditor 403
//     read-only-role, whatever the body; checked again here (defense in
//     depth);
//  2. the body limit (32 MiB, 413) and the JSON media type (415);
//  3. by CaptureRawBody, on the raw body and before the generated handler
//     decodes it (CheckImportBody): the schemaVersion, read before
//     anything else of the document (a document of another version, which
//     may hold members unknown here, is 422 import-schema-unsupported; a
//     value that is not an integer is 422 import-invalid), then the strict
//     check (strictjson): duplicate member, member outside the schema,
//     missing required member, value of the wrong shape, array longer than
//     its limit, nesting deeper than 32: 422 import-invalid with the JSON
//     pointer of the first problem;
//  4. the decoding of the generated handler: a scalar of the wrong type (a
//     string for a number...) is 400 validation-failed;
//  5. here, the strict decoding of the raw body again, then the validators
//     of the manual entry in the service (422 import-invalid with the
//     pointer of the first problem).
//
// A field error carries the pointer and a code, never the value. The body
// decoded by the generated handler is not used (it accepted duplicate and
// unknown members): the raw body kept by CaptureRawBody is decoded again,
// strictly.
func (s *Server) ImportTenant(ctx context.Context, _ gen.ImportTenantRequestObject) (gen.ImportTenantResponseObject, error) {
	svc, p, err := s.tenantSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := requireSuperAdmin(p); err != nil {
		return nil, serviceError(err)
	}
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	if !ok {
		return nil, errNoImportBody
	}
	in, err := decodeImport(raw)
	if err != nil {
		return nil, err
	}
	created, err := svc.ImportTenant(ctx, p, in, middleware.ClientIP(ctx))
	if err != nil {
		return nil, importTenantError(err)
	}
	return gen.ImportTenant201JSONResponse(tenantCreatedBody(created)), nil
}

// decodeImport checks (CheckImportBody) and decodes the raw body of an
// import, returning the input of the service or the Problem to answer.
func decodeImport(raw []byte) (tenantadmin.ImportInput, error) {
	if err := CheckImportBody(raw); err != nil {
		return tenantadmin.ImportInput{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b importBody
	if err := dec.Decode(&b); err != nil {
		// The strict check accepted the shape: only a scalar of the wrong
		// type (a string for a number...) is left.
		return tenantadmin.ImportInput{}, importInvalid(decodePointer(err), string(strictjson.ReasonType))
	}
	// The one-time secrets settings (since 2.1) are not imported until the
	// module is implemented: refused rather than silently ignored.
	if b.Config.SecretSettings != nil {
		return tenantadmin.ImportInput{}, validationFailed("/config/secretSettings", fieldNotSupported)
	}
	in := tenantadmin.ImportInput{Name: b.Name, FQDN: b.FQDN, StorageQuotaBytes: b.StorageQuotaBytes, Config: b.Config}
	if d := b.DelegatedAdmin; d != nil {
		// A new tenant has no single sign-on yet: as for createTenant, its
		// first delegated admin cannot be created without activation link.
		if d.Delivery != nil && *d.Delivery == gen.InvitationDeliveryNone {
			return tenantadmin.ImportInput{}, validationFailed(delegatedAdminField+"/delivery", fieldNotSupported)
		}
		in.DelegatedAdmin = &adminauth.DelegatedAdmin{Username: d.Username, Email: string(d.Email), Language: string(d.Language)}
		if d.Delivery != nil {
			in.DelegatedAdmin.Delivery = store.ActivationDelivery(*d.Delivery)
		}
	}
	return in, nil
}

// CheckImportBody runs the checks of the raw body of an import that need
// no typed decode, in this order: the schemaVersion (checkSchemaVersion),
// then the strict check against importSchema, whose array limits bound
// what a typed decode can allocate. It returns nil or the 422 Problem to
// answer. CaptureRawBody runs it before the generated handler decodes the
// body; decodeImport runs it again.
func CheckImportBody(raw []byte) error {
	if err := checkSchemaVersion(raw); err != nil {
		return err
	}
	if err := strictjson.Check(raw, importSchema, importMaxDepth); err != nil {
		// Check reports every problem as an *strictjson.Error.
		var se *strictjson.Error
		_ = errors.As(err, &se)
		return importInvalid(se.Pointer, string(se.Reason))
	}
	return nil
}

// checkSchemaVersion reads config.schemaVersion alone: absent or null, it
// is 422 import-invalid at its pointer (code required); a value that is
// not an integer (true, "1", 1.0...) is 422 import-invalid at its pointer
// (code type); an integer other than the one this server reads is 422
// import-schema-unsupported, whatever the rest of the document holds. A
// body that is not an object with an object config is left to the strict
// check, which locates the problem. The read skips every other member
// without keeping it, so it allocates little whatever the body.
func checkSchemaVersion(raw []byte) error {
	var head struct {
		Config *struct {
			SchemaVersion json.RawMessage `json:"schemaVersion"`
		} `json:"config"`
	}
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' || json.Unmarshal(raw, &head) != nil {
		return nil
	}
	at := strictjson.Pointer("config", "schemaVersion")
	if head.Config == nil {
		return importInvalid(strictjson.Pointer("config"), fieldRequired)
	}
	v := bytes.TrimSpace(head.Config.SchemaVersion)
	switch {
	case len(v) == 0 || bytes.Equal(v, []byte("null")):
		return importInvalid(at, fieldRequired)
	case !isJSONInteger(v):
		return importInvalid(at, string(strictjson.ReasonType))
	case string(v) != strconv.Itoa(tenantadmin.ConfigSchemaVersion):
		return problem.New(problem.CodeImportSchemaUnsupported)
	}
	return nil
}

// isJSONInteger reports whether v, a valid JSON value, is a number written
// as an integer: an optional minus sign and digits only (no fraction nor
// exponent).
func isJSONInteger(v []byte) bool {
	if len(v) > 0 && v[0] == '-' {
		v = v[1:]
	}
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// decodePointer returns the JSON pointer of the member a decoding error
// names, "" when it names none. encoding/json gives a dotted path without
// the array indexes: the pointer then names the array.
func decodePointer(err error) string {
	var te *json.UnmarshalTypeError
	if !errors.As(err, &te) || te.Field == "" {
		return ""
	}
	return strictjson.Pointer(stringsToAny(strings.Split(te.Field, "."))...)
}

// stringsToAny converts a []string to a []any.
func stringsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// importInvalid returns the 422 import-invalid Problem whose only field
// error is at pointer with code.
func importInvalid(pointer, code string) *problem.Problem {
	return problem.New(problem.CodeImportInvalid, problem.WithFieldErrors(problem.FieldError{Field: pointer, Code: code}))
}

// importTenantError maps an error of the import to the declared answers of
// importTenant: 422 for the document, 400 for the delegated admin and an
// admin host FQDN (as createTenant), 409 for an FQDN or a username already
// used, 401 and 403 for the session. Anything else is a 500 whose cause is
// logged.
func importTenantError(err error) error {
	var (
		ie        *tenantadmin.ImportError
		invalid   *tenantadmin.InvalidError
		authInval *adminauth.InvalidError
	)
	switch {
	case errors.Is(err, tenantadmin.ErrImportSchemaUnsupported):
		return problem.New(problem.CodeImportSchemaUnsupported)
	case errors.As(err, &ie):
		if ie.Code == tenantadmin.CodeAdminHost {
			// Same answer as createTenant for an admin host.
			return validationFailed(ie.Pointer, ie.Code)
		}
		code := ie.Code
		if code == "" {
			code = fieldInvalidValue
		}
		return importInvalid(ie.Pointer, code)
	case errors.Is(err, tenantadmin.ErrImportInvalid):
		return importInvalid("", fieldInvalidValue)
	case errors.Is(err, tenantadmin.ErrAlreadyExists), errors.Is(err, adminauth.ErrAlreadyExists):
		return problem.New(problem.CodeAlreadyExists)
	case errors.As(err, &authInval):
		return validationFailed(delegatedAdminField+authInval.Field, formatCode(authInval.Field == adminauth.FieldEmail))
	case errors.Is(err, adminauth.ErrSystemSMTPUnavailable):
		// Same answer as createTenant: 503 system-smtp-unavailable.
		return problem.New(problem.CodeSystemSMTPUnavailable)
	case errors.As(err, &invalid):
		return invalidProblem(invalid)
	case errors.Is(err, adminauth.ErrInvalid), errors.Is(err, tenantadmin.ErrInvalid):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, adminauth.ErrUnauthenticated), errors.Is(err, tenantadmin.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, adminauth.ErrForbidden), errors.Is(err, tenantadmin.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	default:
		return err
	}
}

// Item limits of the arrays of an import body (strictjson Max), each the
// limit of the manual entry of its section, so that the strict check
// refuses an oversized array before any typed decode allocates it (T-306).
// A test checks they equal the maxItems of api/openapi.yaml.
var (
	importMaxTemplates      = len(store.EmailTemplateKeys()) * len(tenant.Languages())
	importMaxLegalDocuments = len([]string{store.LegalNotice, store.PrivacyPolicy}) * len(tenant.Languages())
	importMaxExpiryDays     = len(store.ExpiryDaysOfMask(store.ExpiryMaskAll))
	importMaxWebhookEvents  = len(events.TenantTypes())
	// importMaxSecretDurations is the number of duration codes of a secret.
	importMaxSecretDurations = 6
)

// importDaysPerWeek bounds the weekdays of the office hours.
const importDaysPerWeek = 7

// importSchema is the whitelist tree of an import body (OpenAPI
// TenantImport with TenantConfigExport and NewDelegatedAdmin): every
// object member allowed and the required ones, the objects and arrays that
// may be null, the item limit of every array. A test checks it equals the
// schemas of api/openapi.yaml, so that it cannot drift from the contract.
var importSchema = func() *strictjson.Schema {
	s := strictjson.Scalar
	obj := strictjson.Object
	arr := func(item *strictjson.Schema, maxItems int) *strictjson.Schema {
		return strictjson.Array(item).Max(maxItems)
	}
	scalars := func(names ...string) map[string]*strictjson.Schema {
		m := make(map[string]*strictjson.Schema, len(names))
		for _, n := range names {
			m[n] = s()
		}
		return m
	}
	with := func(m map[string]*strictjson.Schema, extra map[string]*strictjson.Schema) map[string]*strictjson.Schema {
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// strict returns an object whose members are all required.
	strict := func(m map[string]*strictjson.Schema) *strictjson.Schema {
		o := obj(m)
		return o.Require(o.MemberNames()...)
	}
	// A map keyed by the interface languages (labels, descriptions).
	byLanguage := obj(scalars(tenant.Languages()...))
	asset := strict(scalars("mediaType", "dataBase64"))
	ruleList := func(maxItems int) *strictjson.Schema { return arr(s(), maxItems) }
	levelRules := obj(with(scalars("requireRecipientVerification", "requirePassword", "internalRecipientsOnly",
		"forceDeleteAfterFirstDownload", "maxDownloads", "e2ePolicy", "linkOnlyAllowed"), map[string]*strictjson.Schema{
		"allowedExpiryDays": arr(s(), importMaxExpiryDays),
	})).Require("requireRecipientVerification", "requirePassword", "allowedExpiryDays", "internalRecipientsOnly",
		"forceDeleteAfterFirstDownload", "maxDownloads")
	level := obj(with(scalars("key", "isDefault"), map[string]*strictjson.Schema{
		"labels": byLanguage, "descriptions": byLanguage, "rules": levelRules,
	})).Require("key", "labels", "isDefault", "rules")
	config := obj(with(scalars("schemaVersion", "exportedAt", "sourceVersion"), map[string]*strictjson.Schema{
		"settings": obj(scalars("defaultLanguage", "maxTransferBytes", "maxTransferCeiling", "allowRemoteInternalDeposit",
			"allowTransferReply", "webhookIncludeAddresses", "linkOnlyAllowed", "e2ePolicy")),
		"branding": obj(with(scalars("primaryColor", "accentColor", "backgroundPreset"), map[string]*strictjson.Schema{
			"logo": asset, "background": asset,
		})),
		"network": strict(map[string]*strictjson.Schema{
			"internalCidrs":   ruleList(tenantadmin.MaxInternalCIDRs),
			"internalDomains": ruleList(tenantadmin.MaxInternalDomains),
		}),
		"smtp": obj(scalars("host", "port", "security", "fromAddress", "fromName")).
			Require("host", "port", "security", "fromAddress"),
		"recipientRules": strict(map[string]*strictjson.Schema{
			"allowedDomains": ruleList(store.MaxRecipientRules), "deniedDomains": ruleList(store.MaxRecipientRules),
		}),
		"confidentialityLevels": strict(map[string]*strictjson.Schema{"items": arr(level, store.MaxConfidentialityLevels)}),
		// Every member is required, as for the manual entry
		// (checkThresholdMembers).
		"abuseThresholds": strict(with(scalars("maxDailyBytesPerSender", "maxDailyTransfersPerSender", "maxRecipientsPerTransfer",
			"blockOnExceed", "unusualVolumeFactor", "unusualMinHistoryDays", "largeExternalTransferBytes", "timeZone",
			"maxInvitationsPerInviter", "externalMaxDailyBytes", "externalMaxDailyDeposits"), map[string]*strictjson.Schema{
			"officeHours": strict(with(scalars("start", "end"), map[string]*strictjson.Schema{
				"weekdays": arr(s(), importDaysPerWeek),
			})).OrNull(),
		})),
		// Since 2.1: decoded, then refused with not-supported until the module
		// is implemented (decodeImport).
		"secretSettings": obj(with(scalars("enabled", "defaultDuration", "fileAllowed", "fileMaxBytes", "emailAllowed"), map[string]*strictjson.Schema{
			"durations": arr(s(), importMaxSecretDurations),
		})).Require("enabled", "durations", "fileAllowed", "fileMaxBytes", "emailAllowed"),
		"emailTemplates": arr(strict(scalars("key", "language", "subject", "bodyHtml", "bodyText")), importMaxTemplates),
		"legalDocuments": arr(strict(scalars("document", "language", "markdown")), importMaxLegalDocuments),
		"webhooks": arr(strict(with(scalars("name", "kind", "enabled"), map[string]*strictjson.Schema{
			"events": arr(s(), importMaxWebhookEvents),
		})), store.MaxWebhooks),
		"blocklist": arr(obj(scalars("kind", "value", "comment")).Require("kind", "value"), tenantadmin.MaxImportBlocklistEntries),
	})).Require("schemaVersion", "exportedAt", "sourceVersion")
	return obj(with(scalars("name", "fqdn", "storageQuotaBytes"), map[string]*strictjson.Schema{
		"config":         config,
		"delegatedAdmin": obj(scalars("username", "email", "language", "delivery")).Require("username", "email", "language"),
	})).Require("name", "fqdn", "storageQuotaBytes", "config")
}()
