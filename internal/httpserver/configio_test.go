package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/api/stubs"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
)

// importStub answers importTenant 404 after the body was decoded by the
// generated handler, like a stub.
type importStub struct{ stubTenantAdmin }

func (importStub) ImportTenant(context.Context, gen.ImportTenantRequestObject) (gen.ImportTenantResponseObject, error) {
	return nil, stubs.ErrNotImplemented
}

// minimalImport is the smallest import body the strict check accepts.
const minimalImport = `{"name":"Entity C","fqdn":"transfer.entity-c.example.com","storageQuotaBytes":1,` +
	`"config":{"schemaVersion":1,"exportedAt":"2026-11-04T10:00:00Z","sourceVersion":"2.0.0"}}`

// TestImportBodyLimit checks the 32 MiB body limit of the tenant import
// (since API 2.0): above the JSON limit but within it, the request reaches
// the handler; beyond, 413 payload-too-large, announced or chunked. The
// admin CSRF checks apply.
func TestImportBodyLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{adminSessions: fakeAdminSessions{}, adminAPI: importStub{stubTenantAdmin{admin.NewServer()}}})
	const path = "/api/v1/admin/tenants/import"
	hdr := append(adminAuth(), "Content-Type", "application/json")
	body := func(n int64) io.Reader {
		return strings.NewReader(strings.Repeat(" ", int(n)-len(minimalImport)) + minimalImport)
	}
	rec := e.do(t, http.MethodPost, path, hostAdmin, body(middleware.DefaultJSONBodyLimit+1), hdr...)
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	rec = e.do(t, http.MethodPost, path, hostAdmin, body(admin.ImportBodyLimit), hdr...)
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	rec = e.do(t, http.MethodPost, path, hostAdmin, body(admin.ImportBodyLimit+1), hdr...)
	decodeProblem(t, rec, http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge)
	rec = e.do(t, http.MethodPost, path, hostAdmin, io.MultiReader(body(admin.ImportBodyLimit), strings.NewReader(" ")), hdr...)
	decodeProblem(t, rec, http.StatusRequestEntityTooLarge, problem.CodePayloadTooLarge)
	// Without the CSRF token: refused before the handler.
	rec = e.do(t, http.MethodPost, path, hostAdmin, strings.NewReader("{}"),
		"Cookie", middleware.AdminCookie+"="+adminGoodToken, "Origin", "https://"+hostAdmin, "Sec-Fetch-Site", "same-origin",
		"Content-Type", "application/json")
	decodeProblem(t, rec, http.StatusForbidden, problem.CodeCSRFInvalid)
	// The strict check runs before the generated decoder: the stub is not
	// reached, the Problem carries the pointer.
	rec = e.do(t, http.MethodPost, path, hostAdmin, strings.NewReader(`{"name":"x","config":{"schemaVersion":1}}`), hdr...)
	p := decodeProblem(t, rec, http.StatusUnprocessableEntity, problem.CodeImportInvalid)
	if len(p.Errors) != 1 || p.Errors[0].Field != "/config/exportedAt" || p.Errors[0].Code != "required" {
		t.Errorf("errors %+v", p.Errors)
	}
}

// readRecorder is a request body that records whether it was read.
type readRecorder struct {
	r    io.Reader
	read atomic.Bool
}

// Read implements io.Reader.
func (b *readRecorder) Read(p []byte) (int, error) {
	b.read.Store(true)
	return b.r.Read(p)
}

// hostileImport returns an import body of about 32 MiB whose
// confidentiality levels are hundreds of thousands of items (item, an
// object): decoded into the generated types, such a body allocated
// gigabytes.
func hostileImport(item string) string {
	head := `{"name":"x","fqdn":"a.example.com","storageQuotaBytes":1,"config":{"schemaVersion":1,"confidentialityLevels":{"items":[` + item
	tail := `]}}}`
	n := (int(admin.ImportBodyLimit) - len(head) - len(tail)) / (len(item) + 1)
	return head + strings.Repeat(","+item, n) + tail
}

// validLevel is a confidentiality level the strict check accepts.
const validLevel = `{"key":"a","labels":{},"isDefault":false,"rules":{"requireRecipientVerification":false,` +
	`"requirePassword":false,"allowedExpiryDays":[1],"internalRecipientsOnly":false,` +
	`"forceDeleteAfterFirstDownload":false,"maxDownloads":null}}`

// TestImportRoleBeforeBody checks that the import is refused to any other
// admin than the super admin before its body is read, with the answers of
// the handler: 403 forbidden for a delegated admin, 403 read-only-role for
// an auditor, 401 for a session awaiting its TOTP code.
func TestImportRoleBeforeBody(t *testing.T) {
	t.Parallel()
	e := newEnv(t, envConfig{adminSessions: fakeAdminSessions{}, adminAPI: importStub{stubTenantAdmin{admin.NewServer()}}})
	const path = "/api/v1/admin/tenants/import"
	big := hostileImport("{}")
	for _, tt := range []struct {
		token  string
		status int
		code   problem.Code
	}{
		{adminDelegatedToken, http.StatusForbidden, problem.CodeForbidden},
		{adminAuditorToken, http.StatusForbidden, problem.CodeReadOnlyRole},
		{adminPendingToken, http.StatusUnauthorized, problem.CodeUnauthenticated},
		{adminAuditorPendingToken, http.StatusUnauthorized, problem.CodeUnauthenticated},
	} {
		body := &readRecorder{r: strings.NewReader(big)}
		rec := e.do(t, http.MethodPost, path, hostAdmin, body,
			"Cookie", middleware.AdminCookie+"="+tt.token, middleware.HeaderCSRFToken, adminCSRF,
			"Origin", "https://"+hostAdmin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json")
		decodeProblem(t, rec, tt.status, tt.code)
		if body.read.Load() {
			t.Errorf("%s: body read", tt.token)
		}
	}
	// Another operation is not concerned by the guard.
	if superAdminGuardPassThrough(t) {
		t.Error("guard applied outside its routes")
	}
	// The super admin's body is read, and refused by the strict check.
	body := &readRecorder{r: strings.NewReader(minimalImport)}
	rec := e.do(t, http.MethodPost, path, hostAdmin, body, append(adminAuth(), "Content-Type", "application/json")...)
	decodeProblem(t, rec, http.StatusNotFound, problem.CodeNotFound)
	if !body.read.Load() {
		t.Error("super admin body not read")
	}
}

// superAdminGuardPassThrough reports whether superAdminGuard refused a
// request on a route without the superAdminOnly policy (it must not).
func superAdminGuardPassThrough(t *testing.T) bool {
	t.Helper()
	reached := false
	h := superAdminGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tenants", nil)
	req.Pattern = http.MethodGet + " " + APIBaseURL + "/admin/tenants"
	h.ServeHTTP(httptest.NewRecorder(), req)
	return !reached
}

// TestImportHostileBodyBounded checks that a super admin importing a
// hostile document (32 MiB of array items) gets 422 at the first problem
// quickly (too-many at the array for valid items, required for empty
// ones), without the gigabytes a typed decode of it allocated. Not
// parallel, so that the allocation count is that of these requests.
func TestImportHostileBodyBounded(t *testing.T) {
	e := newEnv(t, envConfig{adminSessions: fakeAdminSessions{}, adminAPI: importStub{stubTenantAdmin{admin.NewServer()}}})
	for item, want := range map[string]problem.FieldError{
		validLevel: {Field: "/config/confidentialityLevels/items", Code: "too-many"},
		"{}":       {Field: "/config/confidentialityLevels/items/0/key", Code: "required"},
	} {
		big := hostileImport(item)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		rec := e.do(t, http.MethodPost, "/api/v1/admin/tenants/import", hostAdmin, strings.NewReader(big),
			append(adminAuth(), "Content-Type", "application/json")...)
		runtime.ReadMemStats(&after)
		p := decodeProblem(t, rec, http.StatusUnprocessableEntity, problem.CodeImportInvalid)
		if len(p.Errors) != 1 || p.Errors[0].Field != want.Field || p.Errors[0].Code != want.Code {
			t.Errorf("errors %+v, want %+v", p.Errors, want)
		}
		// The raw body is read once (32 MiB, with the growth of its
		// buffer); nothing proportional to the number of items is
		// allocated.
		const bound = 200 << 20
		if d := after.TotalAlloc - before.TotalAlloc; d > bound {
			t.Errorf("allocated %d MiB, want below %d MiB", d>>20, bound>>20)
		}
	}
}
