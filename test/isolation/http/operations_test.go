// Package httpisolation_test is the per-endpoint tenant isolation harness
// of the HTTP API (CLAUDE.md sections 5 and 24.2, threat model T-01 and
// section 9).
//
// It parses api/openapi.yaml, enumerates every operation and runs it
// against a real server (app.Run, real database on every engine of
// storetest.Engines) holding two tenants, A and B:
//
//   - an operation listed in isolationCases runs its case, which must show
//     that a resource of tenant A requested under tenant B's Host is never
//     served (404, never data), or document why the operation is
//     tenant-agnostic;
//   - any other operation must still be a stub: the implementations used by
//     the server (public.NewServer on tenant hosts, admin.NewServer on the
//     admin host) behave exactly like stubs.Unimplemented, and the server
//     answers 404 under both hosts.
//
// The administration operations are served on the admin host only
// (admin_test.go): under tenant A's and tenant B's hosts they answer 404
// before any admin logic, and on the admin host the tenant operations
// answer 404.
//
// Implementing an operation without adding its isolation case therefore
// makes this test fail, as does a case for an operation that no longer
// exists in the specification.
package httpisolation_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/api"
	"github.com/ed-fr/transteira/internal/api/admin"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/public"
	"github.com/ed-fr/transteira/internal/api/stubs"
	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Fictitious tenants (CLAUDE.md section 24.2: *.localhost).
const (
	hostA = "transfer.entity-a.localhost"
	hostB = "transfer.entity-b.localhost"
	nameA = "Entity A Isolation"
	nameB = "Entity B Isolation"
)

// waitTimeout bounds start-up, shutdown and each request.
const waitTimeout = 60 * time.Second

// isolationCase checks one operation for cross-tenant leaks.
type isolationCase func(t *testing.T, h *harness, op operation)

// isolationCases maps every operation that is implemented (or served
// outside the generated API) to its isolation case. Add an entry whenever
// an operation stops being a stub.
var isolationCases = map[string]isolationCase{
	// Tenant-scoped route, but its answer carries no tenant data at all: the
	// same instance version is returned under every tenant. The case asserts
	// identical bodies under A and B and no identifier, name or host of
	// either tenant.
	"getVersion": sameAnswerWithoutTenantData,
	// Served at /healthz outside any tenant (CLAUDE.md section 19): the same
	// health report is returned whatever the Host, even unknown.
	"getHealth": tenantAgnostic,
	// Served at /api/openapi.yaml outside any tenant: the same document is
	// returned whatever the Host, even unknown.
	"getOpenApiSpec": tenantAgnostic,
	// Deposit sessions and invitations (deposit_test.go): a session cookie,
	// a challenge identifier or an invitation token of tenant A is refused
	// under tenant B's Host (401, 403 or 404), while tenant A recognizes it.
	"startDepositSession":          startWithForeignInvitation,
	"confirmVerificationChallenge": confirmForeignChallenge,
	"getCurrentDepositSession":     currentWithForeignSession,
	"endDepositSession":            endWithForeignSession,
	"createInvitation":             inviteWithForeignSession,
	"getInvitation":                getForeignInvitation,
	// Transfers and tus uploads (transfer_test.go): a transfer or upload of
	// tenant A's owner is never reached by another sender of A nor, under
	// B's Host, by a sender of B (404), while its owner reaches it. The tus
	// capabilities carry no tenant data.
	"createTransfer":     createWithForeignSession,
	"getTransfer":        getForeignTransfer,
	"cancelTransfer":     cancelForeignTransfer,
	"finalizeTransfer":   finalizeForeignTransfer,
	"getTusCapabilities": tusCapabilities,
	"getUploadOffset":    headForeignUpload,
	"appendUploadChunk":  patchForeignUpload,
	"terminateUpload":    terminateForeignUpload,
	// Downloads (download_test.go): tenant A's link token, with A's grant
	// cookie, under B's Host is unknown (404); unlock attempts under B
	// never count against A's transfer.
	"getDownload":     getForeignDownload,
	"unlockDownload":  unlockForeignDownload,
	"downloadFile":    fileOfForeignDownload,
	"downloadArchive": archiveOfForeignDownload,
	// Administration (admin_test.go): served on the admin host only, where
	// no tenant is resolved; under tenant A's and B's hosts every one
	// answers 404 before any admin logic. The cross-tenant checks of the
	// admin operations themselves (a delegated admin of A never reaching
	// B) are in TestAdminHostIsolation.
	"getSetupStatus":        adminHostOnly,
	"createSuperAdmin":      adminHostOnly,
	"adminLogin":            adminHostOnly,
	"adminVerifyTotp":       adminHostOnly,
	"adminLogout":           adminHostOnly,
	"getAdminMe":            adminHostOnly,
	"changeAdminPassword":   adminHostOnly,
	"startTotpEnrollment":   adminHostOnly,
	"disableTotp":           adminHostOnly,
	"confirmTotpEnrollment": adminHostOnly,
	"listAdmins":            adminHostOnly,
	"createAdmin":           adminHostOnly,
	"getAdmin":              adminHostOnly,
	"updateAdmin":           adminHostOnly,
	"deleteAdmin":           adminHostOnly,
	"resetAdminCredentials": adminHostOnly,
	"activateAdmin":         adminHostOnly,
	// Tenant configuration (tenantconfig_test.go): served on the admin host
	// only, like every administration operation; the delegated admin of
	// tenant A, sending each operation for tenant B's ID, gets exactly the
	// answer of an unknown tenant ID (404, or 403 for a super admin
	// operation) and never data of B.
	"listTenants":           adminTenantOp,
	"createTenant":          adminTenantOp,
	"getTenant":             adminTenantOp,
	"updateTenant":          adminTenantOp,
	"deleteTenant":          adminTenantOp,
	"getBranding":           adminTenantOp,
	"updateBranding":        adminTenantOp,
	"uploadBrandingAsset":   adminTenantOp,
	"deleteBrandingAsset":   adminTenantOp,
	"getNetworkRules":       adminTenantOp,
	"updateNetworkRules":    adminTenantOp,
	"getSmtpSettings":       adminTenantOp,
	"updateSmtpSettings":    adminTenantOp,
	"testSmtp":              adminTenantOp,
	"checkMailDns":          adminTenantOp,
	"listEmailTemplates":    adminTenantOp,
	"getEmailTemplate":      adminTenantOp,
	"updateEmailTemplate":   adminTenantOp,
	"resetEmailTemplate":    adminTenantOp,
	"previewEmailTemplate":  adminTenantOp,
	"getLegalDocumentAdmin": adminTenantOp,
	"updateLegalDocument":   adminTenantOp,
	// Public configuration of the tenant (tenantconfig_test.go): under each
	// tenant host, the name, branding, logo and legal documents of that
	// tenant only.
	"getPublicTenant":        publicTenantConfig,
	"getTenantAsset":         tenantAssets,
	"getTenantLegalDocument": tenantLegal,
	// Operations of a tenant (tenantops_test.go): served on the admin host
	// only; the delegated admin of tenant A gets for tenant B's ID exactly
	// the answer of an unknown tenant ID, and, under A's own path, for a
	// transfer, invitation or blocklist entry of B exactly the answer of an
	// unknown one; its lists, audit log, statistics and data subject
	// searches and erasures never count, show or touch data of B.
	"listTenantTransfers":        adminOperation,
	"getTenantTransfer":          adminOperation,
	"deleteTenantTransfer":       adminOperation,
	"resendTransferNotification": adminOperation,
	"listTenantInvitations":      adminOperation,
	"revokeInvitation":           adminOperation,
	"listBlocklist":              adminOperation,
	"createBlocklistEntry":       adminOperation,
	"deleteBlocklistEntry":       adminOperation,
	"listTenantAuditEvents":      adminOperation,
	"getTenantStats":             adminOperation,
	"searchDataSubject":          adminOperation,
	"eraseDataSubject":           adminOperation,
	// Instance-wide operations (tenantops_test.go): reserved to the super
	// admin, 403 forbidden for a delegated admin, without data of any
	// tenant.
	"listGlobalAuditEvents": superAdminOperation,
	"getGlobalStats":        superAdminOperation,
	// API tokens (apitokens_test.go): served on the admin host only; the
	// delegated admin of tenant A gets for tenant B's ID exactly the answer
	// of an unknown tenant ID, and, under A's own path, for a token of B
	// exactly the answer of an unknown token; B's token is never listed,
	// renamed nor revoked, and A's new token is never listed for B.
	"listApiTokens":  adminAPIToken,
	"createApiToken": adminAPIToken,
	"updateApiToken": adminAPIToken,
	"revokeApiToken": adminAPIToken,
	// System operations (system_test.go): instance-wide, served on the
	// admin host only. The maintenance state holds no tenant data and is
	// readable by every administrator; the other operations are reserved
	// to the super admin (403 forbidden for tenant A's delegated admin,
	// even with a valid body) and answer no tenant data.
	"getMaintenance":         readMaintenance,
	"setMaintenance":         systemOperation,
	"getSystemSettings":      systemOperation,
	"updateSystemSettings":   systemOperation,
	"startMasterKeyRotation": systemOperation,
	"getMasterKeyRotation":   systemOperation,
	"getMasterKeyStatus":     systemOperation,
}

// TestEveryOperationIsIsolatedOrStub is the harness itself.
func TestEveryOperationIsIsolatedOrStub(t *testing.T) {
	ops := loadOperations(t)

	t.Run("cases reference existing operations", func(t *testing.T) {
		known := map[string]bool{}
		for _, op := range ops {
			known[op.id] = true
		}
		for id := range isolationCases {
			if !known[id] {
				t.Errorf("isolationCases has a stale entry %q: no such operation in api/openapi.yaml", id)
			}
		}
	})

	t.Run("stub detector tells implemented operations apart", func(t *testing.T) {
		for _, op := range ops {
			switch op.id {
			case "getVersion", "getSetupStatus", "adminLogin": // implemented by public.Server or admin.Server
				if isStub(t, op) {
					t.Errorf("isStub(%s) = true, want false: the detector would let implementations through", op.id)
				}
			case "getHealth", "getOpenApiSpec": // served before routing, stubs in the generated interface
				if !isStub(t, op) {
					t.Errorf("isStub(%s) = false, want true", op.id)
				}
			}
		}
	})

	t.Run("specification and generated interface agree", func(t *testing.T) {
		iface := reflect.TypeFor[gen.StrictServerInterface]()
		if iface.NumMethod() != len(ops) {
			t.Errorf("gen.StrictServerInterface has %d methods, api/openapi.yaml %d operations: run make generate",
				iface.NumMethod(), len(ops))
		}
		for _, op := range ops {
			if _, ok := iface.MethodByName(op.method()); !ok {
				t.Errorf("operation %s has no method %s in gen.StrictServerInterface", op.id, op.method())
			}
		}
	})

	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		h := startHarness(t, e)
		var implemented, stubbed []string
		for _, op := range ops {
			t.Run(op.id, func(t *testing.T) {
				if c, ok := isolationCases[op.id]; ok {
					implemented = append(implemented, op.id)
					c(t, h, op)
					return
				}
				stubbed = append(stubbed, op.id)
				if !isStub(t, op) {
					t.Fatalf("operation %s is implemented but has no isolation case: add one to isolationCases "+
						"proving that tenant A's resources are never served under tenant B's host", op.id)
				}
				stillStub(t, h, op)
			})
		}
		sort.Strings(implemented)
		t.Logf("%d operations: %d with an isolation case %v, %d not implemented yet (stubs answering 404)",
			len(ops), len(implemented), implemented, len(stubbed))
	})
}

// --- Specification -------------------------------------------------------

// operation is one operation of the specification.
type operation struct {
	id       string
	verb     string // HTTP method
	template string // path template, e.g. /transfers/{transferId}
	base     string // server URL prefix, e.g. /api/v1
	params   []param
	body     *requestBody
}

func (op operation) method() string { return strings.ToUpper(op.id[:1]) + op.id[1:] }

func (op operation) String() string { return op.verb + " " + op.base + op.template }

type specDoc struct {
	Servers    []serverObj         `yaml:"servers"`
	Paths      map[string]pathItem `yaml:"paths"`
	Components struct {
		Parameters map[string]param `yaml:"parameters"`
	} `yaml:"components"`
}

type serverObj struct {
	URL string `yaml:"url"`
}

type pathItem struct {
	Servers    []serverObj `yaml:"servers"`
	Parameters []param     `yaml:"parameters"`
	Get        *opObj      `yaml:"get"`
	Put        *opObj      `yaml:"put"`
	Post       *opObj      `yaml:"post"`
	Delete     *opObj      `yaml:"delete"`
	Options    *opObj      `yaml:"options"`
	Head       *opObj      `yaml:"head"`
	Patch      *opObj      `yaml:"patch"`
	Trace      *opObj      `yaml:"trace"`
}

type opObj struct {
	OperationID string       `yaml:"operationId"`
	Servers     []serverObj  `yaml:"servers"`
	Parameters  []param      `yaml:"parameters"`
	RequestBody *requestBody `yaml:"requestBody"`
}

type param struct {
	Ref      string `yaml:"$ref"`
	Name     string `yaml:"name"`
	In       string `yaml:"in"`
	Required bool   `yaml:"required"`
	Example  any    `yaml:"example"`
	Schema   struct {
		Example any   `yaml:"example"`
		Enum    []any `yaml:"enum"`
		Default any   `yaml:"default"`
	} `yaml:"schema"`
}

type requestBody struct {
	Required bool           `yaml:"required"`
	Content  map[string]any `yaml:"content"`
}

// sample returns a value for the parameter: its example, else the schema
// example, first enumerated value or default.
func (p param) sample() string {
	for _, v := range []any{p.Example, p.Schema.Example} {
		if v != nil {
			return fmt.Sprint(v)
		}
	}
	if len(p.Schema.Enum) > 0 {
		return fmt.Sprint(p.Schema.Enum[0])
	}
	if p.Schema.Default != nil {
		return fmt.Sprint(p.Schema.Default)
	}
	return "x"
}

// loadOperations parses the embedded specification (the one the server
// serves) and returns every operation, sorted by operationId.
func loadOperations(t *testing.T) []operation {
	t.Helper()
	var doc specDoc
	if err := yaml.Unmarshal(api.OpenAPISpec, &doc); err != nil {
		t.Fatalf("parse api/openapi.yaml: %v", err)
	}
	resolve := func(ps []param) []param {
		out := make([]param, 0, len(ps))
		for _, p := range ps {
			if p.Ref != "" {
				name := strings.TrimPrefix(p.Ref, "#/components/parameters/")
				rp, ok := doc.Components.Parameters[name]
				if !ok {
					t.Fatalf("unresolved parameter %s", p.Ref)
				}
				p = rp
			}
			out = append(out, p)
		}
		return out
	}
	base := "/api/v1"
	if len(doc.Servers) > 0 {
		base = doc.Servers[0].URL
	}
	var ops []operation
	seen := map[string]bool{}
	for template, item := range doc.Paths {
		for verb, o := range map[string]*opObj{
			http.MethodGet: item.Get, http.MethodPut: item.Put, http.MethodPost: item.Post,
			http.MethodDelete: item.Delete, http.MethodOptions: item.Options, http.MethodHead: item.Head,
			http.MethodPatch: item.Patch, http.MethodTrace: item.Trace,
		} {
			if o == nil {
				continue
			}
			if o.OperationID == "" || seen[o.OperationID] {
				t.Fatalf("%s %s: missing or duplicate operationId %q", verb, template, o.OperationID)
			}
			seen[o.OperationID] = true
			b := base
			for _, s := range [][]serverObj{item.Servers, o.Servers} {
				if len(s) > 0 {
					b = strings.TrimSuffix(s[0].URL, "/")
				}
			}
			ops = append(ops, operation{
				id: o.OperationID, verb: verb, template: template, base: b,
				params: append(resolve(item.Parameters), resolve(o.Parameters)...),
				body:   o.RequestBody,
			})
		}
	}
	if len(ops) == 0 {
		t.Fatal("no operation found in api/openapi.yaml")
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].id < ops[j].id })
	return ops
}

// --- Stub detection ------------------------------------------------------

// isStub reports whether the implementations wired by the server
// (public.NewServer on tenant hosts and admin.NewServer on the admin host,
// built without their services) both answer op exactly like
// stubs.Unimplemented, for a zero request and a context without tenant. A
// panic or any difference means implemented.
func isStub(t *testing.T, op operation) bool {
	t.Helper()
	want, wantOK := call(reflect.ValueOf(stubs.Unimplemented{}), op.method())
	if !wantOK {
		t.Fatalf("stubs.Unimplemented.%s panicked", op.method())
	}
	for _, impl := range []any{public.NewServer(), admin.NewServer()} {
		got, gotOK := call(reflect.ValueOf(impl), op.method())
		if !gotOK {
			return false
		}
		if errors.Is(got.err, stubs.ErrNotImplemented) != errors.Is(want.err, stubs.ErrNotImplemented) {
			return false
		}
		if !reflect.DeepEqual(got.resp, want.resp) {
			return false
		}
	}
	return true
}

type callResult struct {
	resp any
	err  error
}

// call invokes the named strict-server method with a background context and
// a zero request object, recovering from panics.
func call(recv reflect.Value, name string) (res callResult, ok bool) {
	m := recv.MethodByName(name)
	if !m.IsValid() {
		return callResult{}, false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	out := m.Call([]reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.Zero(m.Type().In(1)),
	})
	res.resp = out[0].Interface()
	if e := out[1].Interface(); e != nil {
		res.err, _ = e.(error)
	}
	return res, true
}

// --- Server --------------------------------------------------------------

// harness is a running server with tenants A and B.
type harness struct {
	addr    string
	tenantA *tenant.Tenant
	tenantB *tenant.Tenant
	client  *http.Client
	nextIP  atomic.Uint32
	// fixtures are deposit resources of tenant A.
	fixtures depositFixtures
	// transfers are the other sessions of the transfer cases.
	transfers transferFixtures
	// engine is the database of the server, which the download cases
	// open to make a transfer available as the antivirus would.
	engine storetest.Engine
	// admins are the administrator accounts of the admin cases.
	admins adminFixtures
	// config is the configuration seeded for the tenant cases.
	config configFixtures
	// ops are the resources seeded for the tenant operation cases.
	ops opsFixtures
	// sessMu guards sess, the session of the delegated admin of tenant A
	// shared by the tenant configuration cases (opened on first use), and
	// super, the session of the super admin (completed on first use).
	sessMu sync.Mutex
	sess   *adminSession
	super  *adminSession
}

// masterKeyLabel names the master key of the server
// (masterkeytest.Key gives the same key to the download cases).
const masterKeyLabel = "isolation-http"

// writeMasterKey writes the master key masterKeyLabel to dir and returns
// its path.
func writeMasterKey(t *testing.T, dir string) string {
	t.Helper()
	path, _ := masterkeytest.WriteLabeledKeyFile(t, dir, masterKeyLabel)
	return path
}

// startHarness creates the tenants and runs app.Run on a loopback port.
// The loopback is a trusted proxy so that each request can carry its own
// client IP in X-Forwarded-For and the per-IP rate limits never interfere
// with the enumeration.
func startHarness(t *testing.T, e storetest.Engine) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mk := func(name, fqdn string) *tenant.Tenant {
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: name, FQDN: fqdn, DefaultLanguage: "fr", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		return tn
	}
	h := &harness{
		engine:  e,
		tenantA: mk(nameA, hostA),
		tenantB: mk(nameB, hostB),
		client: &http.Client{
			Timeout:       waitTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     &http.Transport{Proxy: nil},
		},
	}
	h.fixtures = seedDeposit(t, db, h.tenantA.ID)
	h.transfers = seedTransfers(t, db, h.tenantA.ID, h.tenantB.ID)
	h.admins = seedAdmins(t, db, h.tenantA.ID)
	root := t.TempDir()
	h.config = seedTenantConfig(t, db, h, filepath.Join(root, "data"))
	h.ops = seedOperations(t, db, h.tenantA.ID, h.tenantB.ID)
	_ = db.Close()

	env := map[string]string{
		config.EnvDBDriver:       e.Driver,
		config.EnvDBDSN:          e.DSN,
		config.EnvDBMigrateDSN:   e.MigrateDSN,
		config.EnvDataDir:        filepath.Join(root, "data"),
		config.EnvBackupDir:      filepath.Join(root, "backups"),
		config.EnvLogDir:         filepath.Join(root, "logs"),
		config.EnvMasterKeyFile:  writeMasterKey(t, t.TempDir()),
		config.EnvListenAddr:     "127.0.0.1:8080", // unused: WithListener
		config.EnvTrustedProxies: "127.0.0.1",
		config.EnvClamAVAddr:     fakeClamd(t),
		config.EnvAdminHosts:     hostAdmin,
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- app.Run(runCtx, cfg, app.WithListener(ln), app.WithLogOutput(io.Discard)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("app.Run: %v", err)
			}
		case <-time.After(waitTimeout):
			t.Error("app.Run did not stop")
		}
	})
	return h
}

// fakeClamd answers PONG to every PING, so that /healthz is healthy.
func fakeClamd(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				if _, err := bufio.NewReader(c).ReadBytes(0); err == nil {
					_, _ = c.Write([]byte("PONG\x00"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// response is a fully read HTTP response.
type response struct {
	status int
	header http.Header
	body   []byte
}

// send performs op under host, with tenant A's identifiers in the path
// (the "resource of A") and sample values for the other parameters.
func (h *harness) send(t *testing.T, op operation, host string) response {
	t.Helper()
	path := op.template
	header := http.Header{}
	query := url.Values{}
	for _, p := range op.params {
		v := p.sample()
		if p.Name == "tenantId" {
			v = string(h.tenantA.ID)
		}
		switch p.In {
		case "path":
			path = strings.ReplaceAll(path, "{"+p.Name+"}", v)
		case "header":
			if p.Required {
				header.Set(p.Name, v)
			}
		case "query":
			if p.Required {
				query.Set(p.Name, v)
			}
		}
	}
	if strings.Contains(path, "{") {
		t.Fatalf("%s: unresolved path parameter in %s", op.id, path)
	}
	var body io.Reader
	if op.body != nil {
		ct, payload := sampleBody(op.body)
		header.Set("Content-Type", ct)
		body = bytes.NewReader(payload)
	}
	target := "http://" + h.addr + op.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	return h.do(t, op.verb, target, host, body, header)
}

// do sends a request under host with a fresh client IP and reads the whole
// response.
func (h *harness) do(t *testing.T, method, target, host string, body io.Reader, header http.Header) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = header
	req.Host = host
	n := h.nextIP.Add(1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.%d.%d", 100+n/250, 1+n%250))
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s under %s: %v", method, target, host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

// sampleBody returns a minimal body for the first declared media type.
func sampleBody(rb *requestBody) (contentType string, payload []byte) {
	types := make([]string, 0, len(rb.Content))
	for ct := range rb.Content {
		types = append(types, ct)
	}
	sort.Strings(types)
	ct := types[0]
	switch {
	case strings.Contains(ct, "json"):
		return ct, []byte(`{}`)
	case strings.HasPrefix(ct, "image/"):
		return "image/png", []byte("\x89PNG\r\n\x1a\n")
	default:
		return ct, []byte("x")
	}
}

// leaks lists the tenant data that must never appear in an answer about
// another tenant or in a tenant-agnostic answer.
func (h *harness) leaks() []string {
	return []string{
		nameA, nameB, hostA, hostB, string(h.tenantA.ID), string(h.tenantB.ID),
	}
}

// --- Cases ---------------------------------------------------------------

// stillStub asserts that op answers 404 (a not-found Problem when there is
// a body) under both tenants, with tenant A's identifiers in the path.
func stillStub(t *testing.T, h *harness, op operation) {
	t.Helper()
	for _, host := range []string{hostA, hostB} {
		resp := h.send(t, op, host)
		if resp.status != http.StatusNotFound {
			t.Fatalf("%s under %s: status %d, want 404 from the stub; body %s", op, host, resp.status, resp.body)
		}
		if len(resp.body) == 0 {
			continue // tus stubs and HEAD answer a bare 404
		}
		var p struct {
			Code     string `json:"code"`
			Instance string `json:"instance"`
		}
		if err := json.Unmarshal(resp.body, &p); err != nil || p.Code != "not-found" {
			t.Errorf("%s under %s: body %s, want a not-found Problem", op, host, resp.body)
		}
		if p.Instance == "" || p.Instance != resp.header.Get("X-Request-Id") {
			t.Errorf("%s under %s: instance %q, want the X-Request-Id %q", op, host, p.Instance, resp.header.Get("X-Request-Id"))
		}
		noLeak(t, h, op, host, resp)
	}
}

// sameAnswerWithoutTenantData asserts a 200 under both tenants with
// identical bodies carrying no tenant data.
func sameAnswerWithoutTenantData(t *testing.T, h *harness, op operation) {
	t.Helper()
	a := h.send(t, op, hostA)
	b := h.send(t, op, hostB)
	if a.status != http.StatusOK || b.status != http.StatusOK {
		t.Fatalf("%s: status %d under A, %d under B, want 200", op, a.status, b.status)
	}
	if !bytes.Equal(a.body, b.body) {
		t.Errorf("%s differs between tenants: %s vs %s", op, a.body, b.body)
	}
	noLeak(t, h, op, hostA, a)
	noLeak(t, h, op, hostB, b)
}

// tenantAgnostic asserts that the operation, served outside the tenant
// API, answers the same under A, B and an unknown host.
func tenantAgnostic(t *testing.T, h *harness, op operation) {
	t.Helper()
	ref := h.send(t, op, hostA)
	if ref.status != http.StatusOK {
		t.Fatalf("%s under %s: status %d, want 200", op, hostA, ref.status)
	}
	for _, host := range []string{hostB, "unknown.example.net"} {
		got := h.send(t, op, host)
		if got.status != ref.status || !bytes.Equal(got.body, ref.body) {
			t.Errorf("%s under %s: %d %s, want the same answer as under %s", op, host, got.status, got.body, hostA)
		}
	}
	noLeak(t, h, op, hostA, ref)
}

// noLeak asserts that no tenant data appears in resp.
func noLeak(t *testing.T, h *harness, op operation, host string, resp response) {
	t.Helper()
	body := string(resp.body)
	for _, s := range h.leaks() {
		if strings.Contains(body, s) {
			t.Errorf("%s under %s leaks %q", op, host, s)
		}
	}
	for k, vs := range resp.header {
		if slices.ContainsFunc(vs, func(v string) bool {
			return slices.ContainsFunc(h.leaks(), func(s string) bool { return strings.Contains(v, s) })
		}) {
			t.Errorf("%s under %s leaks tenant data in header %s: %q", op, host, k, vs)
		}
	}
}
