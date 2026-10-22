package integration_test

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Helpers of the tenant configuration tests (CLAUDE.md sections 5, 12.1,
// 12.3, 13, 16.1 and 20; api/openapi.yaml "Admin tenants" and "Public";
// docs/operations/tenants.md; threat model T-63, T-64, T-92, T-110 and
// the SMTP SSRF entry P21).

// Tenant C, created through the API by the super admin.
const (
	hostC   = "transfer.entity-c.localhost"
	nameC   = "Entity C Integration"
	domainC = "entity-c.localhost"
	// internalNetC and insideC are the internal range and an internal IP
	// of tenant C (shared address space, RFC 6598: no real customer).
	internalNetC = "100.64.10.0/24"
	insideC      = "100.64.10.10"
	// ceilingC is the per-transfer ceiling of tenant C, set by the super
	// admin; its initial limit is half of it.
	ceilingC = int64(1 << 30)
	// quotaC is the storage quota of tenant C.
	quotaC = int64(1 << 40)
)

// Admin API paths of the tenant configuration.
const (
	pathTenants      = "/api/v1/admin/tenants"
	pathPublicTenant = "/api/v1/tenant"
	pathPublicLogo   = "/api/v1/tenant/assets/logo"
	pathPublicBg     = "/api/v1/tenant/assets/background"
	pathPublicLegal  = "/api/v1/tenant/legal/"
	// Default colors of a new tenant (internal/tenant).
	defaultPrimary = "#1F4E79"
	defaultAccent  = "#C2410C"
)

// tenantPath returns the admin path of tenant tid followed by sub.
func tenantPath(tid, sub string) string { return pathTenants + "/" + tid + sub }

// tenantJSON is the Tenant schema.
type tenantJSON struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	FQDN               string `json:"fqdn"`
	DefaultLanguage    string `json:"defaultLanguage"`
	MaxTransferBytes   int64  `json:"maxTransferBytes"`
	MaxTransferCeiling int64  `json:"maxTransferCeiling"`
	Status             string `json:"status"`
	StorageQuotaBytes  int64  `json:"storageQuotaBytes"`
	StorageUsedBytes   int64  `json:"storageUsedBytes"`
}

// brandingJSON is the Branding schema.
type brandingJSON struct {
	PrimaryColor  string `json:"primaryColor"`
	AccentColor   string `json:"accentColor"`
	HasLogo       bool   `json:"hasLogo"`
	HasBackground bool   `json:"hasBackground"`
	Contrast      []struct {
		Pair  string  `json:"pair"`
		Ratio float64 `json:"ratio"`
		Level string  `json:"level"`
	} `json:"contrast"`
}

// publicTenantJSON is the PublicTenant schema.
type publicTenantJSON struct {
	Name     string `json:"name"`
	Language string `json:"language"`
	Branding struct {
		PrimaryColor  string  `json:"primaryColor"`
		AccentColor   string  `json:"accentColor"`
		HasLogo       bool    `json:"hasLogo"`
		HasBackground bool    `json:"hasBackground"`
		LogoURL       *string `json:"logoUrl"`
		BackgroundURL string  `json:"backgroundUrl"`
	} `json:"branding"`
	Limits struct {
		MaxTransferBytes int64 `json:"maxTransferBytes"`
	} `json:"limits"`
	LegalDocuments []string `json:"legalDocuments"`
}

// smtpJSON is the SmtpSettings schema.
type smtpJSON struct {
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Security    string  `json:"security"`
	Username    *string `json:"username"`
	PasswordSet bool    `json:"passwordSet"`
	FromAddress string  `json:"fromAddress"`
	FromName    *string `json:"fromName"`
}

// smtpTestJSON is the SmtpTestResult schema.
type smtpTestJSON struct {
	Success    bool    `json:"success"`
	DurationMs int     `json:"durationMs"`
	Stage      string  `json:"stage"`
	Error      *string `json:"error"`
}

// templateJSON is the EmailTemplate schema.
type templateJSON struct {
	Key        string   `json:"key"`
	Language   string   `json:"language"`
	Customized bool     `json:"customised"` //nolint:misspell // member name of the OpenAPI schema (spec spelling)
	Subject    string   `json:"subject"`
	BodyHTML   string   `json:"bodyHtml"`
	BodyText   string   `json:"bodyText"`
	Variables  []string `json:"variables"`
}

// legalJSON is the LegalDocument schema.
type legalJSON struct {
	Document string  `json:"document"`
	Language string  `json:"language"`
	Markdown string  `json:"markdown"`
	HTML     *string `json:"html"`
}

// fieldErr is a field error of a Problem.
type fieldErr struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// fieldProblem is a Problem with its field errors.
type fieldProblem struct {
	Code   string     `json:"code"`
	Errors []fieldErr `json:"errors"`
}

// mergePatch sends a JSON merge patch with the client's CSRF token.
func (c *adminClient) mergePatch(t *testing.T, path string, body string) response {
	t.Helper()
	return c.send(t, http.MethodPatch, path, body, http.Header{hdrCSRF: {c.csrf}, "Content-Type": {mergePatch}})
}

// putBytes sends a PUT of data declared as contentType, with the CSRF
// token.
func (c *adminClient) putBytes(t *testing.T, path, contentType string, data []byte) response {
	t.Helper()
	return c.send(t, http.MethodPut, path, string(data), http.Header{hdrCSRF: {c.csrf}, "Content-Type": {contentType}})
}

// mustStatus fails unless resp has the status want, and returns resp.
func mustStatus(t *testing.T, what string, resp response, want int) response {
	t.Helper()
	if resp.status != want {
		t.Fatalf("%s: status %d, want %d; body %s", what, resp.status, want, resp.body)
	}
	return resp
}

// createTenantC creates tenant C as the super admin c, with a transfer
// limit of half its ceiling, and returns it.
func (c *adminClient) createTenantC(t *testing.T) tenantJSON {
	t.Helper()
	resp := mustStatus(t, "createTenant C", c.call(t, http.MethodPost, pathTenants, map[string]any{
		"name": nameC, "fqdn": hostC, "defaultLanguage": "en", "storageQuotaBytes": quotaC,
		"maxTransferBytes": ceilingC / 2, "maxTransferCeiling": ceilingC,
	}), http.StatusCreated)
	var tn tenantJSON
	mustJSON(t, resp.body, &tn)
	if !strings.HasPrefix(tn.ID, "ten_") || tn.Name != nameC || tn.FQDN != hostC || tn.DefaultLanguage != "en" ||
		tn.MaxTransferBytes != ceilingC/2 || tn.MaxTransferCeiling != ceilingC || tn.StorageQuotaBytes != quotaC ||
		tn.Status != "active" || tn.StorageUsedBytes != 0 {
		t.Errorf("created tenant = %+v", tn)
	}
	return tn
}

// createDelegatedOf creates, as the super admin c, a delegated admin of the
// tenant tid with an address in domain, and returns it signed in
// (activated through the link of the API response, TOTP enrolled) from ip.
func (c *adminClient) createDelegatedOf(t *testing.T, username, tid, domain, ip string) *adminClient {
	t.Helper()
	acct := &adminAccount{username: username, email: uniqueEmail(t, username, domain), password: "delegated password " + username}
	resp := mustStatus(t, "createAdmin "+username, c.call(t, http.MethodPost, pathAdmins, map[string]any{
		"username": username, "email": acct.email, "role": "delegated_admin", "tenantIds": []string{tid},
	}), http.StatusCreated)
	created, token := c.a.activationOf(t, resp)
	if created.Role != "delegated_admin" || len(created.TenantIDs) != 1 || created.TenantIDs[0] != tid {
		t.Errorf("created admin = %+v, want a delegated admin of %s", created, tid)
	}
	acct.id = created.ID
	c.a.secret(acct.password)
	d := c.a.client(acct, ip)
	if resp := d.activate(t, token); resp.status != http.StatusOK || d.state != stateEnrollRequired {
		t.Fatalf("activate %s: %d %s (state %s)", username, resp.status, resp.body, d.state)
	}
	d.enroll(t)
	return d
}

// publicTenant sends getPublicTenant on host and decodes the 200 answer.
func (s *server) publicTenant(t *testing.T, host string) publicTenantJSON {
	t.Helper()
	resp := mustStatus(t, "GET /tenant on "+host, s.get(t, host, pathPublicTenant), http.StatusOK)
	var p publicTenantJSON
	mustJSON(t, resp.body, &p)
	return p
}

// tenantRows returns, table by table, the number of rows the tenant tid
// still owns in every tenant-scoped table but the audit log.
func tenantRows(t *testing.T, e storetest.Engine, tid string) map[string]int {
	t.Helper()
	out := map[string]int{}
	out["tenants"] = countSystem(t, e, `SELECT COUNT(*) FROM tenants WHERE id = '`+tid+`'`)
	for _, table := range []string{
		"tenant_network_rules", "blocklist_entries", "wrapped_keys", "tenant_smtp_settings", "invitations",
		"verification_challenges", "verified_addresses", "deposit_sessions", "transfers", "transfer_recipients",
		"transfer_files", "password_failures", "admin_tenants", "tenant_email_templates", "tenant_legal_documents",
	} {
		out[table] = countSystem(t, e, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id = '`+tid+`'`)
	}
	return out
}

// tenantAudit returns the audit events of tenant tid, oldest first.
func (a *adminEnv) tenantAudit(t *testing.T, tid string) []auditRow {
	t.Helper()
	rows := sysQuery(t, a.e, `SELECT actor_kind, actor, ip, action, object_id, details FROM audit_events WHERE tenant_id = '`+
		tid+`' ORDER BY at, id`)
	out := make([]auditRow, len(rows))
	for i, r := range rows {
		out[i] = auditRow{actorKind: r[0], actor: r[1], ip: r[2], action: r[3], objectID: r[4], details: r[5]}
	}
	return out
}

// expectTenantAudit asserts that tenant tid has at least one audit event of
// each action, every one about the tenant itself, and returns them.
func (a *adminEnv) expectTenantAudit(t *testing.T, tid string, actions ...string) []auditRow {
	t.Helper()
	rows := a.tenantAudit(t, tid)
	seen := map[string]int{}
	for _, r := range rows {
		seen[r.action]++
		// The erasure itself is recorded by the system (the cleanup task
		// may complete it); every other tenant event by an admin.
		wantKind := "admin"
		if r.action == actionTenantDeleted {
			wantKind = "system"
		}
		if strings.HasPrefix(r.action, "tenant.") && (r.objectID != tid || r.actorKind != wantKind) {
			t.Errorf("audit event %s: object %q actor kind %q, want the tenant %s and %s", r.action, r.objectID, r.actorKind, tid, wantKind)
		}
	}
	for _, act := range actions {
		if seen[act] == 0 {
			t.Errorf("no %s audit event for tenant %s; actions: %v", act, tid, seen)
		}
	}
	return rows
}

// Audit actions of a tenant deletion: started by the super admin, then
// recorded once by the erasure (actor systemEraser), whoever completes it.
const (
	actionTenantDeletionStarted = "tenant.deletion_started"
	actionTenantDeleted         = "tenant.deleted"
	systemEraser                = "lifecycle"
)

// expectDeletionAudit asserts the audit trail of the deletion of tenant
// tid (name, fqdn): started at least once by the super admin from ip when
// ip is not empty (none otherwise: a deletion started outside the API),
// and exactly one tenant.deleted by the system eraser carrying the name
// and the FQDN, without IP. It returns the tenant's events.
func (a *adminEnv) expectDeletionAudit(t *testing.T, tid, name, fqdn, ip string) []auditRow {
	t.Helper()
	rows := a.expectTenantAudit(t, tid)
	started, deleted := 0, 0
	for _, r := range rows {
		switch r.action {
		case actionTenantDeletionStarted:
			started++
			if r.actorKind != "admin" || r.actor != superName || r.ip != ip {
				t.Errorf("%s by %s %q from %q, want the super admin %q from %q",
					r.action, r.actorKind, r.actor, r.ip, superName, ip)
			}
		case actionTenantDeleted:
			deleted++
			if r.actor != systemEraser || r.ip != "" {
				t.Errorf("%s by %q from %q, want %q without IP", r.action, r.actor, r.ip, systemEraser)
			}
			if !strings.Contains(r.details, `"name":`+strconv.Quote(name)) || !strings.Contains(r.details, `"fqdn":`+strconv.Quote(fqdn)) {
				t.Errorf("%s details = %s, want the name %q and the FQDN %q", r.action, r.details, name, fqdn)
			}
		}
	}
	if ip != "" && started == 0 {
		t.Errorf("no %s audit event for tenant %s", actionTenantDeletionStarted, tid)
	}
	if ip == "" && started != 0 {
		t.Errorf("%d %s audit events for tenant %s, want none", started, actionTenantDeletionStarted, tid)
	}
	if deleted != 1 {
		t.Errorf("%d %s audit events for tenant %s, want exactly 1", deleted, actionTenantDeleted, tid)
	}
	a.expectNoSecrets(t, rows)
	return rows
}

// confirmQuery returns the confirm query of deleteTenant for name.
func confirmQuery(name string) string { return "?confirm=" + url.QueryEscape(name) }

// countingListener is a TCP listener on the loopback that counts the
// connections it accepts and closes them at once.
type countingListener struct {
	ln       net.Listener
	accepted atomic.Int64
}

// newCountingListener starts a counting listener, closed when the test
// ends.
func newCountingListener(t *testing.T) *countingListener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cl.accepted.Add(1)
			_ = c.Close()
		}
	}()
	return cl
}

// port returns the port of the listener.
func (cl *countingListener) port() int { return cl.ln.Addr().(*net.TCPAddr).Port }

// --- Images ------------------------------------------------------------------

// testImage returns a w x h image with a gradient, so that its encodings
// are not trivial.
func testImage(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 255 / w), G: uint8(y * 255 / h), B: 0x80, A: 0xFF})
		}
	}
	return img
}

// pngChunk returns a PNG chunk of type typ with data and its CRC.
func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	_ = binary.Write(&b, binary.BigEndian, crc)
	return b.Bytes()
}

// pngIHDREnd is the offset of the end of the IHDR chunk of a PNG
// (signature 8 bytes, then 4 + 4 + 13 + 4 bytes).
const pngIHDREnd = 33

// pngWithText returns a w x h PNG carrying a tEXt chunk with marker right
// after its header: metadata a re-encoding must drop.
func pngWithText(t *testing.T, w, h int, marker string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage(w, h)); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	out := append([]byte{}, raw[:pngIHDREnd]...)
	out = append(out, pngChunk("tEXt", []byte("Comment\x00"+marker))...)
	return append(out, raw[pngIHDREnd:]...)
}

// pngBomb returns a valid tiny PNG whose header declares side x side
// pixels (with a correct CRC): a decompression bomb the dimension check
// must refuse before decoding.
func pngBomb(t *testing.T, side uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, testImage(4, 4)); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b[16:20], side)
	binary.BigEndian.PutUint32(b[20:24], side)
	binary.BigEndian.PutUint32(b[29:33], crc32.ChecksumIEEE(b[12:29]))
	return b
}

// jpegWithExif returns a w x h JPEG carrying an APP1 Exif segment with
// marker right after its SOI marker.
func jpegWithExif(t *testing.T, w, h int, marker string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, testImage(w, h), &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	payload := append([]byte("Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08"), marker...)
	seg := []byte{0xFF, 0xE1, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(payload)+2))
	seg = append(seg, payload...)
	out := append([]byte{}, raw[:2]...)
	out = append(out, seg...)
	return append(out, raw[2:]...)
}

// --- Files -------------------------------------------------------------------

// tenantDirOf returns the data directory of tenant tid.
func (s *server) tenantDirOf(tid string) string { return filepath.Join(s.cfg.DataDir, tid) }

// filesUnder returns the names of the regular files under dir ("" when the
// directory does not exist).
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// waitLog waits until the application log of s contains every one of the
// substrings in one line, and returns that line.
func waitLog(t *testing.T, s *server, parts ...string) string {
	t.Helper()
	var found string
	eventually(t, "application log line with "+strings.Join(parts, " and "), func() bool {
		for _, line := range strings.Split(s.appLog.String(), "\n") {
			ok := true
			for _, p := range parts {
				if !strings.Contains(line, p) {
					ok = false
					break
				}
			}
			if ok {
				found = line
				return true
			}
		}
		return false
	})
	return found
}

// customizedTrue is the EmailTemplate member of a customized template, in
// the spelling of the OpenAPI schema.
const customizedTrue = `"customised":true` //nolint:misspell // member name of the OpenAPI schema (spec spelling)
