package httpisolation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// hostAdmin is the admin host of the harness (TT_ADMIN_HOSTS).
const hostAdmin = "admin.localhost"

// Cookies of the harness.
const (
	adminCookie   = "__Host-tt_admin"
	depositCookie = "__Host-tt_deposit"
)

// adminFixtures are the administrator accounts of the admin cases.
type adminFixtures struct {
	// delegatedID, delegatedUser and delegatedPassword identify a delegated
	// admin of tenant A whose TOTP is not required, so that a password
	// alone opens an authenticated session.
	delegatedID       string
	delegatedUser     string
	delegatedPassword string
}

// seedAdmins creates the delegated admin of tenant A.
func seedAdmins(t *testing.T, db *store.DB, tidA tenant.ID) adminFixtures {
	t.Helper()
	ctx := context.Background()
	f := adminFixtures{delegatedUser: "deleg.entity-a", delegatedPassword: "a-long-passphrase-for-entity-a"}
	hash, err := crypto.NewPasswordHasher(1).HashPassword(ctx, []byte(f.delegatedPassword))
	if err != nil {
		t.Fatal(err)
	}
	a, err := db.Admins().Create(ctx, store.Admin{
		Username: f.delegatedUser, Email: "admin@entity-a.example.com", Role: store.RoleDelegatedAdmin,
		TenantIDs: []tenant.ID{tidA}, PasswordHash: hash,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.delegatedID = a.ID
	return f
}

// adminHostStatus is the answer of each admin operation on the admin host
// to a request without session and with an empty JSON body: the open
// operations reach their handler, every other one requires a session.
var adminHostStatus = map[string]int{
	"getSetupStatus":   http.StatusOK,           // no admin in the harness: setup required
	"createSuperAdmin": http.StatusBadRequest,   // empty username
	"adminLogin":       http.StatusUnauthorized, // invalid-credentials
	"activateAdmin":    http.StatusNotFound,     // unknown activation token
	"":                 http.StatusUnauthorized, // any other: unauthenticated
}

// adminHostOnly asserts that an administration operation answers 404
// under both tenant hosts, before any admin logic, and is served on the
// admin host.
func adminHostOnly(t *testing.T, h *harness, op operation) {
	t.Helper()
	for _, host := range []string{hostA, hostB} {
		resp := h.send(t, op, host)
		if resp.status != http.StatusNotFound || problemCode(resp) != "not-found" {
			t.Fatalf("%s under %s: %d %s, want 404 not-found: the administration is never served on a tenant host",
				op, host, resp.status, resp.body)
		}
		noLeak(t, h, op, host, resp)
	}
	want, ok := adminHostStatus[op.id]
	if !ok {
		want = adminHostStatus[""]
	}
	resp := h.send(t, op, hostAdmin)
	if resp.status != want {
		t.Fatalf("%s under %s: %d %s, want %d", op, hostAdmin, resp.status, resp.body, want)
	}
	if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s under %s: Cache-Control %q, want no-store", op, hostAdmin, cc)
	}
	noLeak(t, h, op, hostAdmin, resp)
}

// problemCode returns the code of a Problem body, "" otherwise.
func problemCode(resp response) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(resp.body, &p)
	return p.Code
}

// adminSession is a session opened on the admin host.
type adminSession struct {
	cookie string
	csrf   string
}

// header returns the headers of a same-origin request of the session.
func (s adminSession) header(withJSON bool) http.Header {
	hdr := http.Header{}
	hdr.Set("Cookie", adminCookie+"="+s.cookie)
	hdr.Set("X-CSRF-Token", s.csrf)
	hdr.Set("Origin", "https://"+hostAdmin)
	hdr.Set("Sec-Fetch-Site", "same-origin")
	if withJSON {
		hdr.Set("Content-Type", "application/json")
	}
	return hdr
}

// adminLogin signs the delegated admin in on the admin host.
func (h *harness) adminLogin(t *testing.T) adminSession {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": h.admins.delegatedUser, "password": h.admins.delegatedPassword})
	hdr := http.Header{"Content-Type": {"application/json"}}
	resp := h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/admin/auth/login", hostAdmin, bytes.NewReader(body), hdr)
	var state struct {
		Status    string `json:"status"`
		CsrfToken string `json:"csrfToken"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &state) != nil || state.Status != "authenticated" || state.CsrfToken == "" {
		t.Fatalf("login: %d %s", resp.status, resp.body)
	}
	for _, c := range (&http.Response{Header: resp.header}).Cookies() {
		if c.Name == adminCookie && c.Value != "" {
			return adminSession{cookie: c.Value, csrf: state.CsrfToken}
		}
	}
	t.Fatalf("login set no admin cookie: %v", resp.header)
	return adminSession{}
}

// TestAdminHostIsolation checks the separation of the admin host and the
// tenant hosts, and that a delegated admin of tenant A reaches neither
// tenant B nor the super admin operations.
func TestAdminHostIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		h := startHarness(t, e)
		base := "http://" + h.addr

		t.Run("tenant operations answer 404 on the admin host", func(t *testing.T) {
			for _, op := range loadOperations(t) {
				switch {
				case strings.HasPrefix(op.template, "/admin/"):
					continue
				case op.id == "getHealth" || op.id == "getOpenApiSpec":
					continue // outside any host (tenantAgnostic)
				case op.id == "getVersion":
					admin := h.send(t, op, hostAdmin)
					tenantA := h.send(t, op, hostA)
					if admin.status != http.StatusOK || !bytes.Equal(admin.body, tenantA.body) {
						t.Errorf("%s on the admin host: %d %s, want the answer of a tenant host", op, admin.status, admin.body)
					}
					continue
				}
				resp := h.send(t, op, hostAdmin)
				if resp.status != http.StatusNotFound || (len(resp.body) > 0 && problemCode(resp) != "not-found") {
					t.Errorf("%s on the admin host: %d %s, want 404", op, resp.status, resp.body)
				}
				noLeak(t, h, op, hostAdmin, resp)
			}
		})

		sess := h.adminLogin(t)

		t.Run("a delegated admin sees its own tenant only", func(t *testing.T) {
			resp := h.do(t, http.MethodGet, base+"/api/v1/admin/me", hostAdmin, nil, sess.header(false))
			var me struct {
				ID      string `json:"id"`
				Role    string `json:"role"`
				Tenants []struct {
					ID string `json:"id"`
				} `json:"tenants"`
			}
			if resp.status != http.StatusOK || json.Unmarshal(resp.body, &me) != nil {
				t.Fatalf("me: %d %s", resp.status, resp.body)
			}
			if me.ID != h.admins.delegatedID || me.Role != "delegated_admin" || len(me.Tenants) != 1 || me.Tenants[0].ID != string(h.tenantA.ID) {
				t.Errorf("me = %+v", me)
			}
			for _, leak := range []string{nameB, hostB, string(h.tenantB.ID)} {
				if strings.Contains(string(resp.body), leak) {
					t.Errorf("me of a delegated admin of A leaks %q", leak)
				}
			}
		})

		t.Run("a delegated admin cannot call the super admin operations", func(t *testing.T) {
			created, _ := json.Marshal(map[string]any{
				"username": "deleg.entity-b", "email": "admin@entity-b.example.com", "role": "delegated_admin",
				"tenantIds": []string{string(h.tenantB.ID)},
			})
			for _, c := range []struct {
				method, path string
				body         []byte
			}{
				{http.MethodGet, "/api/v1/admin/admins", nil},
				{http.MethodGet, "/api/v1/admin/admins/" + h.admins.delegatedID, nil},
				{http.MethodPost, "/api/v1/admin/admins", created},
				{http.MethodPost, "/api/v1/admin/admins/" + h.admins.delegatedID + "/reset-credentials", nil},
				{http.MethodDelete, "/api/v1/admin/admins/" + h.admins.delegatedID, nil},
			} {
				var body *bytes.Reader
				if c.body != nil {
					body = bytes.NewReader(c.body)
				} else {
					body = bytes.NewReader(nil)
				}
				resp := h.do(t, c.method, base+c.path, hostAdmin, body, sess.header(c.body != nil))
				if resp.status != http.StatusForbidden || problemCode(resp) != "forbidden" {
					t.Errorf("%s %s: %d %s, want 403 forbidden", c.method, c.path, resp.status, resp.body)
				}
			}
		})

		t.Run("the admin session is not accepted on a tenant host", func(t *testing.T) {
			// The browser never sends a __Host- cookie of the admin host to a
			// tenant FQDN; even sent by hand, it opens nothing there.
			resp := h.do(t, http.MethodGet, base+"/api/v1/admin/me", hostA, nil, sess.header(false))
			if resp.status != http.StatusNotFound {
				t.Errorf("admin me under %s: %d %s, want 404", hostA, resp.status, resp.body)
			}
			for _, name := range []string{adminCookie, depositCookie} {
				hdr := http.Header{"Cookie": {name + "=" + sess.cookie}}
				resp := h.do(t, http.MethodGet, base+"/api/v1/deposit-sessions/current", hostA, nil, hdr)
				if resp.status != http.StatusUnauthorized {
					t.Errorf("deposit session with the admin token in %s: %d %s, want 401", name, resp.status, resp.body)
				}
			}
			resp = h.do(t, http.MethodGet, base+"/api/v1/admin/me", "unknown.example.net", nil, sess.header(false))
			if resp.status != http.StatusMisdirectedRequest {
				t.Errorf("admin me under an unknown host: %d, want 421", resp.status)
			}
		})

		t.Run("logout ends the session and clears the cookie", func(t *testing.T) {
			resp := h.do(t, http.MethodPost, base+"/api/v1/admin/auth/logout", hostAdmin, nil, sess.header(false))
			if resp.status != http.StatusNoContent || !strings.Contains(resp.header.Get("Set-Cookie"), adminCookie+"=;") {
				t.Fatalf("logout: %d %v", resp.status, resp.header)
			}
			resp = h.do(t, http.MethodGet, base+"/api/v1/admin/me", hostAdmin, nil, sess.header(false))
			if resp.status != http.StatusUnauthorized || !strings.Contains(resp.header.Get("Set-Cookie"), adminCookie+"=;") {
				t.Errorf("me after logout: %d %v", resp.status, resp.header)
			}
		})
	})
}
