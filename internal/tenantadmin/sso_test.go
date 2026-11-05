package tenantadmin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/oidc"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Test values of the single sign-on configuration.
const (
	ssoIssuerA  = "https://login.example.com/11111111-2222-3333-4444-555555555555/v2.0"
	ssoIssuerA2 = "https://idp.entity-a.example.com/realms/staff"
	ssoAppA     = "7f3c9a10-0000-4000-8000-00000000c0de"
	ssoAppA2    = "7f3c9a10-0000-4000-8000-00000000beef"
	ssoSecret   = "client-secret-from-the-provider"
	ssoSecret2  = "second-client-secret-value"
	domainA     = "entity-a.example.com"
	domainA2    = "staff.entity-a.example.com"
	domainB     = "entity-b.example.com"
	sharedDom   = "shared.example.com"
	sessionIdle = 30 * time.Minute
)

// fakeTester records the issuers tested and answers res.
type fakeTester struct {
	issuers []string
	res     oidc.TestResult
}

func (f *fakeTester) Test(_ context.Context, issuer string) oidc.TestResult {
	f.issuers = append(f.issuers, issuer)
	return f.res
}

// faultSSO wraps an ssoRepo and fails the methods named in errs.
type faultSSO struct {
	ssoRepo
	errs map[string]error
}

func (f *faultSSO) getSSO(ctx context.Context, tid tenant.ID) (store.TenantSSO, error) {
	if err := f.errs["getSSO"]; err != nil {
		return store.TenantSSO{}, err
	}
	return f.ssoRepo.getSSO(ctx, tid)
}

func (f *faultSSO) revokeSSOSessions(ctx context.Context, tid tenant.ID, issuer, clientID string) (int64, error) {
	if err := f.errs["revoke"]; err != nil {
		return 0, err
	}
	return f.ssoRepo.revokeSSOSessions(ctx, tid, issuer, clientID)
}

func (f *faultSSO) unpinIdentities(ctx context.Context, tid tenant.ID, issuer, clientID string) ([]store.AdminIdentity, error) {
	if err := f.errs["unpin"]; err != nil {
		return nil, err
	}
	return f.ssoRepo.unpinIdentities(ctx, tid, issuer, clientID)
}

func (f *faultSSO) scrub(ctx context.Context) error {
	if err := f.errs["scrub"]; err != nil {
		return err
	}
	return f.ssoRepo.scrub(ctx)
}

// ssoFaults replaces the SSO repository of the service with a faultSSO.
func (ev *env) ssoFaults(errs map[string]error) {
	inner := ev.svc.sso
	if prev, ok := inner.(*faultSSO); ok {
		inner = prev.ssoRepo
	}
	ev.svc.sso = &faultSSO{ssoRepo: inner, errs: errs}
}

// ssoSteps returns the store steps of the SSO repository of the service.
func (ev *env) ssoSteps() *ssoStore {
	r := ev.svc.sso
	if f, ok := r.(*faultSSO); ok {
		r = f.ssoRepo
	}
	return r.(*ssoStore)
}

// ssoEnv is an env whose tenants have internal domains (A: domainA,
// domainA2 and sharedDom; B: domainB and sharedDom) and a fake tester.
func ssoEnv(t *testing.T, e storetest.Engine) (*env, *fakeTester) {
	t.Helper()
	tester := &fakeTester{res: oidc.TestResult{Success: true, Duration: 182 * time.Millisecond, Stage: oidc.StageDone}}
	ev := newEnv(t, e, func(o *Options) { o.SSOTester = tester })
	ctx := context.Background()
	if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID, nil, []string{domainA, domainA2, sharedDom}); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.db.NetworkRules().Replace(ctx, ev.b.ID, nil, []string{domainB, sharedDom}); err != nil {
		t.Fatal(err)
	}
	return ev, tester
}

// ssoIn returns a valid update of tenant A, with secret when not "".
func ssoIn(secret string) SSOUpdate {
	in := SSOUpdate{
		Enabled: true, Issuer: ssoIssuerA, ClientID: ssoAppA, EmailDomains: []string{domainA2, "Entity-A.Example.com"},
		RequireMFA: true,
	}
	if secret != "" {
		in.ClientSecret = ptr(secret)
	}
	return in
}

// ssoAuditFields returns the "fields" of the last event of action on tid,
// failing when the details hold one of the secrets.
func ssoAuditFields(t *testing.T, ev *env, tid tenant.ID, action audit.Action) []string {
	t.Helper()
	evs := ev.auditEvents(t, tid, action)
	if len(evs) == 0 {
		t.Fatalf("no %s event", action)
	}
	last := evs[0]
	for _, e := range evs {
		if e.At.After(last.At) || (e.At.Equal(last.At) && e.ID > last.ID) {
			last = e
		}
	}
	for _, s := range []string{ssoSecret, ssoSecret2} {
		if strings.Contains(string(last.Details), s) {
			t.Fatalf("%s details hold the secret: %s", action, last.Details)
		}
	}
	var d struct {
		Fields []string `json:"fields"`
	}
	if err := json.Unmarshal(last.Details, &d); err != nil {
		t.Fatalf("%s details %s: %v", action, last.Details, err)
	}
	return d.Fields
}

func TestSSOConfiguration(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		auditorA := principal(store.RoleAuditor, "audrey.audit", ev.a.ID)

		_, err := ev.svc.GetSSO(ctx, ev.super, ev.a.ID)
		wantErr(t, "none yet", err, ErrNotFound)

		// The first write needs a secret, even disabled.
		in := ssoIn("")
		in.Enabled = false
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		if ie := invalidOf(t, "first write without secret", err, FieldSSOClientSecret); ie.Code != CodeRequired {
			t.Fatalf("code %q", ie.Code)
		}

		v, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
		mustNoErr(t, "create", err)
		if !v.Enabled || !v.HasClientSecret || !v.RequireMFA || v.Enforced || v.Issuer != ssoIssuerA || v.ClientID != ssoAppA ||
			!slices.Equal(v.EmailDomains, []string{domainA, domainA2}) || v.CreatedAt.IsZero() {
			t.Fatalf("created view %+v", v)
		}
		stored, err := ev.db.SSOSettings().Get(ctx, ev.a.ID)
		mustNoErr(t, "stored", err)
		secret, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, stored.ClientSecretKeyID)
		mustNoErr(t, "open", err)
		if string(secret) != ssoSecret || stored.UpdatedBy != ev.super.Admin.ID {
			t.Fatalf("secret %q, updated by %q", secret, stored.UpdatedBy)
		}
		firstKey := stored.ClientSecretKeyID
		if got := ssoAuditFields(t, ev, ev.a.ID, audit.ActionTenantSSOUpdated); !slices.Equal(got,
			[]string{"enabled", "issuer", "clientId", "clientSecret", "emailDomains", "requireMfa"}) {
			t.Fatalf("create fields %v", got)
		}

		// Readable by the super admin, the delegated admin and the auditor
		// of A; 404 for those of B.
		for name, p := range map[string]adminauth.Principal{"super": ev.super, "delegated": ev.adminA, "auditor": auditorA} {
			got, err := ev.svc.GetSSO(ctx, p, ev.a.ID)
			mustNoErr(t, "get by "+name, err)
			if !got.HasClientSecret || got.Issuer != ssoIssuerA || !slices.Equal(got.EmailDomains, v.EmailDomains) {
				t.Errorf("get by %s: %+v", name, got)
			}
		}
		for name, p := range map[string]adminauth.Principal{
			"delegated of B": ev.adminB, "auditor of B": principal(store.RoleAuditor, "boris.audit", ev.b.ID),
		} {
			_, err := ev.svc.GetSSO(ctx, p, ev.a.ID)
			wantErr(t, "get by "+name, err, ErrNotFound)
		}

		// Keeping the secret while the pair stays.
		in = ssoIn("")
		in.Enforced = true
		v, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "keep", err)
		if !v.HasClientSecret || !v.Enforced {
			t.Fatalf("kept view %+v", v)
		}
		if got := ssoAuditFields(t, ev, ev.a.ID, audit.ActionTenantSSOUpdated); !slices.Equal(got, []string{"enforced"}) {
			t.Fatalf("keep fields %v", got)
		}
		// A new issuer or client ID without a secret is refused.
		for name, change := range map[string]func(*SSOUpdate){
			"issuer": func(u *SSOUpdate) { u.Issuer = ssoIssuerA2 },
			"client": func(u *SSOUpdate) { u.ClientID = ssoAppA2 },
		} {
			in := ssoIn("")
			change(&in)
			_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
			if ie := invalidOf(t, name+" without secret", err, FieldSSOClientSecret); ie.Code != CodeRequired {
				t.Errorf("%s: code %q", name, ie.Code)
			}
		}
		// A new secret replaces and erases the stored one.
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret2), clientIP)
		mustNoErr(t, "new secret", err)
		if _, err := ev.db.WrappedKeys().Get(ctx, ev.a.ID, firstKey); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("replaced secret kept: %v", err)
		}
		if got := ssoAuditFields(t, ev, ev.a.ID, audit.ActionTenantSSOUpdated); !slices.Equal(got, []string{"clientSecret", "enforced"}) {
			t.Fatalf("secret fields %v", got)
		}

		// A domain routed to another tenant.
		in = ssoIn(ssoSecret)
		in.EmailDomains = []string{sharedDom, domainA}
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "shared on A", err)
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.b.ID, SSOUpdate{
			Enabled: true, Issuer: ssoIssuerA2, ClientID: ssoAppA2, ClientSecret: ptr(ssoSecret), EmailDomains: []string{domainB, sharedDom},
		}, clientIP)
		wantErr(t, "shared on B", err, ErrSSODomainConflict)
		if _, err := ev.svc.GetSSO(ctx, ev.super, ev.b.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("conflict stored something: %v", err)
		}

		// Deletion.
		key, _ := ev.db.SSOSettings().Get(ctx, ev.a.ID)
		mustNoErr(t, "delete", ev.svc.DeleteSSO(ctx, ev.super, ev.a.ID, clientIP))
		_, err = ev.svc.GetSSO(ctx, ev.super, ev.a.ID)
		wantErr(t, "deleted", err, ErrNotFound)
		if _, err := ev.db.WrappedKeys().Get(ctx, ev.a.ID, key.ClientSecretKeyID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deleted secret kept: %v", err)
		}
		if got := ssoAuditFields(t, ev, ev.a.ID, audit.ActionTenantSSODeleted); !slices.Equal(got,
			[]string{"enabled", "issuer", "clientId", "clientSecret", "emailDomains", "requireMfa"}) {
			t.Fatalf("delete fields %v", got)
		}
		wantErr(t, "delete again", ev.svc.DeleteSSO(ctx, ev.super, ev.a.ID, clientIP), ErrNotFound)
		// The domain is free again for B.
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.b.ID, SSOUpdate{
			Issuer: ssoIssuerA2, ClientID: ssoAppA2, ClientSecret: ptr(ssoSecret), EmailDomains: []string{sharedDom},
		}, clientIP)
		mustNoErr(t, "shared on B after deletion", err)
	})
}

func TestSSOValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		long := strings.Repeat("a", maxSSOSecretLen+1)
		manyDomains := make([]string, store.MaxSSODomains+1)
		for i := range manyDomains {
			manyDomains[i] = "d" + string(rune('a'+i)) + ".example.com"
		}
		for name, tc := range map[string]struct {
			change func(*SSOUpdate)
			field  string
			code   string
		}{
			"issuer malformed":      {func(u *SSOUpdate) { u.Issuer = "not a url" }, FieldSSOIssuer, ""},
			"issuer backslash":      {func(u *SSOUpdate) { u.Issuer = `https://idp.example.com/a\b` }, FieldSSOIssuer, ""},
			"issuer other scheme":   {func(u *SSOUpdate) { u.Issuer = "ftp://idp.example.com/x" }, FieldSSOIssuer, ""},
			"client id empty":       {func(u *SSOUpdate) { u.ClientID = "" }, FieldSSOClientID, ""},
			"client id space":       {func(u *SSOUpdate) { u.ClientID = "a b" }, FieldSSOClientID, ""},
			"client id too long":    {func(u *SSOUpdate) { u.ClientID = strings.Repeat("x", store.MaxSSOClientIDLen+1) }, FieldSSOClientID, ""},
			"secret empty":          {func(u *SSOUpdate) { u.ClientSecret = ptr("") }, FieldSSOClientSecret, ""},
			"secret too long":       {func(u *SSOUpdate) { u.ClientSecret = &long }, FieldSSOClientSecret, ""},
			"secret control":        {func(u *SSOUpdate) { u.ClientSecret = ptr("a\nb") }, FieldSSOClientSecret, ""},
			"no domain":             {func(u *SSOUpdate) { u.EmailDomains = nil }, FieldSSOEmailDomains, ""},
			"too many domains":      {func(u *SSOUpdate) { u.EmailDomains = manyDomains }, FieldSSOEmailDomains, ""},
			"malformed domain":      {func(u *SSOUpdate) { u.EmailDomains = []string{domainA, "user@" + domainA2} }, "/emailDomains/1", ""},
			"duplicate domain":      {func(u *SSOUpdate) { u.EmailDomains = []string{domainA, "ENTITY-A.example.com."} }, "/emailDomains/1", ""},
			"not internal":          {func(u *SSOUpdate) { u.EmailDomains = []string{domainA, domainB} }, "/emailDomains/1", CodeNotInternalDomain},
			"not internal, first":   {func(u *SSOUpdate) { u.EmailDomains = []string{"other.example.org", domainA} }, "/emailDomains/0", CodeNotInternalDomain},
			"subdomain not listed":  {func(u *SSOUpdate) { u.EmailDomains = []string{"x." + domainA} }, "/emailDomains/0", CodeNotInternalDomain},
			"issuer before domains": {func(u *SSOUpdate) { u.Issuer, u.EmailDomains = "nope", nil }, FieldSSOIssuer, ""},
		} {
			in := ssoIn(ssoSecret)
			tc.change(&in)
			_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
			ie := invalidOf(t, name, err, tc.field)
			if ie.Code != tc.code {
				t.Errorf("%s: code %q, want %q", name, ie.Code, tc.code)
			}
		}
		for name, issuer := range map[string]string{
			"entra common":        "https://login.microsoftonline.com/common/v2.0",
			"entra organizations": "https://login.microsoftonline.com/organizations/v2.0",
			"template":            "https://login.microsoftonline.com/{tenantid}/v2.0",
			"multi-directory any": "https://idp.example.com/consumers/v2.0",
			"plain http":          "http://idp.example.com/realms/staff",
			"plain http, upper":   "HTTP://idp.example.com/realms/staff",
		} {
			in := ssoIn(ssoSecret)
			in.Issuer = issuer
			_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
			wantErr(t, name, err, ErrSSOIssuerNotAllowed)
		}
		if _, err := ev.svc.GetSSO(ctx, ev.super, ev.a.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a refused write stored something: %v", err)
		}
	})
}

// newSSOAccount creates a delegated admin attached to tids.
func newSSOAccount(t *testing.T, ev *env, username string, tids ...tenant.ID) store.Admin {
	t.Helper()
	a, err := ev.db.Admins().Create(context.Background(), store.Admin{
		Username: username, Email: username + "@entity-a.example.com", Role: store.RoleDelegatedAdmin, TenantIDs: tids, RequireTOTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// newSSOSession creates a session of adminID with token: a single sign-on
// one through (issuer, clientID), or a password one when issuer is "".
func newSSOSession(t *testing.T, ev *env, adminID, token, issuer, clientID string) {
	t.Helper()
	h := sha256.Sum256([]byte(token))
	s := store.AdminSession{
		ID: id.New(id.AdminSession), TokenHash: h[:], AdminID: adminID, State: store.SessionAuthenticated,
		CreatedAt: testStart, ExpiresAt: testStart.Add(12 * time.Hour),
	}
	if issuer != "" {
		s.AuthMethod, s.SSOIssuer, s.SSOClientID, s.SSOMFA = store.AuthOIDC, issuer, clientID, true
	}
	if err := ev.db.AdminSessions().Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// sessionAlive reports whether the session of token still exists.
func sessionAlive(t *testing.T, ev *env, token string) bool {
	t.Helper()
	h := sha256.Sum256([]byte(token))
	_, err := ev.db.AdminSessions().GetByTokenHash(context.Background(), h[:], testStart, sessionIdle)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	}
	t.Fatal(err)
	return false
}

// identities returns the pinned identities of adminID.
func identities(t *testing.T, ev *env, adminID string) []store.AdminIdentity {
	t.Helper()
	out, err := ev.db.AdminIdentities().List(context.Background(), adminID)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSSORevocation checks P57: a change of issuer or client ID revokes the
// single sign-on sessions of the previous pair and unpins its identities;
// disabling or deleting revokes the sessions only; other changes, the
// password sessions and the other tenants are untouched.
func TestSSORevocation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		alice := newSSOAccount(t, ev, "alice.sso", ev.a.ID)
		bob := newSSOAccount(t, ev, "bob.sso", ev.b.ID)
		link := func(adminID, issuer, clientID, subject string) {
			t.Helper()
			if _, err := ev.db.AdminIdentities().Link(ctx, store.AdminIdentity{
				AdminID: adminID, Issuer: issuer, ClientID: clientID, Subject: subject,
			}); err != nil {
				t.Fatal(err)
			}
		}

		_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
		mustNoErr(t, "create", err)
		newSSOSession(t, ev, alice.ID, "a-oidc", ssoIssuerA, ssoAppA)
		newSSOSession(t, ev, alice.ID, "a-password", "", "")
		newSSOSession(t, ev, bob.ID, "b-oidc", ssoIssuerA, ssoAppA)
		link(alice.ID, ssoIssuerA, ssoAppA, "subject-alice-0001")
		link(bob.ID, ssoIssuerA, ssoAppA, "subject-bob-0001")

		// A change of another member revokes nothing.
		in := ssoIn("")
		in.Enforced, in.RequireMFA = true, false
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "enforce", err)
		if !sessionAlive(t, ev, "a-oidc") || len(identities(t, ev, alice.ID)) != 1 {
			t.Fatal("a change of enforced revoked the sessions or the identities")
		}

		// New client ID: A's single sign-on sessions and identities of the
		// old pair go, the password session and B's account stay.
		in = ssoIn(ssoSecret2)
		in.ClientID = ssoAppA2
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "new client", err)
		for token, alive := range map[string]bool{"a-oidc": false, "a-password": true, "b-oidc": true} {
			if got := sessionAlive(t, ev, token); got != alive {
				t.Errorf("after client change: session %s alive = %v", token, got)
			}
		}
		if n := len(identities(t, ev, alice.ID)); n != 0 {
			t.Errorf("alice keeps %d identities", n)
		}
		if n := len(identities(t, ev, bob.ID)); n != 1 {
			t.Errorf("bob has %d identities", n)
		}
		unlinked := ev.auditEvents(t, ev.a.ID, audit.ActionAdminIdentityUnlinked)
		if len(unlinked) != 1 || unlinked[0].ObjectID != alice.ID || unlinked[0].ObjectKind != audit.ObjectAdmin ||
			unlinked[0].Actor != "root" || strings.Contains(string(unlinked[0].Details), "subject-alice") ||
			!strings.Contains(string(unlinked[0].Details), ssoIssuerA) {
			t.Fatalf("identity_unlinked events %+v", unlinked)
		}
		var details map[string]any
		if err := json.Unmarshal(unlinked[0].Details, &details); err != nil {
			t.Fatal(err)
		}
		if details["identity_id"] == nil || details["client_id"] != ssoAppA || details["reason"] != "sso_changed" {
			t.Fatalf("identity_unlinked details %v", details)
		}

		// Disabling: the sessions of the pair go, the identities stay.
		newSSOSession(t, ev, alice.ID, "a-oidc-2", ssoIssuerA, ssoAppA2)
		link(alice.ID, ssoIssuerA, ssoAppA2, "subject-alice-0002")
		in = ssoIn("")
		in.ClientID, in.Enabled = ssoAppA2, false
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "disable", err)
		if sessionAlive(t, ev, "a-oidc-2") || len(identities(t, ev, alice.ID)) != 1 {
			t.Fatal("disabling: session kept or identity dropped")
		}
		// Enabling again revokes nothing.
		newSSOSession(t, ev, alice.ID, "a-oidc-3", ssoIssuerA, ssoAppA2)
		in.Enabled = true
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "enable", err)
		if !sessionAlive(t, ev, "a-oidc-3") {
			t.Fatal("enabling revoked a session")
		}

		// New issuer: identities of the old pair unpinned too.
		in = ssoIn(ssoSecret)
		in.Issuer, in.ClientID = ssoIssuerA2, ssoAppA2
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "new issuer", err)
		if sessionAlive(t, ev, "a-oidc-3") || len(identities(t, ev, alice.ID)) != 0 {
			t.Fatal("issuer change: session or identity kept")
		}

		// Deletion: the sessions go, the identities stay.
		newSSOSession(t, ev, alice.ID, "a-oidc-4", ssoIssuerA2, ssoAppA2)
		link(alice.ID, ssoIssuerA2, ssoAppA2, "subject-alice-0003")
		mustNoErr(t, "delete", ev.svc.DeleteSSO(ctx, ev.super, ev.a.ID, clientIP))
		if sessionAlive(t, ev, "a-oidc-4") || !sessionAlive(t, ev, "a-password") || len(identities(t, ev, alice.ID)) != 1 {
			t.Fatal("deletion: session kept, password session revoked or identity dropped")
		}
	})
}

// TestSSORights checks the roles (T-287): the writes and the test are the
// super admin's; a delegated admin of the tenant gets ErrForbidden, an
// auditor of the tenant ErrReadOnlyRole, anyone outside the tenant
// ErrNotFound, without ever reaching the configuration.
func TestSSORights(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, tester := ssoEnv(t, e)
		_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
		mustNoErr(t, "create", err)
		ops := map[string]func(p adminauth.Principal, tid tenant.ID) error{
			"put": func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.PutSSO(ctx, p, tid, ssoIn("bogus"), clientIP)
				return err
			},
			"delete": func(p adminauth.Principal, tid tenant.ID) error { return ev.svc.DeleteSSO(ctx, p, tid, clientIP) },
			"test": func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.TestSSO(ctx, p, tid)
				return err
			},
		}
		for name, op := range ops {
			for who, tc := range map[string]struct {
				p    adminauth.Principal
				want error
			}{
				"delegated of A": {ev.adminA, ErrForbidden},
				"auditor of A":   {principal(store.RoleAuditor, "audrey.audit", ev.a.ID), adminauth.ErrReadOnlyRole},
				"delegated of B": {ev.adminB, ErrNotFound},
				"auditor of B":   {principal(store.RoleAuditor, "boris.audit", ev.b.ID), ErrNotFound},
				"no session":     {adminauth.Principal{}, ErrUnauthenticated},
			} {
				err := op(tc.p, ev.a.ID)
				wantErr(t, name+" by "+who, err, tc.want)
				if errors.Is(tc.want, ErrNotFound) && errors.Is(err, ErrForbidden) {
					t.Errorf("%s by %s tells the tenant exists", name, who)
				}
			}
			wantErr(t, name+" on unknown tenant", op(ev.super, "ten_unknown"), ErrNotFound)
		}
		_, err = ev.svc.GetSSO(ctx, adminauth.Principal{}, ev.a.ID)
		wantErr(t, "get without session", err, ErrUnauthenticated)
		if len(tester.issuers) != 0 {
			t.Fatalf("a refused test ran: %v", tester.issuers)
		}
		// Nothing changed.
		v, err := ev.svc.GetSSO(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "get", err)
		if v.Issuer != ssoIssuerA || len(ev.auditEvents(t, ev.a.ID, audit.ActionTenantSSODeleted)) != 0 {
			t.Fatalf("refused operations changed the configuration: %+v", v)
		}
	})
}

func TestSSOTest(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, tester := ssoEnv(t, e)
		_, err := ev.svc.TestSSO(ctx, ev.super, ev.a.ID)
		wantErr(t, "no configuration", err, ErrSSONothingToTest)

		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
		mustNoErr(t, "create", err)
		res, err := ev.svc.TestSSO(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "test", err)
		if !res.Success || res.Stage != oidc.StageDone || res.Duration != 182*time.Millisecond ||
			!slices.Equal(tester.issuers, []string{ssoIssuerA}) {
			t.Fatalf("result %+v, issuers %v", res, tester.issuers)
		}
		// A failure is a result.
		tester.res = oidc.TestResult{Duration: time.Second, Stage: "tls", Error: oidc.CategoryTLS}
		res, err = ev.svc.TestSSO(ctx, ev.super, ev.a.ID)
		mustNoErr(t, "failed test", err)
		if res.Success || res.Error != oidc.CategoryTLS {
			t.Fatalf("failed result %+v", res)
		}

		// Without tester: a wiring error.
		ev.svc.ssoTester = nil
		_, err = ev.svc.TestSSO(ctx, ev.super, ev.a.ID)
		wantErr(t, "no tester", err, errNoSSOTester)

		// A read failure is internal.
		ev.ssoFaults(map[string]error{"getSSO": errBoom})
		_, err = ev.svc.TestSSO(ctx, ev.super, ev.a.ID)
		if !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) {
			t.Fatalf("read failure: %v", err)
		}
		_, err = ev.svc.GetSSO(ctx, ev.super, ev.a.ID)
		wantErr(t, "get read failure", err, errBoom)
	})
}

// TestSSOFaults injects a failure at each step of the writes.
func TestSSOFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, _ := ssoEnv(t, e)
		steps := ev.ssoSteps()
		seal, put, del, rec := steps.sealTx, steps.putTx, steps.deleteTx, steps.recordTx
		restore := func() { steps.sealTx, steps.putTx, steps.deleteTx, steps.recordTx = seal, put, del, rec }

		// Network rules unreadable.
		f := ev.faults("networkRules")
		_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
		wantErr(t, "network rules", err, errBoom)
		delete(f.errs, "networkRules")

		// Each step of the write transaction, and the store errors mapped.
		for name, tc := range map[string]struct {
			set  func()
			want error
		}{
			"seal": {func() {
				steps.sealTx = func(context.Context, *store.ScopedTx, []byte) (string, error) { return "", errBoom }
			}, errBoom},
			"put": {func() {
				steps.putTx = func(context.Context, *store.ScopedTx, store.TenantSSO) (store.TenantSSO, store.TenantSSO, error) {
					return store.TenantSSO{}, store.TenantSSO{}, errBoom
				}
			}, errBoom},
			"tenant gone": {func() {
				steps.putTx = func(context.Context, *store.ScopedTx, store.TenantSSO) (store.TenantSSO, store.TenantSSO, error) {
					return store.TenantSSO{}, store.TenantSSO{}, store.ErrNotFound
				}
			}, ErrNotFound},
			"store issuer rule": {func() {
				steps.putTx = func(context.Context, *store.ScopedTx, store.TenantSSO) (store.TenantSSO, store.TenantSSO, error) {
					return store.TenantSSO{}, store.TenantSSO{}, store.ErrSSOIssuerNotAllowed
				}
			}, ErrSSOIssuerNotAllowed},
			"record": {func() {
				steps.recordTx = func(context.Context, *store.ScopedTx, audit.Event) error { return errBoom }
			}, errBoom},
		} {
			tc.set()
			_, err := ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
			wantErr(t, name, err, tc.want)
			restore()
			if _, err := ev.db.SSOSettings().Get(ctx, ev.a.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("%s: the failed write was committed: %v", name, err)
			}
		}
		if n := len(ev.auditEvents(t, ev.a.ID, audit.ActionTenantSSOUpdated)); n != 0 {
			t.Fatalf("%d events of failed writes", n)
		}

		// The deletion transaction.
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, ssoIn(ssoSecret), clientIP)
		mustNoErr(t, "create", err)
		steps.deleteTx = func(context.Context, *store.ScopedTx) (store.TenantSSO, error) { return store.TenantSSO{}, errBoom }
		wantErr(t, "delete step", ev.svc.DeleteSSO(ctx, ev.super, ev.a.ID, clientIP), errBoom)
		restore()
		steps.recordTx = func(context.Context, *store.ScopedTx, audit.Event) error { return errBoom }
		wantErr(t, "delete record", ev.svc.DeleteSSO(ctx, ev.super, ev.a.ID, clientIP), errBoom)
		restore()
		if _, err := ev.svc.GetSSO(ctx, ev.super, ev.a.ID); err != nil {
			t.Fatalf("a failed deletion was committed: %v", err)
		}

		// A tenant ID the store refuses (never reached through the service,
		// which checks the tenant first).
		if _, _, err := steps.putSSO(ctx, "", store.TenantSSO{}, nil, nil); err == nil {
			t.Error("putSSO with an empty tenant")
		}
		if _, err := steps.deleteSSO(ctx, "", nil); err == nil {
			t.Error("deleteSSO with an empty tenant")
		}

		// The steps after the commit only log their failures.
		alice := newSSOAccount(t, ev, "alice.sso", ev.a.ID)
		if _, err := ev.db.AdminIdentities().Link(ctx, store.AdminIdentity{
			AdminID: alice.ID, Issuer: ssoIssuerA, ClientID: ssoAppA, Subject: "subject-alice-0001",
		}); err != nil {
			t.Fatal(err)
		}
		ev.ssoFaults(map[string]error{"revoke": errBoom, "unpin": errBoom, "scrub": errBoom})
		in := ssoIn(ssoSecret2)
		in.ClientID = ssoAppA2
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "put with failing revocation", err)
		for _, msg := range []string{
			"revoking the single sign-on sessions failed", "unpinning the single sign-on identities failed",
			"scrubbing the erased single sign-on secret failed",
		} {
			if !strings.Contains(ev.logs.String(), msg) {
				t.Errorf("log lacks %q: %s", msg, ev.logs.String())
			}
		}
		// The audit of an unpinned identity.
		ev.ssoFaults(map[string]error{"scrub": store.ErrScrubBusy})
		ev.faults("audit")
		ev.logs.Reset()
		in.ClientID, in.ClientSecret = ssoAppA, ptr(ssoSecret)
		if _, err := ev.db.AdminIdentities().Link(ctx, store.AdminIdentity{
			AdminID: alice.ID, Issuer: ssoIssuerA, ClientID: ssoAppA2, Subject: "subject-alice-0002",
		}); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.PutSSO(ctx, ev.super, ev.a.ID, in, clientIP)
		mustNoErr(t, "put with failing audit", err)
		if logs := ev.logs.String(); !strings.Contains(logs, "audit write failed") || strings.Contains(logs, "scrubbing") {
			t.Errorf("logs: %s", logs)
		}
		ev.ssoFaults(map[string]error{"revoke": errBoom, "scrub": errBoom})
		mustNoErr(t, "delete with failing revocation", ev.svc.DeleteSSO(ctx, ev.super, ev.a.ID, clientIP))
	})
}
