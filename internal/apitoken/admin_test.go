package apitoken

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// strPtr returns a pointer to s.
func strPtr(s string) *string { return &s }

// wantInvalid checks that err is an *InvalidError naming field.
func wantInvalid(t *testing.T, what string, err error, field string) {
	t.Helper()
	var ie *InvalidError
	if !errors.As(err, &ie) || ie.Field != field || !errors.Is(err, ErrInvalidInput) {
		t.Errorf("%s: err = %v, want an invalid %s", what, err, field)
	}
}

func TestNew(t *testing.T) {
	if _, err := New(nil, Options{}); !errors.Is(err, errMissingDB) {
		t.Errorf("New(nil) = %v", err)
	}
	s := newService(nil, Options{TouchInterval: time.Second, MaxTracked: 3})
	if s.touchInterval != time.Second || s.maxTracked != 3 || s.now == nil || s.logger == nil {
		t.Errorf("newService options = %+v", s)
	}
	s = newService(nil, Options{})
	if s.touchInterval != DefaultTouchInterval || s.maxTracked != DefaultMaxTracked {
		t.Errorf("newService defaults = %+v", s)
	}
}

func TestAdminLifecycle(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		svc := ev.svc
		// Each change happens one second after the previous one, so that
		// the audit events have distinct times.
		tick := func() { ev.clock.Advance(time.Second) }

		expires := testStart.Add(30 * 24 * time.Hour)
		created, err := svc.Create(ctx, ev.delegA, ev.a.ID, CreateInput{
			Name: "  Nightly export  ", AllowedCIDRs: []string{" 192.0.2.0/24 ", "2001:db8::1", "::ffff:198.51.100.0/120"},
			ExpiresAt: expires,
		}, adminIP)
		if err != nil {
			t.Fatal(err)
		}
		tok := created.Token
		wantCIDRs := []netip.Prefix{
			netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("198.51.100.0/24"),
		}
		if !ValidSecret(created.Secret) || tok.Prefix != created.Secret[:PrefixLen] || tok.Name != "Nightly export" ||
			!reflect.DeepEqual(tok.AllowedCIDRs, wantCIDRs) || tok.CreatedBy != "admin.a" || !tok.ExpiresAt.Equal(expires) ||
			!id.Valid(id.APIToken, tok.ID) {
			t.Fatalf("Create = %+v", tok)
		}
		// The secret authenticates on A only.
		if p, err := svc.Authenticate(ctx, ev.a.ID, "Bearer "+created.Secret, netip.MustParseAddr("192.0.2.99")); err != nil || p.TokenID != tok.ID {
			t.Fatalf("Authenticate = %+v, %v", p, err)
		}
		if _, err := svc.Authenticate(ctx, ev.b.ID, "Bearer "+created.Secret, netip.MustParseAddr("192.0.2.99")); !errors.Is(err, ErrInvalid) {
			t.Errorf("Authenticate on B = %v, want ErrInvalid", err)
		}

		// Without expiry, by the super admin.
		tick()
		other, err := svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "ops@example.com", AllowedCIDRs: []string{"0.0.0.0/0", "::/0"}}, adminIP)
		if err != nil || !other.Token.ExpiresAt.IsZero() || other.Secret == created.Secret {
			t.Fatalf("Create(no expiry) = %+v, %v", other.Token, err)
		}
		list, err := svc.List(ctx, ev.delegA, ev.a.ID)
		if err != nil || len(list) != 2 {
			t.Fatalf("List = %+v, %v", list, err)
		}
		if list, err := svc.List(ctx, ev.super, ev.b.ID); err != nil || len(list) != 0 {
			t.Errorf("List(B) = %+v, %v", list, err)
		}

		// Update: merge semantics.
		tick()
		upd, err := svc.Update(ctx, ev.delegA, ev.a.ID, tok.ID, UpdateInput{Name: strPtr("Renamed")}, adminIP)
		if err != nil || upd.Name != "Renamed" || !reflect.DeepEqual(upd.AllowedCIDRs, wantCIDRs) {
			t.Errorf("Update(name) = %+v, %v", upd, err)
		}
		tick()
		upd, err = svc.Update(ctx, ev.delegA, ev.a.ID, tok.ID, UpdateInput{AllowedCIDRs: []string{"203.0.113.7"}}, adminIP)
		if err != nil || upd.Name != "Renamed" || len(upd.AllowedCIDRs) != 1 || upd.AllowedCIDRs[0] != netip.MustParsePrefix("203.0.113.7/32") {
			t.Errorf("Update(cidrs) = %+v, %v", upd, err)
		}
		if upd, err := svc.Update(ctx, ev.delegA, ev.a.ID, tok.ID, UpdateInput{}, adminIP); err != nil || upd.Name != "Renamed" {
			t.Errorf("Update(nothing) = %+v, %v", upd, err)
		}
		tick()
		if _, err := svc.Update(ctx, ev.delegA, ev.a.ID, other.Token.ID, UpdateInput{Name: strPtr("ops2@example.com")}, adminIP); err != nil {
			t.Fatal(err)
		}

		// Revoke: once, then a no-op.
		tick()
		if err := svc.Revoke(ctx, ev.delegA, ev.a.ID, tok.ID, adminIP); err != nil {
			t.Fatal(err)
		}
		if err := svc.Revoke(ctx, ev.delegA, ev.a.ID, tok.ID, adminIP); err != nil {
			t.Errorf("Revoke(again) = %v", err)
		}
		if _, err := svc.Update(ctx, ev.delegA, ev.a.ID, tok.ID, UpdateInput{Name: strPtr("x")}, adminIP); !errors.Is(err, ErrStateConflict) {
			t.Errorf("Update(revoked) = %v, want ErrStateConflict", err)
		}
		if _, err := svc.Authenticate(ctx, ev.a.ID, "Bearer "+created.Secret, netip.MustParseAddr("203.0.113.7")); !errors.Is(err, ErrInvalid) {
			t.Errorf("Authenticate(revoked) = %v, want ErrInvalid", err)
		}
		list, _ = svc.List(ctx, ev.delegA, ev.a.ID)
		for _, k := range list {
			if k.ID == tok.ID && !k.Revoked() {
				t.Error("listed token not revoked")
			}
		}

		// Unknown or malformed IDs, and tokens of another tenant.
		for _, tokID := range []string{"tok_bad", id.New(id.APIToken), id.New(id.Transfer)} {
			if _, err := svc.Update(ctx, ev.super, ev.a.ID, tokID, UpdateInput{Name: strPtr("x")}, adminIP); !errors.Is(err, ErrNotFound) {
				t.Errorf("Update(%s) = %v", tokID, err)
			}
			if err := svc.Revoke(ctx, ev.super, ev.a.ID, tokID, adminIP); !errors.Is(err, ErrNotFound) {
				t.Errorf("Revoke(%s) = %v", tokID, err)
			}
		}
		if _, err := svc.Update(ctx, ev.super, ev.b.ID, other.Token.ID, UpdateInput{Name: strPtr("x")}, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("Update(A's token on B) = %v", err)
		}
		if err := svc.Revoke(ctx, ev.super, ev.b.ID, other.Token.ID, adminIP); !errors.Is(err, ErrNotFound) {
			t.Errorf("Revoke(A's token on B) = %v", err)
		}

		// Audit: one event per change, never the secret, the hash or an
		// address.
		rows := ev.auditRows(t, ev.a.ID)
		var actions []string
		for _, r := range rows {
			actions = append(actions, r.Action)
			if r.ObjectKind != "api_token" || r.IP != adminIP || r.ActorKind != store.ActorAdmin {
				t.Errorf("audit row = %+v", r.AuditEvent)
			}
			raw := string(r.Details)
			if strings.Contains(raw, created.Secret) || strings.Contains(raw, other.Secret) || strings.Contains(raw, "@") ||
				strings.Contains(raw, "tt_") {
				t.Errorf("audit details leak: %s", raw)
			}
		}
		wantActions := []string{
			"api_token.created", "api_token.created", "api_token.updated", "api_token.updated",
			"api_token.updated", "api_token.revoked",
		}
		if !reflect.DeepEqual(actions, wantActions) {
			t.Fatalf("audit actions = %v, want %v", actions, wantActions)
		}
		if d := rows[0].details; d["name"] != "Nightly export" || d["cidrCount"] != float64(3) ||
			d["expiresAt"] != expires.Format(time.RFC3339) || rows[0].Actor != "admin.a" || rows[0].ObjectID != tok.ID {
			t.Errorf("created details = %v", d)
		}
		if d := rows[1].details; d["name"] != nil || d["expiresAt"] != nil || d["cidrCount"] != float64(2) || rows[1].Actor != "root" {
			t.Errorf("created (address name) details = %v", d)
		}
		if d := rows[2].details; d["name"] != "Renamed" || d["cidrCount"] != nil || !reflect.DeepEqual(d["fields"], []any{"name"}) {
			t.Errorf("updated (name) details = %v", d)
		}
		if d := rows[3].details; d["name"] != nil || d["cidrCount"] != float64(1) || !reflect.DeepEqual(d["fields"], []any{"allowedCidrs"}) {
			t.Errorf("updated (cidrs) details = %v", d)
		}
		if d := rows[4].details; d["name"] != nil || !reflect.DeepEqual(d["fields"], []any{"name"}) {
			t.Errorf("updated (address name) details = %v", d)
		}
		if d := rows[5].details; d["name"] != "Renamed" || rows[5].ObjectID != tok.ID {
			t.Errorf("revoked details = %v", d)
		}
		if rows := ev.auditRows(t, ev.b.ID); len(rows) != 0 {
			t.Errorf("audit of B = %+v", rows)
		}
	})
}

func TestAdminRights(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	created, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "x", AllowedCIDRs: []string{"192.0.2.0/24"}}, adminIP)
	if err != nil {
		t.Fatal(err)
	}
	tokID := created.Token.ID
	ops := map[string]func(p adminauth.Principal, tid tenant.ID) error{
		"List": func(p adminauth.Principal, tid tenant.ID) error { _, err := ev.svc.List(ctx, p, tid); return err },
		// The invalid bodies prove that access is checked first.
		"Create": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.Create(ctx, p, tid, CreateInput{}, adminIP)
			return err
		},
		"Update": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.Update(ctx, p, tid, tokID, UpdateInput{Name: strPtr("")}, adminIP)
			return err
		},
		"Revoke": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.Revoke(ctx, p, tid, "tok_bad", adminIP)
		},
	}
	unauth := ev.delegA
	unauth.State = store.SessionTOTPRequired
	disabled := principal(store.RoleSuperAdmin, "gone")
	disabled.Admin.Disabled = true
	for name, op := range ops {
		if err := op(adminauth.Principal{}, ev.a.ID); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s without session = %v", name, err)
		}
		if err := op(unauth, ev.a.ID); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s pending TOTP = %v", name, err)
		}
		for _, c := range []struct {
			who string
			p   adminauth.Principal
			tid tenant.ID
		}{
			{"delegated admin of A on B", ev.delegA, ev.b.ID},
			{"disabled super admin", disabled, ev.a.ID},
			{"missing tenant", ev.super, missingTn},
			{"malformed tenant", ev.super, "bogus"},
		} {
			if err := op(c.p, c.tid); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s by %s = %v, want ErrNotFound", name, c.who, err)
			}
		}
	}
	// A tenant being deleted is not found; a failing tenant read is an
	// internal error.
	ev.repo.tenantStatus = tenant.StatusDeleting
	for name, op := range ops {
		if err := op(ev.super, ev.a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a deleting tenant = %v", name, err)
		}
	}
	ev.repo.tenantStatus, ev.repo.tenantErr = "", errBoom
	for name, op := range ops {
		if err := op(ev.super, ev.a.ID); !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) {
			t.Errorf("%s with a failing tenant read = %v", name, err)
		}
	}
	// No token was changed and nothing was audited by the refusals.
	ev.repo.tenantErr = nil
	if rows := ev.auditRows(t, ev.a.ID); len(rows) != 1 {
		t.Errorf("audit rows = %d, want the creation only", len(rows))
	}
}

func TestAdminValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	created, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "x", AllowedCIDRs: []string{"192.0.2.0/24"}}, adminIP)
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{"192.0.2.0/24"}
	many := make([]string, MaxCIDRs+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, byte(i), 0, 0}).String() + "/16"
	}
	names := map[string]string{
		"empty":    "",
		"blank":    "   ",
		"too long": strings.Repeat("é", MaxNameLen+1),
		"invalid":  "\xff\xfe",
		"control":  "a\x07b",
		"newline":  "a\nb",
		"bidi":     "a" + string(rune(0x202e)) + "b",
		"line sep": "a" + string(rune(0x2028)) + "b",
	}
	for what, name := range names {
		_, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: name, AllowedCIDRs: ok}, adminIP)
		wantInvalid(t, "Create(name "+what+")", err, FieldName)
		_, err = ev.svc.Update(ctx, ev.super, ev.a.ID, created.Token.ID, UpdateInput{Name: strPtr(name)}, adminIP)
		wantInvalid(t, "Update(name "+what+")", err, FieldName)
	}
	if _, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: strings.Repeat("é", MaxNameLen), AllowedCIDRs: ok}, adminIP); err != nil {
		t.Errorf("Create(name of %d characters) = %v", MaxNameLen, err)
	}
	cidrs := map[string]struct {
		in    []string
		field string
	}{
		"none":      {[]string{}, FieldAllowedCIDRs},
		"too many":  {many, FieldAllowedCIDRs},
		"too long":  {[]string{"192.0.2.0/24", strings.Repeat("1", MaxCIDRLen+1)}, FieldAllowedCIDRs + "/1"},
		"syntax":    {[]string{"not-an-ip"}, FieldAllowedCIDRs + "/0"},
		"host bits": {[]string{"192.0.2.1/24"}, FieldAllowedCIDRs + "/0"},
		"zone":      {[]string{"fe80::1%eth0"}, FieldAllowedCIDRs + "/0"},
		"duplicate": {[]string{"192.0.2.0/24", "198.51.100.0/24", "::ffff:192.0.2.0/120"}, FieldAllowedCIDRs + "/2"},
	}
	for what, c := range cidrs {
		_, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "n", AllowedCIDRs: c.in}, adminIP)
		wantInvalid(t, "Create(cidrs "+what+")", err, c.field)
		_, err = ev.svc.Update(ctx, ev.super, ev.a.ID, created.Token.ID, UpdateInput{AllowedCIDRs: c.in}, adminIP)
		wantInvalid(t, "Update(cidrs "+what+")", err, c.field)
	}
	if _, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "n"}, adminIP); err == nil {
		t.Error("Create without ranges accepted")
	}
	for _, exp := range []time.Time{testStart, testStart.Add(-time.Hour)} {
		_, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "n", AllowedCIDRs: ok, ExpiresAt: exp}, adminIP)
		wantInvalid(t, "Create(expiry "+exp.String()+")", err, FieldExpiresAt)
	}
	var ie *InvalidError
	_, err = ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "n", AllowedCIDRs: []string{"secret-looking-value"}}, adminIP)
	if !errors.As(err, &ie) || strings.Contains(ie.Error(), "secret-looking-value") || !strings.HasPrefix(ie.Error(), "apitoken: invalid /allowedCidrs/0: ") {
		t.Errorf("InvalidError = %v", err)
	}
}

func TestAdminStoreFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ok := CreateInput{Name: "n", AllowedCIDRs: []string{"192.0.2.0/24"}}
	created, err := ev.svc.Create(ctx, ev.super, ev.a.ID, ok, adminIP)
	if err != nil {
		t.Fatal(err)
	}
	tokID := created.Token.ID

	ev.repo.listErr = errBoom
	if _, err := ev.svc.List(ctx, ev.super, ev.a.ID); !errors.Is(err, errBoom) {
		t.Errorf("List = %v", err)
	}
	ev.repo.listErr = nil
	ev.repo.createErr = store.ErrNotFound
	if _, err := ev.svc.Create(ctx, ev.super, ev.a.ID, ok, adminIP); !errors.Is(err, ErrNotFound) {
		t.Errorf("Create(tenant gone) = %v", err)
	}
	ev.repo.createErr = errBoom
	if _, err := ev.svc.Create(ctx, ev.super, ev.a.ID, ok, adminIP); !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) {
		t.Errorf("Create(failure) = %v", err)
	}
	ev.repo.createErr = nil
	saved := newSecret
	newSecret = func() (string, error) { return "", errBoom }
	_, err = ev.svc.Create(ctx, ev.super, ev.a.ID, ok, adminIP)
	newSecret = saved
	if !errors.Is(err, errBoom) {
		t.Errorf("Create(no entropy) = %v", err)
	}
	ev.repo.updateErr = errBoom
	if _, err := ev.svc.Update(ctx, ev.super, ev.a.ID, tokID, UpdateInput{Name: strPtr("x")}, adminIP); !errors.Is(err, errBoom) {
		t.Errorf("Update(failure) = %v", err)
	}
	ev.repo.revokeErr = errBoom
	if err := ev.svc.Revoke(ctx, ev.super, ev.a.ID, tokID, adminIP); !errors.Is(err, errBoom) {
		t.Errorf("Revoke(failure) = %v", err)
	}
	ev.repo.updateErr, ev.repo.revokeErr = nil, nil

	// A failing audit write is logged; the change stays.
	ev.repo.auditErr = errBoom
	if err := ev.svc.Revoke(ctx, ev.super, ev.a.ID, tokID, adminIP); err != nil {
		t.Fatalf("Revoke with a failing audit = %v", err)
	}
	if logs := ev.logs.String(); !strings.Contains(logs, "audit write failed") || !strings.Contains(logs, "api_token.revoked") {
		t.Errorf("logs = %s", logs)
	}
	if list, _ := ev.svc.List(ctx, ev.super, ev.a.ID); len(list) != 1 || !list[0].Revoked() {
		t.Errorf("token after a failing audit = %+v", list)
	}
}
