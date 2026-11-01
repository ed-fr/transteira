package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestNew(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	for name, opts := range map[string]Options{
		"no confirmer": {Tenants: ev.tenants},
		"no tenants":   {Confirmer: ev.confirm},
	} {
		if _, err := New(ev.db, opts); err != errMissingDependency { //nolint:errorlint // exact sentinel
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := New(nil, Options{Confirmer: ev.confirm, Tenants: ev.tenants}); err != errMissingDependency { //nolint:errorlint // exact sentinel
		t.Errorf("no db: %v", err)
	}
	s, err := New(ev.db, Options{Confirmer: ev.confirm, Tenants: ev.tenants, AdminHosts: []string{"Bad Host", "Admin.Example.com."}})
	if err != nil {
		t.Fatal(err)
	}
	if s.logger == nil || s.now == nil || s.touches.Interval() != DefaultTouchInterval || s.touches.MaxTracked() != DefaultMaxTracked ||
		s.notifier != nil || len(s.adminHosts) != 2 || s.adminHosts[0] != "bad host" || s.adminHosts[1] != adminHost {
		t.Errorf("defaults: %+v", s)
	}
}

func TestCreateToken(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		delegated := principal(store.RoleDelegatedAdmin, "alice", tenant.ID(id.New(id.Tenant)))

		// Role first, then body, then TOTP: no attempt consumed before.
		_, err := ev.svc.CreateToken(ctx, adminauth.Principal{}, goodCreate(), "123456", "", mspIP)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
		_, err = ev.svc.CreateToken(ctx, delegated, goodCreate(), "123456", "", mspIP)
		wantErr(t, "delegated", err, ErrForbidden)
		past := testStart.Add(-time.Second)
		zero := int64(0)
		above := tenant.MaxTransferLimit + 1
		long := make([]string, 101)
		for i := range long {
			long[i] = fmt.Sprintf("10.%d.0.0/16", i)
		}
		for name, tc := range map[string]struct {
			mut   func(*TokenCreate)
			field string
		}{
			"empty name":       {func(c *TokenCreate) { c.Name = "" }, FieldName},
			"blank name":       {func(c *TokenCreate) { c.Name = "   " }, FieldName},
			"long name":        {func(c *TokenCreate) { c.Name = strings.Repeat("n", 101) }, FieldName},
			"control name":     {func(c *TokenCreate) { c.Name = "a\nb" }, FieldName},
			"bidi name":        {func(c *TokenCreate) { c.Name = "a\u202eb" }, FieldName},
			"invalid utf8":     {func(c *TokenCreate) { c.Name = "a\xffb" }, FieldName},
			"no cidr":          {func(c *TokenCreate) { c.AllowedCIDRs = nil }, FieldAllowedCIDRs},
			"too many cidrs":   {func(c *TokenCreate) { c.AllowedCIDRs = long }, FieldAllowedCIDRs},
			"bad cidr":         {func(c *TokenCreate) { c.AllowedCIDRs = []string{"198.51.100.1"} }, FieldAllowedCIDRs},
			"v4 any":           {func(c *TokenCreate) { c.AllowedCIDRs = []string{"0.0.0.0/0"} }, FieldAllowedCIDRs},
			"v6 any":           {func(c *TokenCreate) { c.AllowedCIDRs = []string{"2001:db8::/32", "::/0"} }, FieldAllowedCIDRs},
			"v4 mapped":        {func(c *TokenCreate) { c.AllowedCIDRs = []string{"::ffff:0.0.0.0/96"} }, FieldAllowedCIDRs},
			"duplicate cidr":   {func(c *TokenCreate) { c.AllowedCIDRs = []string{"198.51.100.0/24", "198.51.100.7/24"} }, FieldAllowedCIDRs},
			"no suffix":        {func(c *TokenCreate) { c.AllowedFQDNSuffixes = nil }, FieldAllowedFQDNSuffixes},
			"too many suffix":  {func(c *TokenCreate) { c.AllowedFQDNSuffixes = make([]string, 101) }, FieldAllowedFQDNSuffixes},
			"suffix no dot":    {func(c *TokenCreate) { c.AllowedFQDNSuffixes = []string{"example.com"} }, FieldAllowedFQDNSuffixes},
			"suffix tld":       {func(c *TokenCreate) { c.AllowedFQDNSuffixes = []string{".com"} }, FieldAllowedFQDNSuffixes},
			"suffix admin":     {func(c *TokenCreate) { c.AllowedFQDNSuffixes = []string{".example.com"} }, FieldAllowedFQDNSuffixes},
			"duplicate suffix": {func(c *TokenCreate) { c.AllowedFQDNSuffixes = []string{".a.example.org", ".A.example.org."} }, FieldAllowedFQDNSuffixes},
			"zero quota":       {func(c *TokenCreate) { c.MaxStorageQuotaBytes = 0 }, FieldMaxStorageQuotaBytes},
			"zero transfer":    {func(c *TokenCreate) { c.MaxTransferBytes = &zero }, FieldMaxTransferBytes},
			"transfer > 20GiB": {func(c *TokenCreate) { c.MaxTransferBytes = &above }, FieldMaxTransferBytes},
			"zero tenants":     {func(c *TokenCreate) { c.MaxTenants = 0 }, FieldMaxTenantsCap},
			"many tenants":     {func(c *TokenCreate) { c.MaxTenants = MaxTenantsLimit + 1 }, FieldMaxTenantsCap},
			"expired":          {func(c *TokenCreate) { c.ExpiresAt = &past }, FieldExpiresAt},
			"expires now":      {func(c *TokenCreate) { c.ExpiresAt = &testStart }, FieldExpiresAt},
		} {
			in := goodCreate()
			tc.mut(&in)
			_, err := ev.svc.CreateToken(ctx, ev.super, in, "123456", "", mspIP)
			wantField(t, name, err, tc.field)
		}
		if n := ev.confirm.count(); n != 0 {
			t.Fatalf("the TOTP was checked %d times before the role and body", n)
		}

		// A refused re-confirmation creates nothing.
		ev.confirm.err = adminauth.ErrInvalidCredentials
		_, err = ev.svc.CreateToken(ctx, ev.super, goodCreate(), "000000", "", mspIP)
		wantErr(t, "wrong code", err, adminauth.ErrInvalidCredentials)
		ev.confirm.err = nil
		// The account confirmed is no longer a super admin.
		ev.confirm.acc = principal(store.RoleDelegatedAdmin, "demoted").Admin
		_, err = ev.svc.CreateToken(ctx, ev.super, goodCreate(), "123456", "", mspIP)
		wantErr(t, "demoted", err, ErrForbidden)
		ev.confirm.acc = ev.super.Admin
		if list, _ := ev.svc.ListTokens(ctx, ev.super); len(list) != 0 {
			t.Fatalf("refused creations stored %d tokens", len(list))
		}
		if len(ev.pub.all()) != 0 || len(ev.notifier.tokenNotices()) != 0 {
			t.Fatalf("refused creations published %+v, notified %+v", ev.pub.all(), ev.notifier.tokenNotices())
		}

		// Created: the secret once, its hash stored, the audit without it.
		in := goodCreate()
		capBytes := int64(10 << 30)
		expires := testStart.Add(30 * 24 * time.Hour)
		in.MaxTransferBytes, in.ExpiresAt = &capBytes, &expires
		in.Name = "MSP it@msp.example.com"
		got, err := ev.svc.CreateToken(ctx, ev.super, in, "123456", "", mspIP)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := ev.db.ProvisioningTokens().Get(ctx, got.ID)
		sum := sha256.Sum256([]byte(got.Secret))
		if err != nil || !ValidSecret(got.Secret) || got.Prefix != got.Secret[:PrefixLen] || string(stored.TokenHash) != string(sum[:]) ||
			!id.Valid(id.ProvisioningToken, got.ID) || got.CreatedBy != ev.super.Admin.ID || got.MaxTransferBytes != capBytes ||
			!got.ExpiresAt.Equal(expires) || got.AllowedFQDNSuffixes[0] != ".transfer.example.com" ||
			got.AllowedCIDRs[0] != netip.MustParsePrefix("198.51.100.0/24") || got.TenantsCreated != 0 || got.MaxTenants != 5 ||
			got.MaxStorageQuotaBytes != 1<<40 || !got.CreatedAt.Equal(testStart) {
			t.Fatalf("CreateToken = %+v (stored %+v, %v)", got, stored, err)
		}
		evs := ev.auditEvents(t, ActionTokenCreated)
		if len(evs) != 1 || evs[0].Actor != "root" || evs[0].ActorKind != store.ActorAdmin || evs[0].ObjectID != got.ID ||
			evs[0].TenantID != "" || evs[0].IP != mspIP || strings.Contains(string(evs[0].Details), got.Secret) ||
			strings.Contains(string(evs[0].Details), "@") {
			t.Fatalf("audit = %+v", evs)
		}
		var d map[string]any
		if err := json.Unmarshal(evs[0].Details, &d); err != nil || d["prefix"] != got.Prefix || d["maxTenants"] != 5.0 ||
			d["maxTransferBytes"] != float64(capBytes) || d["expiresAt"] == nil || d["allowedCidrs"] == nil || d["cidrCount"] != 1.0 {
			t.Errorf("details = %s", evs[0].Details)
		}
		// The super admins are told (T-275): a system event and a notice,
		// neither with the secret.
		pubs := ev.pub.all()
		if len(pubs) != 1 || pubs[0].Type != events.ProvisioningTokenCreated || pubs[0].Severity != events.SeverityInfo ||
			pubs[0].TenantID != "" || !pubs[0].OccurredAt.Equal(testStart) || pubs[0].Addresses != nil ||
			pubs[0].AdminPath != events.AdminPathProvisioningTokens || pubs[0].Counts["cidrCount"] != 1 ||
			pubs[0].Counts["suffixCount"] != 1 || pubs[0].Counts["maxTenants"] != 5 ||
			pubs[0].Counts["maxStorageQuotaBytes"] != 1<<40 || strings.Contains(fmt.Sprintf("%+v", pubs[0]), got.Secret) {
			t.Fatalf("published = %+v", pubs)
		}
		notes := ev.notifier.tokenNotices()
		if len(notes) != 1 || notes[0].TokenID != got.ID || notes[0].TokenName != in.Name || notes[0].TokenPrefix != got.Prefix ||
			notes[0].CreatedBy != "root" || notes[0].ClientIP != mspIP || !notes[0].At.Equal(testStart) ||
			notes[0].CIDRCount != 1 || notes[0].SuffixCount != 1 || notes[0].MaxTenants != 5 ||
			notes[0].MaxStorageQuotaBytes != 1<<40 || !notes[0].ExpiresAt.Equal(expires) ||
			strings.Contains(fmt.Sprintf("%+v", notes[0]), got.Secret) {
			t.Fatalf("notices = %+v", notes)
		}

		// A wide scope: the audit keeps the counts only.
		wide := goodCreate()
		wide.AllowedCIDRs = long[:100]
		wide.AllowedFQDNSuffixes = make([]string, 100)
		for i := range wide.AllowedFQDNSuffixes {
			wide.AllowedFQDNSuffixes[i] = fmt.Sprintf(".client-%03d-%s.example.org", i, strings.Repeat("x", 40))
		}
		if _, err := ev.svc.CreateToken(ctx, ev.super, wide, "123456", "", mspIP); err != nil {
			t.Fatalf("wide scope: %v", err)
		}
		evs = ev.auditEvents(t, ActionTokenCreated)
		if len(evs) != 2 || strings.Contains(string(evs[1].Details), "allowedCidrs") || !strings.Contains(string(evs[1].Details), `"cidrCount":100`) {
			t.Errorf("wide details = %s", evs[1].Details)
		}
	})
}

func TestCreateTokenFailures(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	old := newSecret
	newSecret = func() (string, error) { return "", errBoom }
	_, err := ev.svc.CreateToken(ctx, ev.super, goodCreate(), "123456", "", mspIP)
	newSecret = old
	wantErr(t, "random failure", err, errBoom)
	for _, m := range []string{"createToken", "recordTx"} {
		ev.faults(m)
		_, err := ev.svc.CreateToken(ctx, ev.super, goodCreate(), "123456", "", mspIP)
		wantErr(t, m, err, errBoom)
	}
	ev.faults()
	if list, _ := ev.svc.ListTokens(ctx, ev.super); len(list) != 0 {
		t.Errorf("failed creations stored %d tokens", len(list))
	}
	if len(ev.pub.all()) != 0 || len(ev.notifier.tokenNotices()) != 0 {
		t.Errorf("failed creations published %+v, notified %+v", ev.pub.all(), ev.notifier.tokenNotices())
	}
	// Without a notifier, the event is still published.
	ev.svc.notifier = nil
	if _, err := ev.svc.CreateToken(ctx, ev.super, goodCreate(), "123456", "", mspIP); err != nil {
		t.Fatal(err)
	}
	if pubs := ev.pub.all(); len(pubs) != 1 || pubs[0].Type != events.ProvisioningTokenCreated || len(ev.notifier.tokenNotices()) != 0 {
		t.Errorf("without notifier: published %+v", pubs)
	}
}

func TestListAndRevokeTokens(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		delegated := principal(store.RoleDelegatedAdmin, "alice", tenant.ID(id.New(id.Tenant)))
		first := ev.mustToken(t, goodCreate())
		ev.clock.Advance(time.Second)
		second := ev.mustToken(t, goodCreate())

		_, err := ev.svc.ListTokens(ctx, delegated)
		wantErr(t, "list delegated", err, ErrForbidden)
		list, err := ev.svc.ListTokens(ctx, ev.super)
		if err != nil || len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
			t.Fatalf("ListTokens = %+v, %v", list, err)
		}

		// Revoke: role, identifiers, idempotence, audit once.
		wantErr(t, "revoke delegated", ev.svc.RevokeToken(ctx, delegated, first.ID, mspIP), ErrForbidden)
		wantErr(t, "revoke malformed", ev.svc.RevokeToken(ctx, ev.super, "tok_x", mspIP), ErrNotFound)
		wantErr(t, "revoke unknown", ev.svc.RevokeToken(ctx, ev.super, id.New(id.ProvisioningToken), mspIP), ErrNotFound)
		ev.mustAuth(t, first.Secret)
		if err := ev.svc.RevokeToken(ctx, ev.super, first.ID, mspIP); err != nil {
			t.Fatal(err)
		}
		if err := ev.svc.RevokeToken(ctx, ev.super, first.ID, mspIP); err != nil {
			t.Fatalf("revoke again: %v", err)
		}
		evs := ev.auditEvents(t, ActionTokenRevoked)
		if len(evs) != 1 || evs[0].ObjectID != first.ID || evs[0].Actor != "root" || !strings.Contains(string(evs[0].Details), first.Prefix) {
			t.Fatalf("revocation audit = %+v", evs)
		}
		_, err = ev.svc.Authenticate(ctx, first.Secret, mspIP)
		wantReason(t, "revoked", err, ReasonRevoked)
		list, _ = ev.svc.ListTokens(ctx, ev.super)
		if len(list) != 2 || list[1].RevokedAt.IsZero() || !list[0].RevokedAt.IsZero() {
			t.Errorf("a revoked token must stay listed: %+v", list)
		}

		// Store failures.
		ev.faults("listTokens", "revokeToken")
		_, err = ev.svc.ListTokens(ctx, ev.super)
		wantErr(t, "list fault", err, errBoom)
		wantErr(t, "revoke fault", ev.svc.RevokeToken(ctx, ev.super, second.ID, mspIP), errBoom)
		ev.faults("recordTx")
		wantErr(t, "revoke audit fault", ev.svc.RevokeToken(ctx, ev.super, second.ID, mspIP), errBoom)
		ev.faults()
		ev.mustAuth(t, second.Secret) // the failed revocation was rolled back
	})
}
