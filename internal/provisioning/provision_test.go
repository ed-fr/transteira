package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

func TestProvisionTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := goodCreate()
		capBytes := int64(5 << 30)
		in.MaxTransferBytes = &capBytes
		in.MaxStorageQuotaBytes = 2 << 30
		in.MaxTenants = 3
		tok := ev.mustToken(t, in)
		p := ev.mustAuth(t, tok.Secret)

		// No principal.
		_, err := ev.svc.ProvisionTenant(ctx, Principal{}, request("a.transfer.example.com", "a.admin"), mspIP)
		wantErr(t, "no principal", err, ErrInvalidToken)

		// FQDN normalization and suffix at a label boundary (T-276).
		for _, fqdn := range []string{"a.transfer.example.com:443", "192.0.2.1", "*.transfer.example.com", "", "a b.transfer.example.com"} {
			_, err := ev.svc.ProvisionTenant(ctx, p, request(fqdn, "x.admin"), mspIP)
			wantField(t, "fqdn "+fqdn, err, FieldFQDN)
		}
		for _, fqdn := range []string{
			"eviltransfer.example.com", "transfer.example.com", "a.transfer.example.org", "a.example.com", adminHost,
			"a.transfer.example.com.evil.example.net",
		} {
			_, err := ev.svc.ProvisionTenant(ctx, p, request(fqdn, "x.admin"), mspIP)
			wantScope(t, "suffix "+fqdn, err, FieldFQDN)
		}
		// Caps.
		r := request("a.transfer.example.com", "x.admin")
		r.StorageQuotaBytes = 2<<30 + 1
		_, err = ev.svc.ProvisionTenant(ctx, p, r, mspIP)
		wantScope(t, "quota", err, FieldStorageQuotaBytes)
		r = request("a.transfer.example.com", "x.admin")
		over := capBytes + 1
		r.MaxTransferBytes = &over
		_, err = ev.svc.ProvisionTenant(ctx, p, r, mspIP)
		wantScope(t, "transfer", err, FieldMaxTransferBytes)
		// A transfer limit of 0 or less is invalid, never defaulted (400).
		for _, v := range []int64{0, -1} {
			r.MaxTransferBytes = &v
			_, err = ev.svc.ProvisionTenant(ctx, p, r, mspIP)
			var inv *InvalidError
			if !errors.As(err, &inv) || inv.Field != FieldMaxTransferBytes {
				t.Errorf("transfer %d: %v", v, err)
			}
		}
		r = request("a.transfer.example.com", "x.admin")
		r.StorageQuotaBytes = 0
		_, err = ev.svc.ProvisionTenant(ctx, p, r, mspIP)
		wantErr(t, "zero quota", err, tenantadmin.ErrInvalid)
		r = request("a.transfer.example.com", "x.admin")
		r.DelegatedAdmin.Delivery = store.DeliveryCopy
		_, err = ev.svc.ProvisionTenant(ctx, p, r, mspIP)
		wantErr(t, "copy delivery", err, adminauth.ErrInvalid)
		if ev.mailer.count() != 0 || len(ev.pub.tenantEvents()) != 0 || ev.notifier.provisionedCount() != 0 {
			t.Fatal("a refused creation was announced")
		}

		// Created: setup, the cap of the token as default limit, no link.
		r = request("Entity-A.Transfer.Example.com.", "a.admin")
		got, err := ev.svc.ProvisionTenant(ctx, p, r, mspIP)
		if err != nil {
			t.Fatal(err)
		}
		stored, _ := ev.db.Tenants().Get(ctx, got.ID)
		if got.FQDN != "entity-a.transfer.example.com" || got.SetupState != tenant.SetupStateSetup || got.DelegatedAdminActivated ||
			!got.CreatedAt.Equal(testStart) || stored.ProvisionedBy != tok.ID || stored.MaxTransferBytes != capBytes ||
			stored.MaxTransferCeiling != capBytes || stored.SetupState != tenant.SetupStateSetup {
			t.Fatalf("ProvisionTenant = %+v (stored %+v)", got, stored)
		}
		if ev.mailer.count() != 1 || ev.mailer.mails[0].To != "a.admin@entity.example.com" {
			t.Errorf("activation mails = %+v", ev.mailer.mails)
		}
		// Audited with the token as actor, the real IP, never a link.
		evs := ev.auditEvents(t, ActionTenantProvisioned)
		if len(evs) != 1 || evs[0].ActorKind != store.ActorProvisioningToken || evs[0].Actor != tok.ID || evs[0].IP != mspIP ||
			evs[0].TenantID != got.ID || evs[0].ObjectID != string(got.ID) {
			t.Fatalf("tenant.provisioned = %+v", evs)
		}
		var d map[string]any
		if err := json.Unmarshal(evs[0].Details, &d); err != nil || d["provisionerPrefix"] != tok.Prefix ||
			d["delegatedAdmin"] != "a.admin" || d["fqdn"] != got.FQDN {
			t.Errorf("details = %s", evs[0].Details)
		}
		for _, action := range []string{"admin.created", "admin.invited"} {
			page, _ := ev.db.AuditEvents().List(ctx, store.AuditFilter{Action: action})
			if len(page.Items) != 1 || page.Items[0].ActorKind != store.ActorProvisioningToken || page.Items[0].Actor != tok.ID {
				t.Errorf("%s = %+v", action, page.Items)
			}
		}
		// Event and notice to the super admins (P50).
		pubs := ev.pub.tenantEvents()
		if len(pubs) != 1 || pubs[0].Type != events.TenantProvisioned || pubs[0].TenantID != string(got.ID) ||
			pubs[0].AdminPath != "/admin/tenants/"+string(got.ID) {
			t.Errorf("events = %+v", pubs)
		}
		want := tenantadmin.ProvisioningNotice{
			TenantID: got.ID, TenantName: got.Name, FQDN: got.FQDN, TokenID: tok.ID, TokenName: tok.Name, TokenPrefix: tok.Prefix,
			AdminUsername: "a.admin", ClientIP: mspIP, At: testStart,
		}
		if len(ev.notifier.provisioned) != 1 || ev.notifier.provisioned[0] != want {
			t.Errorf("notices = %+v, want %+v", ev.notifier.provisioned, want)
		}

		// Taken FQDN or username.
		_, err = ev.svc.ProvisionTenant(ctx, p, request("entity-a.transfer.example.com", "b.admin"), mspIP)
		wantErr(t, "fqdn taken", err, tenantadmin.ErrAlreadyExists)
		_, err = ev.svc.ProvisionTenant(ctx, p, request("entity-b.transfer.example.com", "a.admin"), mspIP)
		wantErr(t, "username taken", err, tenantadmin.ErrAlreadyExists)

		// Explicit limit, audit failure logged, no notifier.
		ev.faults("record")
		ev.svc.notifier = nil
		r = request("entity-b.transfer.example.com", "b.admin")
		limit := int64(1 << 30)
		r.MaxTransferBytes = &limit
		got2, err := ev.svc.ProvisionTenant(ctx, p, r, mspIP)
		if err != nil {
			t.Fatal(err)
		}
		if stored, _ := ev.db.Tenants().Get(ctx, got2.ID); stored.MaxTransferBytes != limit {
			t.Errorf("explicit limit = %d", stored.MaxTransferBytes)
		}
		if !strings.Contains(ev.logs.String(), "audit write failed") || len(ev.pub.tenantEvents()) != 2 {
			t.Errorf("audit failure not logged or event lost: %s", ev.logs)
		}
		ev.faults()
		ev.svc.notifier = ev.notifier

		// maxTenants reached: 403 with the empty pointer.
		if _, err := ev.svc.ProvisionTenant(ctx, p, request("entity-c.transfer.example.com", "c.admin"), mspIP); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.ProvisionTenant(ctx, p, request("entity-d.transfer.example.com", "d.admin"), mspIP)
		wantScope(t, "max tenants", err, FieldMaxTenants)

		// Revoked between the authentication and the creation: 401.
		other := ev.mustToken(t, goodCreate())
		po := ev.mustAuth(t, other.Secret)
		if err := ev.svc.RevokeToken(ctx, ev.super, other.ID, mspIP); err != nil {
			t.Fatal(err)
		}
		_, err = ev.svc.ProvisionTenant(ctx, po, request("entity-e.transfer.example.com", "e.admin"), mspIP)
		wantErr(t, "revoked meanwhile", err, ErrInvalidToken)
		if _, err := ev.db.Tenants().TenantByFQDN(ctx, "entity-e.transfer.example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant created by a revoked token: %v", err)
		}
	})
}

func TestProvisionTenantDefaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	tok := ev.mustToken(t, goodCreate()) // no transfer cap
	p := ev.mustAuth(t, tok.Secret)
	got, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP)
	if err != nil {
		t.Fatal(err)
	}
	if stored, _ := ev.db.Tenants().Get(ctx, got.ID); stored.MaxTransferBytes != tenant.MaxTransferLimit {
		t.Errorf("default limit = %d", stored.MaxTransferBytes)
	}
	// Without a cap, above 20 GiB is the tenant validation's refusal.
	above := tenant.MaxTransferLimit + 1
	r := request("b.transfer.example.com", "b.admin")
	r.MaxTransferBytes = &above
	_, err = ev.svc.ProvisionTenant(ctx, p, r, mspIP)
	wantErr(t, "above 20 GiB", err, tenantadmin.ErrInvalid)
}

// TestProvisionTenantNoSystemSMTP checks that nothing is created without
// the system SMTP (T-272).
func TestProvisionTenantNoSystemSMTP(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t), func(c *envConfig) { c.noMailer = true })
	p := ev.mustAuth(t, ev.mustToken(t, goodCreate()).Secret)
	_, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP)
	wantErr(t, "no smtp", err, adminauth.ErrSystemSMTPUnavailable)
	if list, _ := ev.svc.ListTenants(ctx, p); len(list) != 0 || len(ev.pub.tenantEvents()) != 0 {
		t.Errorf("created without system smtp: %+v", list)
	}
}

// fakeProvisioner answers err to every creation.
type fakeProvisioner struct{ err error }

func (f fakeProvisioner) ProvisionTenant(context.Context, adminauth.AuditActor, string, tenantadmin.TenantCreate, netip.Addr) (tenantadmin.TenantCreated, error) {
	return tenantadmin.TenantCreated{}, f.err
}

func TestProvisionTenantErrorMapping(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	p := ev.mustAuth(t, ev.mustToken(t, goodCreate()).Secret)
	for name, c := range map[string]struct {
		err   error
		check func(error) bool
	}{
		"rate limited": {fmt.Errorf("wrapped: %w", &store.ProvisioningRateLimitError{RetryAfter: 42 * time.Second}), func(err error) bool {
			var rl *RateLimitError
			return errors.As(err, &rl) && rl.RetryAfter == 42*time.Second && errors.Is(err, ErrRateLimited)
		}},
		"unusable":    {store.ErrProvisioningTokenUnusable, func(err error) bool { return errors.Is(err, ErrInvalidToken) }},
		"max tenants": {store.ErrProvisioningMaxTenants, func(err error) bool { return errors.Is(err, ErrScopeExceeded) }},
		"smtp": {adminauth.ErrSystemSMTPUnavailable, func(err error) bool {
			return errors.Is(err, adminauth.ErrSystemSMTPUnavailable)
		}},
		"other": {errBoom, func(err error) bool { return errors.Is(err, errBoom) }},
	} {
		ev.svc.tenants = fakeProvisioner{err: c.err}
		_, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP)
		if !c.check(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestProvisionedTenantsIsolation checks that a token only ever reaches the
// tenants it created (T-270).
func TestProvisionedTenantsIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		pa := ev.mustAuth(t, ev.mustToken(t, goodCreate()).Secret)
		pb := ev.mustAuth(t, ev.mustToken(t, goodCreate()).Secret)
		a1, err := ev.svc.ProvisionTenant(ctx, pa, request("a1.transfer.example.com", "a1.admin"), mspIP)
		if err != nil {
			t.Fatal(err)
		}
		ev.clock.Advance(time.Second)
		a2, err := ev.svc.ProvisionTenant(ctx, pa, request("a2.transfer.example.com", "a2.admin"), mspIP)
		if err != nil {
			t.Fatal(err)
		}
		b1, err := ev.svc.ProvisionTenant(ctx, pb, request("b1.transfer.example.com", "b1.admin"), mspIP)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "Plain", FQDN: "plain.transfer.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1, StorageQuotaBytes: 1,
		})
		if err != nil {
			t.Fatal(err)
		}

		list, err := ev.svc.ListTenants(ctx, pa)
		if err != nil || len(list) != 2 || list[0].ID != a2.ID || list[1].ID != a1.ID {
			t.Fatalf("ListTenants(A) = %+v, %v", list, err)
		}
		list, err = ev.svc.ListTenants(ctx, pb)
		if err != nil || len(list) != 1 || list[0].ID != b1.ID {
			t.Fatalf("ListTenants(B) = %+v, %v", list, err)
		}
		if got, err := ev.svc.GetTenant(ctx, pa, a1.ID); err != nil || got.ID != a1.ID || got.DelegatedAdminActivated {
			t.Errorf("GetTenant(A, a1) = %+v, %v", got, err)
		}
		for name, c := range map[string]struct {
			p   Principal
			tid tenant.ID
		}{
			"A reads B":           {pa, b1.ID},
			"B reads A":           {pb, a1.ID},
			"A reads super admin": {pa, plain.ID},
			"unknown":             {pa, tenant.ID(id.New(id.Tenant))},
			"malformed":           {pa, "ten_x"},
		} {
			_, err := ev.svc.GetTenant(ctx, c.p, c.tid)
			wantErr(t, name, err, ErrNotFound)
		}
		_, err = ev.svc.ListTenants(ctx, Principal{})
		wantErr(t, "list without principal", err, ErrInvalidToken)
		_, err = ev.svc.GetTenant(ctx, Principal{}, a1.ID)
		wantErr(t, "get without principal", err, ErrInvalidToken)

		ev.faults("listTenants", "getTenant")
		_, err = ev.svc.ListTenants(ctx, pa)
		wantErr(t, "list fault", err, errBoom)
		_, err = ev.svc.GetTenant(ctx, pa, a1.ID)
		wantErr(t, "get fault", err, errBoom)
	})
}

// TestProvisionTenantConcurrent proves that maxTenants holds when one
// token creates many tenants at once (T-271).
func TestProvisionTenantConcurrent(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := goodCreate()
		in.MaxTenants = 2
		p := ev.mustAuth(t, ev.mustToken(t, in).Secret)
		const n = 8
		var (
			wg          sync.WaitGroup
			mu          sync.Mutex
			ok, refused int
			others      []error
		)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := ev.svc.ProvisionTenant(ctx, p, request(fmt.Sprintf("c%d.transfer.example.com", i), fmt.Sprintf("c%d.admin", i)), mspIP)
				mu.Lock()
				defer mu.Unlock()
				var se *ScopeError
				switch {
				case err == nil:
					ok++
				case errors.As(err, &se) && se.Field == FieldMaxTenants:
					refused++
				default:
					others = append(others, err)
				}
			}()
		}
		wg.Wait()
		if len(others) > 0 || ok != 2 || refused != n-2 {
			t.Errorf("created %d, refused %d, other errors %v", ok, refused, others)
		}
		if list, _ := ev.svc.ListTenants(ctx, p); len(list) != 2 {
			t.Errorf("tenants = %d", len(list))
		}
	})
}
