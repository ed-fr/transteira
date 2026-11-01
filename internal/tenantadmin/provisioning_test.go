package tenantadmin

import (
	"context"
	"crypto/rand"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// recordingPublisher records the published events.
type recordingPublisher struct {
	mu  sync.Mutex
	evs []events.Event
}

func (p *recordingPublisher) Publish(ev events.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evs = append(p.evs, ev)
}

func (p *recordingPublisher) all() []events.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.evs)
}

// recordingNotifier records the notices to the super admins.
type recordingNotifier struct {
	mu          sync.Mutex
	provisioned []ProvisioningNotice
	completed   []ProvisioningNotice
}

func (n *recordingNotifier) TenantProvisioned(_ context.Context, x ProvisioningNotice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.provisioned = append(n.provisioned, x)
}

func (n *recordingNotifier) TenantSetupCompleted(_ context.Context, x ProvisioningNotice) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.completed = append(n.completed, x)
}

// TokenCreated is never called by this package (the provisioning service
// notifies the token creations).
func (*recordingNotifier) TokenCreated(context.Context, ProvisioningTokenNotice) {}

// newProvisioningToken stores a provisioning token allowing maxTenants
// tenants.
func newProvisioningToken(t *testing.T, db *store.DB, maxTenants int) store.ProvisioningToken {
	t.Helper()
	hash := make([]byte, store.TokenHashSize)
	if _, err := rand.Read(hash); err != nil {
		t.Fatal(err)
	}
	tok, err := db.ProvisioningTokens().Create(context.Background(), store.ProvisioningToken{
		ID: id.New(id.ProvisioningToken), Name: "MSP", Prefix: "ttp_AbCd", TokenHash: hash,
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, AllowedFQDNSuffixes: []string{".transfer.example.com"},
		MaxStorageQuotaBytes: 1 << 40, MaxTenants: maxTenants, CreatedBy: id.New(id.Admin),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// provisionInput returns a valid provisioning input under fqdn.
func provisionInput(fqdn, username string) TenantCreate {
	return TenantCreate{
		Name: "Prov " + fqdn, FQDN: fqdn, DefaultLanguage: "fr", StorageQuotaBytes: 1 << 30, MaxTransferBytes: 1 << 30,
		DelegatedAdmin: &adminauth.DelegatedAdmin{Username: username, Email: username + "@entity-p.example.com", Language: "fr"},
	}
}

func TestProvisionTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		tok := newProvisioningToken(t, ev.db, 2)
		actor := adminauth.AuditActor{Kind: store.ActorProvisioningToken, ID: tok.ID}

		// Without an admin creator: refused.
		_, err := ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput("p0.transfer.example.com", "p0.admin"), clientIP)
		wantErr(t, "no admin creator", err, errNoAdminCreator)

		// Without the system SMTP: nothing is created (T-272).
		ev.withAdmins(t, false)
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput("p1.transfer.example.com", "p1.admin"), clientIP)
		wantErr(t, "no smtp", err, adminauth.ErrSystemSMTPUnavailable)
		ev.tenantGone(t, "p1.transfer.example.com")

		mailer := ev.withAdmins(t, true)
		// Validation, as CreateTenant; delegated admin required, setup only.
		for name, tc := range map[string]struct {
			mut   func(*TenantCreate)
			field string
		}{
			"no admin":   {func(in *TenantCreate) { in.DelegatedAdmin = nil }, FieldDelegatedAdmin},
			"active":     {func(in *TenantCreate) { in.SetupState = tenant.SetupStateActive }, FieldSetupState},
			"name":       {func(in *TenantCreate) { in.Name = "" }, FieldName},
			"fqdn":       {func(in *TenantCreate) { in.FQDN = "bad host:1" }, FieldFQDN},
			"admin host": {func(in *TenantCreate) { in.FQDN = adminHost }, FieldFQDN},
			"language":   {func(in *TenantCreate) { in.DefaultLanguage = "xx" }, FieldDefaultLanguage},
			"quota":      {func(in *TenantCreate) { in.StorageQuotaBytes = 0 }, FieldStorageQuotaBytes},
			"transfer":   {func(in *TenantCreate) { in.MaxTransferBytes = tenant.MaxTransferLimit + 1 }, FieldMaxTransferBytes},
		} {
			in := provisionInput("p2.transfer.example.com", "p2.admin")
			tc.mut(&in)
			_, err := ev.svc.ProvisionTenant(ctx, actor, tok.ID, in, clientIP)
			wantInvalid(t, name, err, tc.field)
		}
		in := provisionInput("p2.transfer.example.com", "p2.admin")
		in.BackgroundPreset = ptr("nope")
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, in, clientIP)
		wantErr(t, "preset", err, ErrUnknownBackgroundPreset)
		in = provisionInput("p2.transfer.example.com", "p2.admin")
		in.DelegatedAdmin.Delivery = store.DeliveryCopy
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, in, clientIP)
		wantErr(t, "copy delivery", err, adminauth.ErrInvalid)
		ev.tenantGone(t, "p2.transfer.example.com")

		// Created in setup, with its admin, the link mailed after commit.
		in = provisionInput("P3.Transfer.Example.com.", "p3.admin")
		in.SetupState = tenant.SetupStateSetup
		got, err := ev.svc.ProvisionTenant(ctx, actor, tok.ID, in, clientIP)
		mustNoErr(t, "provision", err)
		if got.SetupState != tenant.SetupStateSetup || got.FQDN != "p3.transfer.example.com" || got.DelegatedAdmin == nil ||
			got.DelegatedAdmin.Activation.URL != "" || got.DelegatedAdmin.Activation.Delivery != store.DeliveryMail ||
			got.MaxTransferCeiling != 1<<30 || len(mailer.mails) != 1 || !mailer.committed[0] {
			t.Fatalf("provisioned = %+v, mails %+v", got, mailer.mails)
		}
		if stored, _ := ev.db.Tenants().Get(ctx, got.ID); stored.ProvisionedBy != tok.ID {
			t.Errorf("ProvisionedBy = %q", stored.ProvisionedBy)
		}
		if !ev.cache.sawHost("p3.transfer.example.com") {
			t.Error("the resolution cache was not invalidated")
		}
		if n := len(ev.auditEvents(t, got.ID, ActionTenantCreated)); n != 0 {
			t.Errorf("tenant.created recorded %d times for a provisioned tenant", n)
		}

		// FQDN or username taken.
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput(hostA, "p4.admin"), clientIP)
		wantErr(t, "fqdn taken", err, ErrAlreadyExists)
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput("p4.transfer.example.com", "p3.admin"), clientIP)
		wantErr(t, "username taken", err, ErrAlreadyExists)
		ev.tenantGone(t, "p4.transfer.example.com")

		// The caps of the store pass through.
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput("p5.transfer.example.com", "p5.admin"), clientIP)
		mustNoErr(t, "second", err)
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput("p6.transfer.example.com", "p6.admin"), clientIP)
		wantErr(t, "max tenants", err, store.ErrProvisioningMaxTenants)
		_, err = ev.svc.ProvisionTenant(ctx, actor, id.New(id.ProvisioningToken), provisionInput("p6.transfer.example.com", "p6.admin"), clientIP)
		wantErr(t, "unknown token", err, store.ErrProvisioningTokenUnusable)
		ev.tenantGone(t, "p6.transfer.example.com")
		if len(mailer.mails) != 2 {
			t.Errorf("mails = %d, want 2", len(mailer.mails))
		}

		// Store and view failures.
		ev.faults("createProvisionedTenant")
		_, err = ev.svc.ProvisionTenant(ctx, actor, tok.ID, provisionInput("p7.transfer.example.com", "p7.admin"), clientIP)
		wantErr(t, "store fault", err, errBoom)
		tok2 := newProvisioningToken(t, ev.db, 5)
		ev.faults("usedBytes")
		_, err = ev.svc.ProvisionTenant(ctx, adminauth.AuditActor{Kind: store.ActorProvisioningToken, ID: tok2.ID}, tok2.ID,
			provisionInput("p8.transfer.example.com", "p8.admin"), clientIP)
		wantErr(t, "view fault", err, errBoom)
	})
}

func TestCompleteSetupProvisioned(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		pub := &recordingPublisher{}
		notifier := &recordingNotifier{}
		ev := newEnv(t, e, func(o *Options) { o.Events, o.Notifier = pub, notifier })
		tok := newProvisioningToken(t, ev.db, 5)
		provision := func(fqdn string) *tenant.Tenant {
			t.Helper()
			tn, err := ev.db.Tenants().CreateProvisioned(ctx, tok.ID, &tenant.Tenant{
				SetupState: tenant.SetupStateSetup, Name: "Prov " + fqdn, FQDN: fqdn, DefaultLanguage: "en",
				MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 30,
			}, nil)
			mustNoErr(t, "create provisioned", err)
			return tn
		}

		// A tenant of the super admin tells nobody.
		plain, err := ev.db.Tenants().Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateSetup, Name: "Plain", FQDN: "plain.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 30,
		})
		mustNoErr(t, "plain", err)
		_, err = ev.svc.CompleteSetup(ctx, ev.super, plain.ID, true, false, clientIP)
		mustNoErr(t, "complete plain", err)
		if len(pub.all()) != 0 || len(notifier.completed) != 0 {
			t.Fatalf("a plain tenant was announced: %+v %+v", pub.all(), notifier.completed)
		}

		// A provisioned tenant: event and notice with the token.
		p1 := provision("c1.transfer.example.com")
		_, err = ev.svc.CompleteSetup(ctx, ev.super, p1.ID, true, false, clientIP)
		mustNoErr(t, "complete provisioned", err)
		evs := pub.all()
		if len(evs) != 1 || evs[0].Type != events.TenantSetupCompleted || evs[0].TenantID != string(p1.ID) ||
			evs[0].Severity != events.SeverityInfo || evs[0].AdminPath != "/admin/tenants/"+string(p1.ID) ||
			!evs[0].OccurredAt.Equal(testStart) {
			t.Fatalf("events = %+v", evs)
		}
		want := ProvisioningNotice{
			TenantID: p1.ID, TenantName: p1.Name, FQDN: p1.FQDN, TokenID: tok.ID, TokenName: "MSP", TokenPrefix: "ttp_AbCd",
			ClientIP: clientIP, At: testStart, Forced: true,
		}
		if len(notifier.completed) != 1 || notifier.completed[0] != want {
			t.Fatalf("notices = %+v, want %+v", notifier.completed, want)
		}

		// The token cannot be read: the notice goes without its name.
		p2 := provision("c2.transfer.example.com")
		ev.faults("provisioningToken")
		ev.clock.Advance(time.Minute)
		_, err = ev.svc.CompleteSetup(ctx, ev.super, p2.ID, true, false, clientIP)
		mustNoErr(t, "complete without token", err)
		if len(notifier.completed) != 2 || notifier.completed[1].TokenID != tok.ID || notifier.completed[1].TokenName != "" {
			t.Fatalf("notices = %+v", notifier.completed)
		}

		// Without notifier, the event is still published.
		ev.svc.notifier = nil
		p3 := provision("c3.transfer.example.com")
		_, err = ev.svc.CompleteSetup(ctx, ev.super, p3.ID, true, false, clientIP)
		mustNoErr(t, "complete without notifier", err)
		if len(pub.all()) != 3 || len(notifier.completed) != 2 {
			t.Fatalf("events %d notices %d", len(pub.all()), len(notifier.completed))
		}
	})
}

func TestAdminPathTenant(t *testing.T) {
	if got := AdminPathTenant("ten_X"); got != "/admin/tenants/ten_X" {
		t.Errorf("AdminPathTenant = %q", got)
	}
}
