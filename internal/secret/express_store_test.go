package secret

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestExpressWithStore runs the express secrets on the real store, audit
// writer and abuse reports, on every engine: the anonymous and token
// creations with their limits (per client, per token, tenant cap), the
// read gate of a closed service, the reports, the lookup from a pasted
// link and the purge, each confined to its tenant.
func TestExpressWithStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Millisecond)
		db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		kr, err := masterkey.New(masterkeytest.Key(t, "secret"), nil)
		if err != nil {
			t.Fatal(err)
		}
		vault := masterkey.NewVault(db, kr, nil)
		newTenant := func(fqdn string) *tenant.Tenant {
			tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
				SetupState: tenant.SetupStateActive, Name: fqdn, FQDN: fqdn, DefaultLanguage: "en",
				MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
			})
			if err != nil {
				t.Fatal(err)
			}
			return tn
		}
		a, b := newTenant("transfer.entity-a.example.com"), newTenant("transfer.entity-b.example.com")
		settings := tenant.ExpressSettings{Enabled: true, PerHourPerIP: 2, PerHourPerToken: 1, MaxPending: 2}
		if a, err = db.Tenants().SetExpressSettings(ctx, a.ID, settings); err != nil {
			t.Fatal(err)
		}
		if b, err = db.Tenants().SetExpressSettings(ctx, b.ID, settings); err != nil {
			t.Fatal(err)
		}
		tokID := id.New(id.APIToken)
		hash := sha256.Sum256([]byte(tokID))
		if _, err := db.APITokens().Create(ctx, a.ID, store.APIToken{
			ID: tokID, Name: "vault", Prefix: "tt_Va", TokenHash: hash[:], CreatedBy: "root",
			AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, ExpressAllowed: true,
		}); err != nil {
			t.Fatal(err)
		}
		seclog, alerts := &fakeSeclog{}, &fakeAlerts{}
		newService := func(kill bool) *Service {
			svc, err := New(Deps{
				Secrets: db.Secrets(vault), Creators: &fakeCreators{}, Scrubber: vault, Files: &fakeFiles{}, SecurityLog: seclog,
				Directory: StoreDirectory{DB: db}, Notifier: &fakeNotifier{}, Mailer: &fakeMailer{},
			}, Options{
				Audit: audit.New(db), Now: func() time.Time { return now }, ExpressKillSwitch: kill,
				AbuseReports: db.AbuseReports(), AbuseNotifier: alerts, EventThrottle: &fakeLimiter{},
			})
			if err != nil {
				t.Fatal(err)
			}
			return svc
		}
		svc, killed := newService(false), newService(true)
		ip1, ip2 := ExpressCreator{ClientIP: netip.MustParseAddr("203.0.113.1")}, ExpressCreator{ClientIP: netip.MustParseAddr("203.0.113.2")}
		tok := ExpressCreator{ClientIP: netip.MustParseAddr("192.0.2.40"), APITokenID: tokID, ExpressAllowed: true}
		create := func(svc *Service, tn *tenant.Tenant, c ExpressCreator) (Created, sealed, error) {
			s, _ := seal(t, "a third-party text", "")
			out, err := svc.CreateExpress(ctx, tn, c, s.expressRequest())
			return out, s, err
		}

		// An anonymous secret, read once; its token is unknown under B.
		first, s1, err := create(svc, a, ip1)
		if err != nil || first.State != store.SecretActive || !first.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("anonymous creation = %+v, %v", first, err)
		}
		st, err := svc.Status(ctx, a, ip1.ClientIP, first.Token)
		if err != nil || !st.Express || !st.Anonymous || st.Passphrase != nil || st.FileSize != 0 {
			t.Fatalf("status = %+v, %v", st, err)
		}
		if _, err := svc.Status(ctx, b, ip1.ClientIP, first.Token); !errors.Is(err, ErrNotFound) {
			t.Errorf("status under B: %v", err)
		}
		if out, err := svc.Reveal(ctx, a, ip1.ClientIP, first.Token, s1.keyProof, s1.proof); err != nil || out.EncryptedText != s1.text {
			t.Fatalf("reveal = %+v, %v", out, err)
		}
		// The reader reports it after reading; not under B.
		if err := svc.ReportAbuse(ctx, a, ip1.ClientIP, first.Token, AbuseReportRequest{Category: "phishing", Message: "fake bank"}); err != nil {
			t.Fatalf("report: %v", err)
		}
		if err := svc.ReportAbuse(ctx, b, ip1.ClientIP, first.Token, AbuseReportRequest{Category: "phishing"}); !errors.Is(err, ErrNotFound) {
			t.Errorf("report under B: %v", err)
		}
		reports, err := db.AbuseReports().List(ctx, a.ID, "", 10, "")
		if err != nil || len(reports.Items) != 1 || reports.Items[0].SecretID != first.ID || reports.Items[0].TransferID != "" ||
			len(alerts.reports) != 1 || alerts.reports[0].ID != reports.Items[0].ID {
			t.Fatalf("reports = %+v, %v, alerts %+v", reports.Items, err, alerts.reports)
		}

		// The limits: 2 per client and hour, a cap of 2 live secrets for
		// the anonymous creations, 1 per token and hour.
		second, _, err := create(svc, a, ip1)
		if err != nil {
			t.Fatal(err)
		}
		var rl *RateLimitError
		if _, _, err := create(svc, a, ip1); !errors.As(err, &rl) || rl.RetryAfter != time.Hour {
			t.Fatalf("per client: %v", err)
		}
		third, _, err := create(svc, a, ip2)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := create(svc, a, ip2); !errors.Is(err, ErrExpressLimit) {
			t.Fatalf("cap: %v", err)
		}
		byToken, sTok, err := create(svc, a, tok)
		if err != nil {
			t.Fatalf("token over the anonymous cap: %v", err)
		}
		if _, _, err := create(svc, a, tok); !errors.As(err, &rl) || rl.RetryAfter != time.Hour {
			t.Fatalf("per token: %v", err)
		}
		// B has its own counters and cap.
		if _, _, err := create(svc, b, ip1); err != nil {
			t.Fatalf("under B: %v", err)
		}

		// The anonymous mode off: anonymous secrets closed, token ones
		// readable; reports still accepted.
		closed := settings
		closed.Enabled = false
		if a, err = db.Tenants().SetExpressSettings(ctx, a.ID, closed); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Status(ctx, a, ip1.ClientIP, second.Token); !errors.Is(err, ErrExpressDisabled) {
			t.Errorf("anonymous secret while closed: %v", err)
		}
		if st, err := svc.Status(ctx, a, ip1.ClientIP, byToken.Token); err != nil || !st.Express || st.Anonymous {
			t.Errorf("token secret while closed: %+v, %v", st, err)
		}
		if _, _, err := create(svc, a, ip2); !errors.Is(err, ErrExpressDisabled) {
			t.Errorf("anonymous creation while closed: %v", err)
		}
		if err := svc.ReportAbuse(ctx, a, ip2.ClientIP, second.Token, AbuseReportRequest{Category: "spam"}); err != nil {
			t.Errorf("report while closed: %v", err)
		}
		// The kill switch closes the token secrets too, consuming nothing.
		if _, err := killed.Reveal(ctx, a, tok.ClientIP, byToken.Token, sTok.keyProof, sTok.proof); !errors.Is(err, ErrExpressDisabled) {
			t.Errorf("token secret under the kill switch: %v", err)
		}
		if _, _, err := create(killed, a, tok); !errors.Is(err, ErrExpressDisabled) {
			t.Errorf("token creation under the kill switch: %v", err)
		}
		if out, err := svc.Reveal(ctx, a, tok.ClientIP, byToken.Token, sTok.keyProof, sTok.proof); err != nil || out.EncryptedText != sTok.text {
			t.Errorf("token secret after the kill switch: %+v, %v", out, err)
		}
		if a, err = db.Tenants().SetExpressSettings(ctx, a.ID, settings); err != nil {
			t.Fatal(err)
		}

		// The lookup from a pasted link, in its tenant only.
		link := "https://" + a.FQDN + "/s/" + second.Token + "#k=" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		admin := AdminActor{Username: "delegate", IP: netip.MustParseAddr("10.0.0.5")}
		found, err := svc.Lookup(ctx, a, admin, link)
		if err != nil || found.ID != second.ID || !found.Express || !found.Anonymous() || found.State != store.SecretActive {
			t.Fatalf("lookup = %+v, %v", found, err)
		}
		if _, err := svc.Lookup(ctx, b, admin, link); !errors.Is(err, ErrNotFound) {
			t.Errorf("lookup under B: %v", err)
		}

		// The purge ends the live anonymous secrets of A only.
		if n, err := svc.PurgeExpress(ctx, a, admin); err != nil || n != 2 {
			t.Fatalf("purge = %d, %v", n, err)
		}
		var gone *GoneError
		for _, c := range []Created{second, third} {
			if _, err := svc.Status(ctx, a, ip1.ClientIP, c.Token); !errors.As(err, &gone) || gone.Reason != ReasonDeleted {
				t.Errorf("after the purge: %v", err)
			}
		}
		if err := svc.ReportAbuse(ctx, a, ip2.ClientIP, third.Token, AbuseReportRequest{Category: "spam"}); !errors.As(err, &gone) {
			t.Errorf("report after the purge: %v", err)
		}
		if n, err := svc.PurgeExpress(ctx, b, admin); err != nil || n != 1 {
			t.Errorf("purge of B = %d, %v", n, err)
		}
		if n, err := svc.PurgeExpress(ctx, a, admin); err != nil || n != 0 {
			t.Errorf("second purge = %d, %v", n, err)
		}

		want := []string{
			"secret_invalid", "secret_invalid", // the status and the report under B
			"rate_limited scope=express_ip", "express_refused reason=limit", "rate_limited scope=express_token",
			"express_refused reason=disabled", "express_refused reason=disabled",
		}
		if got := seclog.types(); !slices.Equal(got, want) {
			t.Errorf("security log = %v, want %v", got, want)
		}
		page, err := db.AuditEvents().List(ctx, store.AuditFilter{TenantID: a.ID, Limit: store.MaxPageSize})
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[audit.Action][]store.AuditActorKind{}
		for _, ev := range page.Items {
			kinds[audit.Action(ev.Action)] = append(kinds[audit.Action(ev.Action)], ev.ActorKind)
		}
		if got := kinds[audit.ActionSecretCreated]; len(got) != 4 || !slices.Contains(got, store.ActorAnonymous) || !slices.Contains(got, store.ActorAPIToken) {
			t.Errorf("secret.created actors = %v", got)
		}
		for _, action := range []audit.Action{
			audit.ActionAPITokenUsed, audit.ActionSecretRevealed, audit.ActionAbuseReported, audit.ActionSecretLookedUp, audit.ActionSecretExpressPurged,
		} {
			if len(kinds[action]) == 0 {
				t.Errorf("audit misses %s: %v", action, kinds)
			}
		}
	})
}
