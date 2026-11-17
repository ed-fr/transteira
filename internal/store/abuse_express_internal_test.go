package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestAbuseReportsOnSecrets covers the reports on express secrets (since
// 2.3), on both engines: the stored snapshot (secret, no sender, no
// verified reporter), the reads, the per-secret and the shared per-IP
// limits, the target checks, and the data-subject and retention paths
// with a NULL transfer and sender.
func TestAbuseReportsOnSecrets(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		f.setExpress(t, f.a, enableExpress(true))
		f.setExpress(t, f.b, enableExpress(true))
		anon := f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		second := f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
		repo := f.db.AbuseReports()
		limits := DefaultAbuseReportLimits()
		ip := netip.MustParseAddr("198.51.100.7")
		report := func(secID string) AbuseReport {
			return AbuseReport{
				SecretID: secID, ReporterIP: ip, Category: AbuseCategoryPhishing,
				Message: "Asks to write to Alice@A.example.com",
			}
		}

		got, err := repo.Create(ctx, f.a, report(anon.Secret.ID), limits, f.now)
		if err != nil || got.SecretID != anon.Secret.ID || got.TransferID != "" || got.SenderEmail != "" ||
			got.RecipientLinkID != "" || got.ReporterVerified || got.Status != AbuseReportOpen || !id.Valid(id.AbuseReport, got.ID) {
			t.Fatalf("Create = %+v, %v", got, err)
		}
		if back, err := repo.Get(ctx, f.a, got.ID); err != nil || back.SecretID != anon.Secret.ID || back.TransferID != "" ||
			back.SenderEmail != "" || back.ReporterIP != ip {
			t.Errorf("Get = %+v, %v", back, err)
		}
		if _, err := repo.Get(ctx, f.b, got.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get from B: %v", err)
		}

		// Three reports per secret per day, then the limit; five per IP
		// per hour across every target.
		for i := range 2 {
			if _, err := repo.Create(ctx, f.a, report(anon.Secret.ID), limits, f.now.Add(time.Duration(i+1)*time.Second)); err != nil {
				t.Fatalf("report %d: %v", i+2, err)
			}
		}
		if _, err := repo.Create(ctx, f.a, report(anon.Secret.ID), limits, f.now.Add(time.Minute)); !errors.Is(err, ErrAbuseReportLinkLimit) {
			t.Errorf("fourth report on the secret: %v", err)
		}
		for i := range 2 {
			if _, err := repo.Create(ctx, f.a, report(second.Secret.ID), limits, f.now.Add(time.Duration(i+2)*time.Minute)); err != nil {
				t.Fatalf("report on the second secret %d: %v", i+1, err)
			}
		}
		if _, err := repo.Create(ctx, f.a, report(second.Secret.ID), limits, f.now.Add(5*time.Minute)); !errors.Is(err, ErrAbuseReportIPLimit) {
			t.Errorf("sixth report of the IP: %v", err)
		}
		// A day later the secret may be reported again (another IP).
		later := report(anon.Secret.ID)
		later.ReporterIP = netip.MustParseAddr("2001:db8::1")
		if _, err := repo.Create(ctx, f.a, later, limits, f.now.Add(AbuseReportLinkWindow+time.Second)); err != nil {
			t.Errorf("report a day later: %v", err)
		}
		page, err := repo.List(ctx, f.a, AbuseReportOpen, 0, "")
		if err != nil || len(page.Items) != 6 {
			t.Fatalf("List = %d items, %v", len(page.Items), err)
		}
		for _, r := range page.Items {
			if r.SecretID == "" || r.TransferID != "" || r.SenderEmail != "" {
				t.Errorf("listed report = %+v", r)
			}
		}
		if r, changed, err := repo.SetStatus(ctx, f.a, got.ID, AbuseReportClosed, "root", nil, f.now); err != nil || !changed ||
			r.Status != AbuseReportClosed || r.SecretID != anon.Secret.ID {
			t.Errorf("SetStatus = %+v, %v, %v", r, changed, err)
		}

		// Malformed targets.
		for name, mod := range map[string]func(*AbuseReport){
			"malformed secret id": func(r *AbuseReport) { r.SecretID = "sec_x" },
			"transfer id too":     func(r *AbuseReport) { r.TransferID = id.New(id.Transfer) },
			"sender":              func(r *AbuseReport) { r.SenderEmail = "alice@a.example.com" },
			"recipient link": func(r *AbuseReport) {
				pos := 0
				r.RecipientLinkID, r.RecipientPosition = id.New(id.RecipientLink), &pos
			},
			"verified reporter": func(r *AbuseReport) { r.ReporterEmail, r.ReporterVerified = "bob@example.org", true },
		} {
			r := report(anon.Secret.ID)
			mod(&r)
			if _, err := repo.Create(ctx, f.a, r, AbuseReportLimits{}, f.now); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		// Only an express secret of the tenant can be reported.
		v21 := f.create(ctx, t, f.a, f.input(newProofs()))
		other := f.createExpress(ctx, t, f.b, f.expressInput(newProofs()))
		for name, try := range map[string]func() error{
			"2.1 secret": func() error {
				_, err := repo.Create(ctx, f.a, report(v21.Secret.ID), AbuseReportLimits{}, f.now)
				return err
			},
			"secret of B": func() error {
				_, err := repo.Create(ctx, f.a, report(other.Secret.ID), AbuseReportLimits{}, f.now)
				return err
			},
			"unknown secret": func() error {
				_, err := repo.Create(ctx, f.a, report(id.New(id.Secret)), AbuseReportLimits{}, f.now)
				return err
			},
		} {
			if err := try(); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: %v", name, err)
			}
		}

		// The erasure of an address rewrites the message of a secret
		// report (no sender to match), and the retention purge removes it.
		var n int64
		err = writeScoped(ctx, f.db, f.a, "pseudonymise", func(tx *ScopedTx) error {
			var err error
			n, err = repo.PseudonymiseTx(ctx, tx, "alice@a.example.com", PseudonymPrefix+strings.Repeat("ab", PseudonymHexLen/2))
			return err
		})
		if err != nil || n != 6 {
			t.Errorf("PseudonymiseTx = %d, %v", n, err)
		}
		if back, err := repo.Get(ctx, f.a, got.ID); err != nil || strings.Contains(back.Message, "A.example.com") {
			t.Errorf("message after the erasure = %+v, %v", back, err)
		}
		if n, err := repo.Purge(ctx, f.a, f.now.AddDate(0, AbuseReportRetentionMonths, 2)); err != nil || n != 6 {
			t.Errorf("Purge = %d, %v", n, err)
		}
	})
}

// TestAbuseReportSecretFault covers the failing check of the reported
// secret (SQLite).
func TestAbuseReportSecretFault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := newSecretFixtureDB(t, db)
	f.setExpress(t, f.a, enableExpress(true))
	cs := f.createExpress(ctx, t, f.a, f.expressInput(newProofs()))
	plan.add(faultQuery, "AND id = ? AND express", 0)
	_, err := f.db.AbuseReports().Create(ctx, f.a, AbuseReport{
		SecretID:   cs.Secret.ID,
		ReporterIP: netip.MustParseAddr("192.0.2.1"), Category: AbuseCategoryOther,
	}, DefaultAbuseReportLimits(), f.now)
	if !errors.Is(err, errInjected) {
		t.Errorf("Create with a failing secret check = %v", err)
	}
}
