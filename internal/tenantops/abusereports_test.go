package tenantops

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestListAbuseReports lists the reports of a tenant only, by status and
// page.
func TestListAbuseReports(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		r1 := ev.seedReport(ev.a)
		ev.clock.Advance(time.Minute)
		r2 := ev.seedReport(ev.a)
		ev.seedReport(ev.b)
		_, err := ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r1.ID, store.AbuseReportClosed, nil, clientIP)
		mustNoErr(t, "close", err)

		page, err := ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "", 0, "")
		mustNoErr(t, "all", err)
		if len(page.Items) != 2 || page.Items[0].ID != r2.ID {
			t.Errorf("all = %+v", page.Items)
		}
		page, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, store.AbuseReportClosed, 0, "")
		mustNoErr(t, "closed", err)
		if len(page.Items) != 1 || page.Items[0].ID != r1.ID {
			t.Errorf("closed = %+v", page.Items)
		}
		page, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "", 1, "")
		mustNoErr(t, "page", err)
		if len(page.Items) != 1 || page.NextCursor == "" {
			t.Fatalf("page = %+v", page)
		}
		page, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "", 1, page.NextCursor)
		mustNoErr(t, "next", err)
		if len(page.Items) != 1 || page.Items[0].ID != r1.ID {
			t.Errorf("next = %+v", page.Items)
		}

		_, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "bogus", 0, "")
		wantInvalid(t, "status", err, FieldStatus)
		_, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "", -1, "")
		wantInvalid(t, "limit", err, FieldLimit)
		_, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "", 0, "garbage")
		wantInvalid(t, "cursor", err, FieldCursor)
		ev.faults("listAbuseReports")
		_, err = ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, "", 0, "")
		wantErr(t, "failure", err, errBoom)
	})
}

// TestGetAbuseReport reads a report and answers a bad ID like a missing one.
func TestGetAbuseReport(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		r := ev.seedReport(ev.a)
		got, err := ev.svc.GetAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID)
		mustNoErr(t, "get", err)
		if got.ID != r.ID || got.SenderEmail != alice {
			t.Errorf("got %+v", got)
		}
		_, err = ev.svc.GetAbuseReport(ctx, ev.adminA, ev.a.ID, "abr_bad")
		wantErr(t, "malformed", err, ErrNotFound)
		_, err = ev.svc.GetAbuseReport(ctx, ev.adminA, ev.a.ID, "abr_01JAB00000000000000000000Z")
		wantErr(t, "missing", err, ErrNotFound)
		ev.faults("getAbuseReport")
		_, err = ev.svc.GetAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID)
		wantErr(t, "failure", err, errBoom)
	})
}

// TestUpdateAbuseReport closes, reopens and no-ops, with sanitized notes
// and audit events only on a change.
func TestUpdateAbuseReport(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		r := ev.seedReport(ev.a)
		// U+202E (RLO) and U+200B (zero width space), as UTF-8 bytes.
		note := "see \xe2\x80\xaebob@example.net \xe2\x80\x8bfor\x07 details"
		got, err := ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, store.AbuseReportClosed, &note, clientIP)
		mustNoErr(t, "close", err)
		if got.Status != store.AbuseReportClosed || got.ClosedBy != "alice.admin" || got.Note != "see bob@example.net for details" {
			t.Errorf("closed = %+v", got)
		}
		evs := ev.auditEvents(ev.a.ID, audit.ActionAbuseReportClosed)
		if len(evs) != 1 || evs[0].ObjectID != r.ID || ev.details(evs[0])["reportId"] != r.ID {
			t.Errorf("closed audit = %+v", evs)
		}

		// A no-op changes nothing and records nothing.
		other := "ignored"
		got, err = ev.svc.UpdateAbuseReport(ctx, ev.super, ev.a.ID, r.ID, store.AbuseReportClosed, &other, clientIP)
		mustNoErr(t, "no-op", err)
		if got.Note != "see bob@example.net for details" || got.ClosedBy != "alice.admin" {
			t.Errorf("no-op = %+v", got)
		}
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionAbuseReportClosed)); n != 1 {
			t.Errorf("closed audits = %d", n)
		}

		got, err = ev.svc.UpdateAbuseReport(ctx, ev.super, ev.a.ID, r.ID, store.AbuseReportOpen, nil, clientIP)
		mustNoErr(t, "reopen", err)
		if got.Status != store.AbuseReportOpen || got.ClosedBy != "" {
			t.Errorf("reopened = %+v", got)
		}
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionAbuseReportReopened)); n != 1 {
			t.Errorf("reopened audits = %d", n)
		}

		long := strings.Repeat("é", MaxAbuseNoteLen+1)
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, store.AbuseReportClosed, &long, clientIP)
		wantInvalid(t, "long note", err, FieldNote)
		bad := "\xff"
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, store.AbuseReportClosed, &bad, clientIP)
		wantInvalid(t, "bad utf8", err, FieldNote)
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, "bogus", nil, clientIP)
		wantInvalid(t, "status", err, FieldStatus)
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, "abr_bad", store.AbuseReportClosed, nil, clientIP)
		wantErr(t, "malformed", err, ErrNotFound)
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, "abr_01JAB00000000000000000000Z", store.AbuseReportClosed, nil, clientIP)
		wantErr(t, "missing", err, ErrNotFound)

		f := ev.faults("setAbuseReportStatus")
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, store.AbuseReportClosed, nil, clientIP)
		wantErr(t, "failure", err, errBoom)
		f.errs["setAbuseReportStatus"] = store.ErrConflict
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, store.AbuseReportClosed, nil, clientIP)
		wantErr(t, "conflict", err, ErrStateConflict)
		f.errs["setAbuseReportStatus"] = store.ErrNotFound
		_, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, r.ID, store.AbuseReportClosed, nil, clientIP)
		wantErr(t, "vanished", err, ErrNotFound)
	})
}

// TestSecretAbuseReport reads and closes a report that names an express
// secret: no transfer and no sender, audited like any other report.
func TestSecretAbuseReport(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		on := tenant.DefaultExpressSettings()
		on.Enabled = true
		_, err := ev.db.Tenants().SetExpressSettings(ctx, ev.a.ID, on)
		mustNoErr(t, "express settings", err)
		kv, v := sha256.Sum256([]byte("key")), sha256.Sum256([]byte("proof"))
		cs, err := ev.db.Secrets(ev.vault).CreateExpress(ctx, ev.a.ID, store.CreateExpressSecret{
			Verifier: v[:], KeyVerifier: kv[:], SealedText: strings.Repeat("TTE2sealed-text_", 4),
			Duration: tenant.SecretDuration1d, Now: ev.clock.Now(),
		})
		mustNoErr(t, "create express", err)
		rep, err := ev.db.AbuseReports().Create(ctx, ev.a.ID, store.AbuseReport{
			SecretID: cs.Secret.ID, Category: store.AbuseCategorySpam, Message: "junk", ReporterIP: clientIP,
		}, store.AbuseReportLimits{PerLinkPerDay: 1000, PerIPPerHour: 1000}, ev.clock.Now())
		mustNoErr(t, "report", err)

		got, err := ev.svc.GetAbuseReport(ctx, ev.adminA, ev.a.ID, rep.ID)
		mustNoErr(t, "get", err)
		if got.SecretID != cs.Secret.ID || got.TransferID != "" || got.SenderEmail != "" {
			t.Errorf("got %+v", got)
		}
		page, err := ev.svc.ListAbuseReports(ctx, ev.adminA, ev.a.ID, store.AbuseReportOpen, 0, "")
		mustNoErr(t, "list", err)
		if len(page.Items) != 1 || page.Items[0].SecretID != cs.Secret.ID {
			t.Errorf("list %+v", page.Items)
		}
		note := "handled"
		got, err = ev.svc.UpdateAbuseReport(ctx, ev.adminA, ev.a.ID, rep.ID, store.AbuseReportClosed, &note, clientIP)
		mustNoErr(t, "close", err)
		if got.Status != store.AbuseReportClosed || got.Note != note || got.SecretID != cs.Secret.ID {
			t.Errorf("closed %+v", got)
		}
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionAbuseReportClosed)); n != 1 {
			t.Errorf("closed audits = %d", n)
		}
		// Another tenant never sees it.
		_, err = ev.svc.GetAbuseReport(ctx, ev.adminB, ev.b.ID, rep.ID)
		wantErr(t, "other tenant", err, ErrNotFound)
	})
}
