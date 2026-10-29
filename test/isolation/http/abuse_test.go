package httpisolation_test

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// reportMarkerB is the message of the abuse report of tenant B.
const reportMarkerB = "marker of an abuse report of entity B"

// seedAbuseReport stores an open abuse report of tenant tid with message
// and returns its ID (the transfer it names need not exist: reports keep
// the identifier only).
func seedAbuseReport(t *testing.T, db *store.DB, tid tenant.ID, message string) string {
	t.Helper()
	r, err := db.AbuseReports().Create(context.Background(), tid, store.AbuseReport{
		TransferID: id.New(id.Transfer), SenderEmail: "sender@sender.example.org", Category: store.AbuseCategorySpam,
		ReporterIP: netip.MustParseAddr("192.0.2.77"), Message: message,
	}, store.AbuseReportLimits{}, time.Now())
	if err != nil {
		t.Fatalf("seed abuse report: %v", err)
	}
	return r.ID
}

// checkListAbuseReports: A's list holds A's report, never B's, whatever the
// status filter.
func checkListAbuseReports(t *testing.T, h *harness, op operation, sess adminSession) {
	for _, q := range []string{"?limit=200", "?limit=200&status=open"} {
		resp := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/abuse-reports"+q), "")
		if body := wantOK(t, op, "tenant A's list", resp); !strings.Contains(string(body), h.ops.reportA) {
			t.Errorf("%s: tenant A's list misses its report: %s", op, body)
		}
		h.noDataOfB(t, op, "tenant A's list", resp, h.ops.reportB)
	}
	h.invalidInputOfB(t, op, sess, http.MethodGet, "/abuse-reports?status=nope", "")
}

// checkGetAbuseReport: A's report is read under A's path, B's answers like
// a missing report.
func checkGetAbuseReport(t *testing.T, h *harness, op operation, sess adminSession) {
	own := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/abuse-reports/"+h.ops.reportA), "")
	if body := wantOK(t, op, "tenant A's report", own); !strings.Contains(string(body), h.ops.reportA) {
		t.Errorf("%s: tenant A's report: %s", op, body)
	}
	foreign := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/abuse-reports/"+h.ops.reportB), "")
	missing := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/abuse-reports/"+id.New(id.AbuseReport)), "")
	h.sameAsMissing(t, op, foreign, missing, h.ops.reportB)
}

// checkUpdateAbuseReport: B's report under A's path answers like a missing
// report and stays open; A's own report is closed, then reopened.
func checkUpdateAbuseReport(t *testing.T, h *harness, op operation, sess adminSession) {
	body := `{"status":"closed","note":"isolation check"}`
	foreign := h.adminCall(t, sess, http.MethodPatch, tenantPath(h.tenantA.ID, "/abuse-reports/"+h.ops.reportB), body)
	missing := h.adminCall(t, sess, http.MethodPatch, tenantPath(h.tenantA.ID, "/abuse-reports/"+id.New(id.AbuseReport)), body)
	h.sameAsMissing(t, op, foreign, missing, h.ops.reportB)
	resp := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/abuse-reports/"+h.ops.reportB), "")
	if b := wantOK(t, op, "tenant B's report (super admin)", resp); !strings.Contains(string(b), `"status":"open"`) {
		t.Errorf("%s: tenant B's report was changed: %s", op, b)
	}
	own := h.adminCall(t, sess, http.MethodPatch, tenantPath(h.tenantA.ID, "/abuse-reports/"+h.ops.reportA), body)
	if b := wantOK(t, op, "tenant A's own report", own); !strings.Contains(string(b), `"status":"closed"`) {
		t.Errorf("%s: tenant A's report not closed: %s", op, b)
	}
}

// reportForeignAbuse: a link of A is unknown under B (404, nothing
// recorded), a report under A is accepted (202) and listed for A only.
func reportForeignAbuse(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID, token := h.availableTransfer(t, "")
	params := map[string]string{"linkToken": token}
	body := `{"category":"phishing","message":"isolation check"}`
	for range 6 {
		refusedUnderB(t, h, op, h.call(t, op, hostB, params, body), http.StatusNotFound, "not-found")
	}
	if resp := h.call(t, op, hostA, params, body); resp.status != http.StatusAccepted || len(resp.body) != 0 {
		t.Fatalf("%s under %s: %d %s, want 202", op, hostA, resp.status, resp.body)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for tid, want := range map[tenant.ID]bool{h.tenantA.ID: true, h.tenantB.ID: false} {
		page, err := db.AbuseReports().List(ctx, tid, "", 200, "")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, r := range page.Items {
			found = found || r.TransferID == trfID
		}
		if found != want {
			t.Errorf("%s: report of %s listed for tenant %s: %v, want %v", op, trfID, tid, found, want)
		}
	}
	// The same link, an invalid category: a validation error, not a leak.
	wantCode(t, op, hostA, h.call(t, op, hostA, params, `{"category":"nope"}`), http.StatusBadRequest, "validation-failed")
}
