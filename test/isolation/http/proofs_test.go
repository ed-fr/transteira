package httpisolation_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// checkGetTransferProof: the proof of A's transfer is served under A's path
// (a PDF, never cached) and, under B's path, answers like an unknown tenant;
// a transfer that does not exist under A's path answers
// proof-not-available, like any transfer without proof.
func checkGetTransferProof(t *testing.T, h *harness, op operation, sess adminSession) {
	trfID := h.availableTransferWithProof(t)
	rest := "/transfers/" + trfID + "/proof?kind=deposit"
	own := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, rest), "")
	if body := wantOK(t, op, "tenant A's proof", own); !strings.HasPrefix(string(body), "%PDF") ||
		own.header.Get("Content-Type") != "application/pdf" || own.header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s: tenant A's proof: %v %.40q", op, own.header, body)
	}
	foreign := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantB.ID, rest), "")
	missing := h.adminCall(t, sess, http.MethodGet, tenantPath(tenant.ID(id.New(id.Tenant)), rest), "")
	h.sameAsMissing(t, op, foreign, missing, trfID)
	unknown := h.adminCall(t, sess, http.MethodGet, tenantPath(h.tenantA.ID, "/transfers/"+id.New(id.Transfer)+"/proof?kind=deposit"), "")
	wantCode(t, op, hostAdmin, unknown, http.StatusNotFound, "proof-not-available")
}

// getMyForeignTransferProof: only the sender of A reads the proof of its
// transfer, under A.
func getMyForeignTransferProof(t *testing.T, h *harness, op operation) {
	t.Helper()
	trfID := h.availableTransferWithProof(t)
	s := h.meSenders(t)
	op = withKind(op)
	params := map[string]string{"transferId": trfID}
	resp := h.call(t, op, hostA, params, "", s.owner.headers()...)
	if resp.status != http.StatusOK || !strings.HasPrefix(string(resp.body), "%PDF") || resp.header.Get("Content-Type") != "application/pdf" ||
		resp.header.Get("Cache-Control") != "no-store" || !strings.Contains(resp.header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("%s for the owner: %d %v %.40q", op, resp.status, resp.header, resp.body)
	}
	meRefusedForOthers(t, h, op, s, params, "")
}
