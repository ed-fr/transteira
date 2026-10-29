package httpisolation_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// startForeignReply: with replies allowed on both tenants, a link of A is
// unknown under B (404, no cookie, with or without a verification cookie),
// and under A it needs the proof of the address (401), whose forged cookie
// is refused as well; with the option off, A answers 403 reply-not-allowed
// and B still answers 404 for the link of A.
func startForeignReply(t *testing.T, h *harness, op operation) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	setReply := func(tid tenant.ID, on bool) {
		tn, err := db.Tenants().Get(ctx, tid)
		if err != nil {
			t.Fatal(err)
		}
		tn.AllowTransferReply = on
		if _, err := db.Tenants().Update(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	token := h.availableVerifiedDownloadA(t)
	params := map[string]string{"linkToken": token}
	forged := []string{"Cookie", download.VerificationCookieName + "=" + download.VerificationCookiePrefix + strings.Repeat("A", 54)}
	for _, on := range []bool{true, false} {
		setReply(h.tenantA.ID, on)
		setReply(h.tenantB.ID, on)
		for range 3 {
			refusedUnderB(t, h, op, h.call(t, op, hostB, params, `{}`), http.StatusNotFound, "not-found")
			refusedUnderB(t, h, op, h.call(t, op, hostB, params, `{}`, forged...), http.StatusNotFound, "not-found")
		}
	}
	setReply(h.tenantA.ID, true)
	setReply(h.tenantB.ID, true)
	wantCode(t, op, hostA, h.call(t, op, hostA, params, `{}`), http.StatusUnauthorized, "recipient-verification-required")
	wantCode(t, op, hostA, h.call(t, op, hostA, params, `{}`, forged...), http.StatusUnauthorized, "recipient-verification-required")
	setReply(h.tenantA.ID, false)
	wantCode(t, op, hostA, h.call(t, op, hostA, params, `{}`), http.StatusForbidden, "reply-not-allowed")
}
