package proof

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/pdf"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// checkDoc verifies doc against the published keys and returns its
// statement.
func checkDoc(t *testing.T, ev *env, doc Document, kind store.ProofKind, trfID string) Statement {
	t.Helper()
	if doc.FileName != FileName(kind, trfID) {
		t.Errorf("file name = %q", doc.FileName)
	}
	st, err := Verify(bytes.NewReader(doc.PDF), ev.keys(), DefaultVerifyLimit)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if st.Kind != kind || st.TransferID != trfID {
		t.Errorf("statement = %+v", st)
	}
	return st
}

func TestMyProof(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := t.Context()
		trf := ev.seed(ev.a, seedOptions{perRecipient: true})
		my := func(sender, trfID string, kind store.ProofKind, rcpt string) (Document, error) {
			return ev.svc.MyProof(ctx, ev.a, sender, trfID, kind, rcpt, "fr", clientIP)
		}

		doc, err := my(alice, trf.id, store.ProofDeposit, "")
		if err != nil {
			t.Fatalf("MyProof(deposit) = %v", err)
		}
		checkDoc(t, ev, doc, store.ProofDeposit, trf.id)
		if !bytes.Contains(doc.PDF, []byte("Preuve de d")) {
			t.Error("PDF not in French")
		}
		// No delivery yet.
		if _, err := my(alice, trf.id, store.ProofDelivery, ""); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("MyProof(delivery before download) = %v", err)
		}
		ev.clock.Advance(time.Hour)
		ev.download(ev.a, trf.id, trf.links[1].ID) // dave
		checkDoc(t, ev, mustDoc(t)(my(alice, trf.id, store.ProofDelivery, "")), store.ProofDelivery, trf.id)
		st := checkDoc(t, ev, mustDoc(t)(my(aliceNorm, trf.id, store.ProofDelivery, " DAVE@customer.example.net")), store.ProofDelivery, trf.id)
		if len(st.RecipientDownloads) != 1 || st.RecipientDownloads[0].Email != dave {
			t.Errorf("recipient statement = %+v", st)
		}
		if _, err := my(alice, trf.id, store.ProofDelivery, carol); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("MyProof(carol before download) = %v", err)
		}
		if _, err := my(alice, trf.id, store.ProofDelivery, bob); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("MyProof(not a recipient) = %v", err)
		}

		// A drop link deposit: its statement names the recipients of
		// the link, never shown to the depositor (T-311).
		tok, err := id.NewDropToken()
		if err != nil {
			t.Fatal(err)
		}
		l, err := ev.db.DropLinks().Create(ctx, ev.a.ID, store.DropLink{
			ID: id.New(id.DropLink), TokenHash: id.HashToken(tok), Label: "Invoices",
			Recipients: []string{carol, dave}, ValidityDays: 7, Enabled: true, CreatedBy: "adm_1",
		})
		if err != nil {
			t.Fatal(err)
		}
		dropped := ev.seed(ev.a, seedOptions{sender: bob, dropLink: l.ID})
		if _, err := my(bob, dropped.id, store.ProofDeposit, ""); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("MyProof(drop link) = %v", err)
		}

		// Parameters.
		for name, c := range map[string]struct {
			kind  store.ProofKind
			rcpt  string
			param string
		}{
			"kind":              {"receipt", "", ParamKind},
			"empty kind":        {"", "", ParamKind},
			"deposit recipient": {store.ProofDeposit, carol, ParamRecipient},
			"bad recipient":     {store.ProofDelivery, "not-an-address", ParamRecipient},
		} {
			_, err := my(alice, trf.id, c.kind, c.rcpt)
			var inv *InvalidError
			if !errors.As(err, &inv) || inv.Param != c.param || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.param) {
				t.Errorf("%s: MyProof = %v", name, err)
			}
		}

		// Scope: another sender, another tenant, unknown or malformed
		// transfer: all answered as not found.
		bobs := ev.seed(ev.a, seedOptions{sender: bob})
		otherTenant := ev.seed(ev.b, seedOptions{})
		for name, c := range map[string]struct {
			tn     *tenant.Tenant
			sender string
			trfID  string
		}{
			"other sender":        {ev.a, alice, bobs.id},
			"other sender's view": {ev.a, bob, trf.id},
			"other tenant":        {ev.a, alice, otherTenant.id},
			"wrong tenant":        {ev.b, alice, trf.id},
			"unknown":             {ev.a, alice, "trf_01JB0000000000000000000009"},
			"malformed":           {ev.a, alice, "x"},
			"bad session address": {ev.a, "nobody", trf.id},
		} {
			if _, err := ev.svc.MyProof(ctx, c.tn, c.sender, c.trfID, store.ProofDeposit, "", "en", clientIP); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s: MyProof = %v", name, err)
			}
		}

		// Audit: the sender as actor, the kind only.
		events := ev.auditEvents(ev.a.ID, audit.ActionTransferProofDownloaded)
		if len(events) != 3 {
			t.Fatalf("%d proof_downloaded events, want 3", len(events))
		}
		for _, e := range events {
			if e.ActorKind != store.ActorDepositor || e.ObjectKind != audit.ObjectTransfer || e.ObjectID != trf.id || e.IP != clientIP ||
				strings.Contains(string(e.Details), "@") || !strings.Contains(string(e.Details), `"kind"`) {
				t.Errorf("event = %+v (%s)", e, e.Details)
			}
		}

		// P60: once the transfer is deleted, the sender no longer reaches
		// the proof (the administrators do).
		ev.end(ev.a, trf.id)
		if _, err := my(alice, trf.id, store.ProofDeposit, ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("MyProof(deleted transfer) = %v", err)
		}
		if _, err := ev.svc.TenantProof(ctx, principal(store.RoleDelegatedAdmin, ev.a.ID), ev.a.ID, trf.id, store.ProofDeposit, "", "en", clientIP); err != nil {
			t.Errorf("TenantProof(deleted transfer) = %v", err)
		}
	})
}

// mustDoc returns a function failing the test on error.
func mustDoc(t *testing.T) func(Document, error) Document {
	return func(d Document, err error) Document {
		t.Helper()
		if err != nil {
			t.Fatalf("proof: %v", err)
		}
		return d
	}
}

func TestTenantProof(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := t.Context()
		trf := ev.seed(ev.a, seedOptions{})
		get := func(p adminauth.Principal, tid tenant.ID, trfID string, kind store.ProofKind) (Document, error) {
			return ev.svc.TenantProof(ctx, p, tid, trfID, kind, "", "", clientIP)
		}
		for name, p := range map[string]adminauth.Principal{
			"delegated admin": principal(store.RoleDelegatedAdmin, ev.b.ID, ev.a.ID),
			"auditor":         principal(store.RoleAuditor, ev.a.ID),
			"super admin":     principal(store.RoleSuperAdmin),
		} {
			doc, err := get(p, ev.a.ID, trf.id, store.ProofDeposit)
			if err != nil {
				t.Fatalf("%s: TenantProof = %v", name, err)
			}
			checkDoc(t, ev, doc, store.ProofDeposit, trf.id)
			// Tenant A's default language is English.
			if !bytes.Contains(doc.PDF, []byte("Proof of deposit")) {
				t.Errorf("%s: PDF not in the tenant language", name)
			}
		}
		events := ev.auditEvents(ev.a.ID, audit.ActionTransferProofDownloaded)
		if len(events) != 3 || events[0].ActorKind != store.ActorAdmin || !strings.HasPrefix(events[0].Actor, "admin-") {
			t.Errorf("events = %+v", events)
		}

		unauth := principal(store.RoleSuperAdmin)
		unauth.State = store.SessionTOTPRequired
		disabled := principal(store.RoleSuperAdmin)
		disabled.Admin.Disabled = true
		for name, c := range map[string]struct {
			p    adminauth.Principal
			tid  tenant.ID
			want error
		}{
			"no session":         {adminauth.Principal{}, ev.a.ID, adminauth.ErrUnauthenticated},
			"half logged in":     {unauth, ev.a.ID, adminauth.ErrUnauthenticated},
			"other tenant admin": {principal(store.RoleDelegatedAdmin, ev.b.ID), ev.a.ID, adminauth.ErrNotFound},
			"other auditor":      {principal(store.RoleAuditor, ev.b.ID), ev.a.ID, adminauth.ErrNotFound},
			"disabled":           {disabled, ev.a.ID, adminauth.ErrNotFound},
			"unknown tenant":     {principal(store.RoleSuperAdmin), "ten_01JB0000000000000000000009", ErrNotFound},
			"malformed tenant":   {principal(store.RoleSuperAdmin), "bogus", ErrNotFound},
		} {
			if _, err := get(c.p, c.tid, trf.id, store.ProofDeposit); !errors.Is(err, c.want) {
				t.Errorf("%s: TenantProof = %v, want %v", name, err, c.want)
			}
		}
		// Tenant B does not see tenant A's proof through its own ID.
		if _, err := get(principal(store.RoleDelegatedAdmin, ev.b.ID), ev.b.ID, trf.id, store.ProofDeposit); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("TenantProof(other tenant's transfer) = %v", err)
		}
		if _, err := ev.svc.TenantProof(ctx, principal(store.RoleSuperAdmin), ev.a.ID, trf.id, store.ProofDeposit, carol, "", clientIP); !errors.Is(err, ErrInvalid) {
			t.Errorf("TenantProof(deposit recipient) = %v", err)
		}

		// The proof outlives the transfer, until its retention ends.
		ev.end(ev.a, trf.id)
		ev.clock.Advance(365*24*time.Hour - 2*time.Minute)
		if _, err := get(principal(store.RoleAuditor, ev.a.ID), ev.a.ID, trf.id, store.ProofDeposit); err != nil {
			t.Errorf("TenantProof(deleted transfer) = %v", err)
		}
		ev.clock.Advance(2 * time.Minute)
		if _, err := get(principal(store.RoleAuditor, ev.a.ID), ev.a.ID, trf.id, store.ProofDeposit); !errors.Is(err, ErrNotAvailable) {
			t.Errorf("TenantProof(after retention) = %v", err)
		}
		if k, err := ev.svc.Keys(ctx); err != nil || len(k) != 1 {
			t.Errorf("Keys = %+v, %v", k, err)
		}
	})
}

func TestProofRateLimit(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t), WithRateLimit(1, 2))
	ctx := t.Context()
	trf := ev.seed(ev.a, seedOptions{})
	v6a, v6b := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2::ffff")
	for i := range 2 {
		if _, err := ev.svc.MyProof(ctx, ev.a, alice, trf.id, store.ProofDeposit, "", "en", v6a); err != nil {
			t.Fatalf("request %d = %v", i, err)
		}
	}
	// Same /64, and the administrators' operation: one bucket per client.
	_, err := ev.svc.MyProof(ctx, ev.a, alice, trf.id, store.ProofDeposit, "", "en", v6b)
	var rl *RateLimitError
	if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter <= 0 || !strings.Contains(err.Error(), "retry after") {
		t.Errorf("third request = %v", err)
	}
	if _, err := ev.svc.TenantProof(ctx, principal(store.RoleSuperAdmin), ev.a.ID, trf.id, store.ProofDeposit, "", "en", v6b); !errors.Is(err, ErrRateLimited) {
		t.Errorf("admin request = %v", err)
	}
	if !strings.Contains(ev.seclog.String(), "event=rate_limited") || !strings.Contains(ev.seclog.String(), ScopeProofIP) {
		t.Errorf("security log = %q", ev.seclog.String())
	}
	// Another client is not limited; the bucket refills.
	if _, err := ev.svc.MyProof(ctx, ev.a, alice, trf.id, store.ProofDeposit, "", "en", clientIP); err != nil {
		t.Errorf("other client = %v", err)
	}
	ev.clock.Advance(time.Minute)
	if _, err := ev.svc.MyProof(ctx, ev.a, alice, trf.id, store.ProofDeposit, "", "en", v6b); err != nil {
		t.Errorf("after refill = %v", err)
	}
	for ip, want := range map[netip.Addr]string{
		{}:                                       "invalid",
		netip.MustParseAddr("::ffff:192.0.2.1"):  "192.0.2.1",
		netip.MustParseAddr("fe80::1%eth0"):      "fe80::/64",
		netip.MustParseAddr("2001:db8:1:2:3::4"): "2001:db8:1:2::/64",
	} {
		if got := clientKey(ip); got != want {
			t.Errorf("clientKey(%v) = %q, want %q", ip, got, want)
		}
	}
}

func TestServiceFaults(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := t.Context()
	trf := ev.seed(ev.a, seedOptions{})
	admin := principal(store.RoleSuperAdmin)

	// Audit and security log failures are logged, never returned.
	svc := NewService(ev.db, ev.signer, faultAudit{}, ev.clock.Now, nil, WithSecurityLog(failingLog{}), WithRateLimit(60, 1))
	if _, err := svc.TenantProof(ctx, admin, ev.a.ID, trf.id, store.ProofDeposit, "", "en", clientIP); err != nil {
		t.Errorf("TenantProof(audit fails) = %v", err)
	}
	if _, err := svc.TenantProof(ctx, admin, ev.a.ID, trf.id, store.ProofDeposit, "", "en", clientIP); !errors.Is(err, ErrRateLimited) {
		t.Errorf("TenantProof(limited) = %v", err)
	}

	// Database failures are internal errors, not answers.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for name, err := range map[string]error{
		"my":           justErr(ev.svc.MyProof(canceled, ev.a, alice, trf.id, store.ProofDeposit, "", "en", clientIP)),
		"tenant":       justErr(ev.svc.TenantProof(canceled, admin, ev.a.ID, trf.id, store.ProofDeposit, "", "en", clientIP)),
		"proof":        justErr(ev.svc.document(canceled, ev.a, trf.id, store.ProofDeposit, "", "en")),
		"keys":         justErr(ev.svc.Keys(canceled)),
		"recipient":    justErr(ev.svc.document(canceled, ev.a, trf.id, store.ProofDelivery, carol, "en")),
		"other tenant": justErr(ev.svc.document(ctx, ev.b, trf.id, store.ProofDeposit, "", "en")),
	} {
		if err == nil || name != "other tenant" && (errors.Is(err, ErrNotFound) || errors.Is(err, ErrNotAvailable)) {
			t.Errorf("%s = %v", name, err)
		}
	}

	// A stored statement that does not parse or does not match its row is
	// an internal error.
	corrupt := func(stmt string, kid string) {
		t.Helper()
		trfID := ev.seed(ev.a, seedOptions{noProof: true}).id
		err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
			return ev.db.TransferProofs().InsertTx(t.Context(), tx, store.TransferProof{
				TransferID: trfID, Kind: store.ProofDeposit, Statement: []byte(strings.ReplaceAll(stmt, "{trf}", trfID)),
				Signature: make([]byte, 64), KeyID: kid, ExpiresAt: ev.clock.Now().AddDate(1, 0, 0),
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.TenantProof(t.Context(), admin, ev.a.ID, trfID, store.ProofDeposit, "", "en", clientIP); err == nil ||
			errors.Is(err, ErrNotAvailable) || errors.Is(err, ErrNotFound) {
			t.Errorf("TenantProof(corrupt %s) = %v", stmt, err)
		}
	}
	kid := ev.keys()[0].KeyID
	corrupt(`{"a":1}`, kid)
	good := ev.proofRow(ev.a, trf.id, store.ProofDeposit, "")
	corrupt(string(good.Statement), kid) // statement of another transfer
}

// TestServiceRenderFault is not parallel: it replaces the PDF writer. A
// rendering failure is an internal error. The store guarantees a 64-byte
// signature and ParseStatement a canonical statement, so the writer is the
// only part of the rendering that can fail.
func TestServiceRenderFault(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := t.Context()
	trf := ev.seed(ev.a, seedOptions{})
	admin := principal(store.RoleSuperAdmin)
	orig := pdfWrite
	t.Cleanup(func() { pdfWrite = orig })
	pdfWrite = func(io.Writer, pdf.Document) error { return errBoom }
	if _, err := ev.svc.TenantProof(ctx, admin, ev.a.ID, trf.id, store.ProofDeposit, "", "en", clientIP); !errors.Is(err, errBoom) {
		t.Errorf("TenantProof(render fails) = %v", err)
	}
}

// justErr drops the value of a two-value result.
func justErr[T any](_ T, err error) error { return err }
