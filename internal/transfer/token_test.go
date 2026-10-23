package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// newToken stores a usable API token in tn and returns its identifier. The
// secret is drawn at runtime and only its hash is kept.
func (ev *env) newToken(t *testing.T, tn *tenant.Tenant) string {
	t.Helper()
	secret, err := id.NewToken("tt", 32)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(secret))
	tok, err := ev.db.APITokens().Create(context.Background(), tn.ID, store.APIToken{
		ID: id.New(id.APIToken), Name: "scanner", Prefix: secret[:7], TokenHash: h[:], CreatedBy: "admin",
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return tok.ID
}

// tokenSender returns the sender of a request authenticated by the API
// token tokID, from outside the tenant ranges (the token ranges are
// checked by the HTTP layer).
func tokenSender(tokID string) Sender {
	return Sender{
		Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: tokID},
		ClientIP:  externalIP,
	}
}

// tokenRequest returns request() with carol as sender address.
func tokenRequest() CreateRequest {
	req := request()
	req.SenderEmail = carol
	return req
}

func TestTokenCreate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok := ev.newToken(t, ev.a)
		req := tokenRequest()
		req.SenderEmail = " Carol@Entity-A.Example.COM "
		d, err := ev.svc.Create(ctx, ev.a, tokenSender(tok), req, "")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if d.SenderEmail != carol || !reflect.DeepEqual(d.Recipients, []string{dave}) || d.Status != store.TransferUploading {
			t.Errorf("details = %+v", d)
		}
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.APITokenID != tok || stored.SenderKind != store.DepositorInternal || stored.SenderEmail != carol ||
			stored.InvitationID != "" || stored.SenderIP != externalIP {
			t.Errorf("stored = %+v", stored.Transfer)
		}
		if got := ev.seclog.reasons(); len(got) != 0 {
			t.Errorf("refusals = %v", got)
		}
	})
}

func TestTokenValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok := tokenSender(ev.newToken(t, ev.a))
		cases := map[string]struct {
			mutate func(*CreateRequest)
			want   []FieldError
		}{
			"missing sender": {
				func(r *CreateRequest) { r.SenderEmail = "" },
				[]FieldError{{FieldSenderEmail, CodeRequired}},
			},
			"display name": {
				func(r *CreateRequest) { r.SenderEmail = "Carol <" + carol + ">" },
				[]FieldError{{FieldSenderEmail, CodeInvalidEmail}},
			},
			"malformed sender": {
				func(r *CreateRequest) { r.SenderEmail = "carol@" },
				[]FieldError{{FieldSenderEmail, CodeInvalidEmail}},
			},
			"missing recipients": {
				func(r *CreateRequest) { r.Recipients = nil },
				[]FieldError{{FieldRecipients, CodeRequired}},
			},
		}
		for name, c := range cases {
			req := tokenRequest()
			c.mutate(&req)
			_, err := ev.svc.Create(ctx, ev.a, tok, req, "")
			var verr *ValidationError
			if !errors.As(err, &verr) || !reflect.DeepEqual(verr.Fields, c.want) {
				t.Errorf("%s: err = %v", name, err)
			}
		}
		// A session may not name the sender.
		_, err := ev.svc.Create(ctx, ev.a, internalSender(), tokenRequest(), "")
		var verr *ValidationError
		if !errors.As(err, &verr) || !reflect.DeepEqual(verr.Fields, []FieldError{{FieldSenderEmail, CodeNotAllowed}}) {
			t.Errorf("session with senderEmail: err = %v", err)
		}
		// Nothing was refused by the eligibility (validation first).
		if got := ev.seclog.reasons(); len(got) != 0 {
			t.Errorf("refusals = %v", got)
		}
	})
}

func TestTokenEligibility(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok := tokenSender(ev.newToken(t, ev.a))

		// Outside the internal domains, whatever the client IP.
		req := tokenRequest()
		req.SenderEmail = dave
		if _, err := ev.svc.Create(ctx, ev.a, tok, req, ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("external domain: err = %v", err)
		}
		inside := tok
		inside.ClientIP = internalIP
		if _, err := ev.svc.Create(ctx, ev.a, inside, req, ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("external domain from inside: err = %v", err)
		}
		// Blocklisted address, then blocklisted domain.
		ev.block(t, ev.a, store.BlockEmail, carol)
		if _, err := ev.svc.Create(ctx, ev.a, tok, tokenRequest(), ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("blocked address: err = %v", err)
		}
		ev.block(t, ev.a, store.BlockDomain, "entity-a.example.com")
		req.SenderEmail = alice
		if _, err := ev.svc.Create(ctx, ev.a, tok, req, ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("blocked domain: err = %v", err)
		}
		want := []string{securitylog.ReasonDomain, securitylog.ReasonDomain, securitylog.ReasonBlocklist, securitylog.ReasonBlocklist}
		if got := ev.seclog.reasons(); !reflect.DeepEqual(got, want) {
			t.Errorf("refusals = %v, want %v", got, want)
		}
	})
}

// TestTokenRevokedMeanwhile checks that a token revoked after the HTTP
// authentication creates nothing.
func TestTokenRevokedMeanwhile(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok := ev.newToken(t, ev.a)
		if _, _, err := ev.db.APITokens().Revoke(ctx, ev.a.ID, tok, ev.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.Create(ctx, ev.a, tokenSender(tok), tokenRequest(), ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("revoked token: err = %v", err)
		}
		// A token of another tenant is unknown in this one.
		other := ev.newToken(t, ev.b)
		if _, err := ev.svc.Create(ctx, ev.a, tokenSender(other), tokenRequest(), ""); !errors.Is(err, ErrForbidden) {
			t.Errorf("token of B: err = %v", err)
		}
		if n := ev.usedBytes(t, ev.a); n != 0 {
			t.Errorf("used bytes = %d", n)
		}
	})
}

func TestTokenOwnership(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok, tok2 := tokenSender(ev.newToken(t, ev.a)), tokenSender(ev.newToken(t, ev.a))
		req := tokenRequest()
		req.SenderEmail = alice // the address of the session below
		mine := ev.mustCreate(t, tok, req)
		session := ev.mustCreate(t, internalSender(), request())

		if d, err := ev.svc.Get(ctx, ev.a, tok, mine.ID); err != nil || d.ID != mine.ID || d.SenderEmail != alice {
			t.Errorf("Get by its token: %+v, %v", d, err)
		}
		// Another token, a session with the same address, the token on a
		// session transfer: not found.
		denied := []struct {
			name   string
			sender Sender
			trfID  string
		}{
			{"other token", tok2, mine.ID},
			{"session", internalSender(), mine.ID},
			{"token on session transfer", tok, session.ID},
		}
		for _, c := range denied {
			if _, err := ev.svc.Get(ctx, ev.a, c.sender, c.trfID); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(%s): err = %v", c.name, err)
			}
			if err := ev.svc.Cancel(ctx, ev.a, c.sender, c.trfID); !errors.Is(err, ErrNotFound) {
				t.Errorf("Cancel(%s): err = %v", c.name, err)
			}
			if _, err := ev.svc.Finalize(ctx, ev.a, c.sender, c.trfID); !errors.Is(err, ErrNotFound) {
				t.Errorf("Finalize(%s): err = %v", c.name, err)
			}
		}
		// The token of A is unknown on B.
		if _, err := ev.svc.Get(ctx, ev.b, tok, mine.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get on B: err = %v", err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, tok, mine.ID); err != nil {
			t.Errorf("Cancel by its token: %v", err)
		}
	})
}

func TestTokenFinalize(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok := tokenSender(ev.newToken(t, ev.a))
		d := ev.mustCreate(t, tok, tokenRequest())
		ev.complete(t, d.ID, "")
		got, err := ev.svc.Finalize(ctx, ev.a, tok, d.ID)
		if err != nil || got.Status != store.TransferScanning {
			t.Fatalf("Finalize: %+v, %v", got, err)
		}

		// The eligibility applies to the stored sender address.
		d = ev.mustCreate(t, tok, tokenRequest())
		ev.complete(t, d.ID, "")
		ev.block(t, ev.a, store.BlockEmail, carol)
		if _, err := ev.svc.Finalize(ctx, ev.a, tok, d.ID); !errors.Is(err, ErrForbidden) {
			t.Errorf("blocked sender: err = %v", err)
		}
		if got := ev.seclog.reasons(); !reflect.DeepEqual(got, []string{securitylog.ReasonBlocklist}) {
			t.Errorf("refusals = %v", got)
		}
	})
}

// TestTokenMalformedSender checks that a malformed token sender is a
// wiring error, never a client error.
func TestTokenMalformedSender(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	tok := ev.newToken(t, ev.a)
	bad := map[string]Sender{
		"malformed id": tokenSender("tok_x"),
		"external":     {Depositor: store.Depositor{Kind: store.DepositorExternal, APITokenID: tok, InvitationID: ev.inv.ID}},
		"invitation":   {Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: tok, InvitationID: ev.inv.ID}},
	}
	trfID := id.New(id.Transfer)
	for name, s := range bad {
		if _, err := ev.svc.Create(ctx, ev.a, s, tokenRequest(), ""); err == nil || isClientError(err) {
			t.Errorf("Create(%s): err = %v", name, err)
		}
		if _, err := ev.svc.Get(ctx, ev.a, s, trfID); err == nil || isClientError(err) {
			t.Errorf("Get(%s): err = %v", name, err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, s, trfID); err == nil || isClientError(err) {
			t.Errorf("Cancel(%s): err = %v", name, err)
		}
		if _, err := ev.svc.Finalize(ctx, ev.a, s, trfID); err == nil || isClientError(err) {
			t.Errorf("Finalize(%s): err = %v", name, err)
		}
	}
	// The eligibility of a token sender needs its address.
	if _, _, err := ev.svc.checkEligible(ctx, ev.a, tokenSender(tok)); err == nil || isClientError(err) {
		t.Errorf("checkEligible without address: err = %v", err)
	}
}

// isClientError reports whether err is one of the errors answered 4xx.
func isClientError(err error) bool {
	for _, target := range []error{ErrInvalid, ErrForbidden, ErrNotFound, ErrConflict, ErrRateLimited} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// TestTokenOpenTransferCap checks that the cap on unfinished transfers is
// counted per token, apart from the sessions of the same address.
func TestTokenOpenTransferCap(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.svc.maxOpen = 2
		tok, tok2 := tokenSender(ev.newToken(t, ev.a)), tokenSender(ev.newToken(t, ev.a))
		req := tokenRequest()
		req.SenderEmail = alice
		ev.mustCreate(t, tok, req)
		ev.mustCreate(t, tok, req)
		var limited *RateLimitError
		if _, err := ev.svc.Create(ctx, ev.a, tok, req, ""); !errors.As(err, &limited) {
			t.Fatalf("at the cap: err = %v", err)
		}
		// The same address through a session, and another token, are apart.
		ev.mustCreate(t, internalSender(), request())
		ev.mustCreate(t, internalSender(), request())
		ev.mustCreate(t, tok2, req)
		// Transfers of the token whose uploads expired no longer count.
		ev.clock.Advance(uploadTTL + time.Hour)
		ev.mustCreate(t, tok, req)
		ev.mustCreate(t, tok, req)
		if _, err := ev.svc.Create(ctx, ev.a, tok, req, ""); !errors.Is(err, ErrRateLimited) {
			t.Errorf("two new active transfers: err = %v", err)
		}
	})
}

// TestTokenIdempotency checks that the idempotency keys are scoped to the
// token.
func TestTokenIdempotency(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tok, tok2 := tokenSender(ev.newToken(t, ev.a)), tokenSender(ev.newToken(t, ev.a))
		req := tokenRequest()
		req.SenderEmail = alice
		first, err := ev.svc.Create(ctx, ev.a, tok, req, "key-1")
		if err != nil {
			t.Fatal(err)
		}
		again, err := ev.svc.Create(ctx, ev.a, tok, req, "key-1")
		if err != nil || again.ID != first.ID {
			t.Errorf("replay: %s, %v", again.ID, err)
		}
		other, err := ev.svc.Create(ctx, ev.a, tok2, req, "key-1")
		if err != nil || other.ID == first.ID {
			t.Errorf("other token: %s, %v", other.ID, err)
		}
		session, err := ev.svc.Create(ctx, ev.a, internalSender(), request(), "key-1")
		if err != nil || session.ID == first.ID || session.ID == other.ID {
			t.Errorf("session: %s, %v", session.ID, err)
		}
		changed := req
		changed.ExpiryDays = 1
		if _, err := ev.svc.Create(ctx, ev.a, tok, changed, "key-1"); !errors.Is(err, ErrIdempotencyMismatch) {
			t.Errorf("mismatch: err = %v", err)
		}
		// Only the sender address differs: a mismatch too, never the
		// transfer of another address.
		otherSender := req
		otherSender.SenderEmail = carol
		if _, err := ev.svc.Create(ctx, ev.a, tok, otherSender, "key-1"); !errors.Is(err, ErrIdempotencyMismatch) {
			t.Errorf("other sender: err = %v", err)
		}
		// The same address written differently is the same request.
		same := req
		same.SenderEmail = " ALICE@entity-a.example.com "
		if again, err := ev.svc.Create(ctx, ev.a, tok, same, "key-1"); err != nil || again.ID != first.ID {
			t.Errorf("same sender, other case: %s, %v", again.ID, err)
		}
	})
}

// TestTokenAllowedSenders checks that the allowed senders of a token
// restrict the sender address on creation and again on finalization, with
// the token's current list, on top of the internal domains.
func TestTokenAllowedSenders(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		tokID := ev.newToken(t, ev.a)
		tok := tokenSender(tokID)
		setSenders := func(senders ...string) {
			t.Helper()
			if senders == nil {
				senders = []string{}
			}
			if _, err := ev.db.APITokens().Update(ctx, ev.a.ID, tokID, store.APITokenUpdate{AllowedSenders: senders}); err != nil {
				t.Fatal(err)
			}
		}
		create := func(sender string) (Details, error) {
			req := tokenRequest()
			req.SenderEmail = sender
			return ev.svc.Create(ctx, ev.a, tok, req, "")
		}

		// By address: only carol.
		setSenders(carol)
		if _, err := create(alice); !errors.Is(err, ErrForbidden) {
			t.Errorf("address not allowed: err = %v", err)
		}
		d, err := create(" CAROL@entity-a.example.com")
		if err != nil {
			t.Fatalf("allowed address: %v", err)
		}
		// By domain: exact domain only, never a subdomain; the internal
		// domains still apply.
		setSenders("entity-a.example.com", "customer.example.net")
		if _, err := create(alice); err != nil {
			t.Errorf("allowed domain: %v", err)
		}
		if _, err := create(dave); !errors.Is(err, ErrForbidden) {
			t.Errorf("allowed but external domain: err = %v", err)
		}
		setSenders("example.com")
		if _, err := create(alice); !errors.Is(err, ErrForbidden) {
			t.Errorf("parent domain: err = %v", err)
		}
		// Finalization reads the current list: carol is no longer allowed.
		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, tok, d.ID); !errors.Is(err, ErrForbidden) {
			t.Errorf("finalize after the restriction: err = %v", err)
		}
		// An empty list allows any internal address again.
		setSenders()
		if got, err := ev.svc.Finalize(ctx, ev.a, tok, d.ID); err != nil || got.Status != store.TransferScanning {
			t.Errorf("finalize without restriction: %+v, %v", got, err)
		}
		want := []string{
			securitylog.ReasonDomain, securitylog.ReasonDomain, securitylog.ReasonDomain, securitylog.ReasonDomain,
		}
		if got := ev.seclog.reasons(); !reflect.DeepEqual(got, want) {
			t.Errorf("refusals = %v, want %v", got, want)
		}

		// A token revoked or expired between authentication and finalize.
		e2 := ev.mustCreate(t, tok, tokenRequest())
		ev.complete(t, e2.ID, "")
		if _, _, err := ev.db.APITokens().Revoke(ctx, ev.a.ID, tokID, ev.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.Finalize(ctx, ev.a, tok, e2.ID); !errors.Is(err, ErrForbidden) {
			t.Errorf("finalize with a revoked token: err = %v", err)
		}
		if got := ev.seclog.reasons(); len(got) != len(want) {
			t.Errorf("revoked token logged: %v", got)
		}
	})
}

// TestTokenSenderStoreFailure checks that a failure to read the token is
// an internal error.
func TestTokenSenderStoreFailure(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	tok := tokenSender(ev.newToken(t, ev.a))
	r := ev.faults()
	r.fail["apiToken"] = errors.New("boom")
	if _, err := ev.svc.Create(context.Background(), ev.a, tok, tokenRequest(), ""); err == nil || isClientError(err) {
		t.Errorf("Create: err = %v, want an internal error", err)
	}
}

func TestTokenAuditEvents(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		tokID := ev.newToken(t, ev.a)
		tok := tokenSender(tokID)
		d := ev.mustCreate(t, tok, tokenRequest())
		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, tok, d.ID); err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		x := ev.mustCreate(t, tok, tokenRequest())
		if err := ev.svc.Cancel(ctx, ev.a, tok, x.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		// A replay records nothing.
		if _, err := ev.svc.Create(ctx, ev.a, tok, tokenRequest(), "k"); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.Create(ctx, ev.a, tok, tokenRequest(), "k"); err != nil {
			t.Fatal(err)
		}

		events, _, errs := h.audit.snapshot()
		if len(errs) != 0 {
			t.Fatalf("audit write errors: %v", errs)
		}
		type want struct {
			action audit.Action
			kind   string
			obj    string
		}
		wants := []want{
			{audit.ActionTransferCreated, audit.ObjectTransfer, d.ID},
			{audit.ActionAPITokenUsed, audit.ObjectAPIToken, tokID},
			{audit.ActionTransferFinalized, audit.ObjectTransfer, d.ID},
			{audit.ActionTransferCreated, audit.ObjectTransfer, x.ID},
			{audit.ActionAPITokenUsed, audit.ObjectAPIToken, tokID},
			{audit.ActionTransferDeleted, audit.ObjectTransfer, x.ID},
		}
		if len(events) != len(wants)+2 {
			t.Fatalf("got %d events: %+v", len(events), events)
		}
		for i, w := range wants {
			ev := events[i]
			// api_token.used names the sender address, as a depositor;
			// the transfer events name the token.
			kind, actor := store.ActorAPIToken, tokID
			if w.action == audit.ActionAPITokenUsed {
				kind, actor = store.ActorDepositor, carol
			}
			if ev.Action != w.action || ev.ActorKind != kind || ev.Actor != actor ||
				ev.ObjectKind != w.kind || ev.ObjectID != w.obj || ev.IP != externalIP {
				t.Errorf("event %d = %+v, want %+v", i, ev, w)
			}
		}
		if events[0].Details["origin"] != "api" {
			t.Errorf("created details = %v", events[0].Details)
		}
		if events[1].Details["transferId"] != d.ID || len(events[1].Details) != 1 {
			t.Errorf("used details = %v", events[1].Details)
		}
		// Stored, never an address in the details, and in the actor column
		// of api_token.used only.
		page, err := ev.db.AuditEvents().List(ctx, store.AuditFilter{TenantID: ev.a.ID, Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != len(events) {
			t.Errorf("stored %d events", len(page.Items))
		}
		for _, row := range page.Items {
			if strings.Contains(string(row.Details), "@") ||
				(row.Action != string(audit.ActionAPITokenUsed) && strings.Contains(row.Actor, "@")) {
				t.Errorf("%s holds an address: %s %s", row.Action, row.Actor, row.Details)
			}
		}
		// The GDPR search and erasure on the sender address cover the
		// three api_token.used events.
		if n, err := ev.db.AuditEvents().CountActor(ctx, ev.a.ID, carol); err != nil || n != 3 {
			t.Errorf("CountActor(sender) = %d, %v; want 3", n, err)
		}
		if n, err := ev.db.AuditEvents().PseudonymiseActor(ctx, ev.a.ID, carol, store.PseudonymPrefix+"0123456789abcdef"); err != nil || n != 3 {
			t.Errorf("PseudonymiseActor(sender) = %d, %v; want 3", n, err)
		}
	})
}
