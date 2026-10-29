package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// allowReply turns the replies of tn on or off in the database. The
// in-memory tn keeps the value it had, so that the tests show the service
// reads the current one.
func (ev *env) allowReply(t *testing.T, tn *tenant.Tenant, on bool) {
	t.Helper()
	c := tn.Clone()
	c.AllowTransferReply = on
	if _, err := ev.db.Tenants().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// original creates a transfer of A by sender with req, uploads and
// finalizes it, makes it available and returns its identifier.
func (ev *env) original(t *testing.T, sender Sender, req CreateRequest) string {
	t.Helper()
	d := ev.mustCreate(t, sender, req)
	ev.complete(t, d.ID, "")
	if _, err := ev.svc.Finalize(context.Background(), ev.a, sender, d.ID); err != nil {
		t.Fatalf("Finalize original: %v", err)
	}
	ev.makeAvailableLinks(t, d.ID)
	return d.ID
}

// makeAvailableLinks moves the finalized transfer trfID of A to available
// with one link per recipient, its files clean, as the antivirus worker
// does.
func (ev *env) makeAvailableLinks(t *testing.T, trfID string) {
	t.Helper()
	ctx := context.Background()
	d, err := ev.db.Transfers().Get(ctx, ev.a.ID, trfID)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ev.db.Scoped(ev.a.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		for _, f := range d.Files {
			if err := ev.db.TransferFiles().SetScanResultTx(ctx, tx, f.ID, store.ScanClean, "", ev.clock.Now()); err != nil {
				return err
			}
		}
		tokens := make([]store.LinkToken, len(d.Recipients))
		for i := range tokens {
			token, err := id.NewDownloadToken()
			if err != nil {
				return err
			}
			wkID, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
			if err != nil {
				return err
			}
			h := sha256.Sum256([]byte(token))
			tokens[i] = store.LinkToken{Hash: h[:], KeyID: wkID}
		}
		_, err := ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, trfID, tokens, ev.clock.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// replySender returns email replying to the transfer origID, from outside.
func replySender(email, origID string) Sender {
	return Sender{
		Depositor: store.Depositor{Email: email, Kind: store.DepositorReply, ReplyToTransferID: origID},
		ClientIP:  externalIP,
	}
}

// replyEnv returns an env whose tenant A allows replies, with an available
// transfer of alice to dave, whose identifier it returns.
func replyEnv(t *testing.T, e storetest.Engine) (*env, string) {
	t.Helper()
	ev := newEnv(t, e)
	ev.allowReply(t, ev.a, true)
	return ev, ev.original(t, internalSender(), request())
}

func TestReplyCreate(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, orig := replyEnv(t, e)
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		ab := &fakeAbuse{}
		ev.svc.abuse = ab
		// An allow list leaving out the internal domain binds free
		// recipients only: the reply to alice passes.
		ev.setRecipientRules(t, ev.a, []string{"customer.example.net"}, nil)
		sender := replySender(dave, orig)

		// The requested recipients, even malformed, are ignored: the reply
		// goes to the original sender.
		req := request()
		req.Recipients = []string{"not an address", bob, bob}
		d := ev.mustCreate(t, sender, req)
		if !reflect.DeepEqual(d.Recipients, []string{alice}) || d.SenderEmail != dave || d.ReplyToTransferID != orig {
			t.Errorf("details = %+v", d)
		}
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || stored.SenderKind != store.DepositorReply || stored.ReplyToTransferID != orig ||
			stored.InvitationID != "" || stored.APITokenID != "" {
			t.Fatalf("stored = %+v, %v", stored.Transfer, err)
		}
		if ab.checks[0].Kind != store.DepositorReply || !reflect.DeepEqual(ab.checks[0].Recipients, []string{alice}) {
			t.Errorf("abuse facts = %+v", ab.checks[0])
		}
		req.Recipients = nil
		x := ev.mustCreate(t, sender, req)

		// Only a reply session of the same address to the same transfer
		// owns it.
		for _, other := range []Sender{replySender(dave, id.New(id.Transfer)), replySender(carol, orig)} {
			if _, err := ev.svc.Get(ctx, ev.a, other, d.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get by %+v: %v", other.Depositor, err)
			}
		}
		got, err := ev.svc.Get(ctx, ev.a, sender, d.ID)
		if err != nil || got.ReplyToTransferID != orig {
			t.Errorf("Get = %+v, %v", got, err)
		}

		ev.complete(t, d.ID, "")
		if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		if err := ev.svc.Cancel(ctx, ev.a, sender, x.ID); err != nil {
			t.Fatalf("Cancel: %v", err)
		}
		if n := len(ev.seclog.reasons()); n != 0 {
			t.Errorf("%d refusals logged", n)
		}

		events, _, errs := h.audit.snapshot()
		if len(errs) != 0 || len(events) != 6 {
			t.Fatalf("events = %+v, errors %v", events, errs)
		}
		created := map[string]any{"fileCount": 2, "totalBytes": int64(300), "origin": "reply", "confidentialityLevel": "internal"}
		wantEvent(t, events[0], audit.ActionTransferCreated, dave, externalIP, d.ID, created)
		wantEvent(t, events[1], audit.ActionTransferReplyCreated, dave, externalIP, d.ID, map[string]any{"replyTo": orig})
		wantEvent(t, events[2], audit.ActionTransferCreated, dave, externalIP, x.ID, created)
		wantEvent(t, events[3], audit.ActionTransferReplyCreated, dave, externalIP, x.ID, map[string]any{"replyTo": orig})
		wantEvent(t, events[4], audit.ActionTransferFinalized, dave, externalIP, d.ID,
			map[string]any{"fileCount": 2, "totalBytes": int64(300)})
		wantEvent(t, events[5], audit.ActionTransferDeleted, dave, externalIP, x.ID, map[string]any{"by": "sender"})
	})
}

func TestReplyEligibility(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, orig := replyEnv(t, e)
		sender := replySender(dave, orig)
		// A reply transfer waiting for its finalization.
		pending := ev.mustCreate(t, sender, request())
		ev.complete(t, pending.ID, "")

		check := func(name string, s Sender, want error, finalize bool) {
			t.Helper()
			if _, err := ev.svc.Create(ctx, ev.a, s, request(), ""); !errors.Is(err, want) {
				t.Errorf("%s: Create err = %v, want %v", name, err, want)
			}
			if finalize {
				if _, err := ev.svc.Finalize(ctx, ev.a, s, pending.ID); !errors.Is(err, want) {
					t.Errorf("%s: Finalize err = %v, want %v", name, err, want)
				}
			}
		}

		// The tenant turned replies off (the in-memory tenant never said on).
		ev.allowReply(t, ev.a, false)
		check("replies off", sender, ErrReplyNotAllowed, true)
		ev.allowReply(t, ev.a, true)

		// No reply to a transfer of an invited external.
		fromExternal := ev.original(t, ev.external(), request())
		check("original by an external", replySender(alice, fromExternal), ErrReplyNotAllowed, false)
		// No reply to a reply.
		reply := ev.original(t, sender, request())
		check("reply to a reply", replySender(alice, reply), ErrReplyNotAllowed, false)
		// Only a recipient of the original replies.
		check("not a recipient", replySender(carol, orig), ErrReplyNotAllowed, false)
		// A reply to a transfer of an API token is allowed.
		fromToken := ev.original(t, tokenSender(ev.newToken(t, ev.a)), tokenRequest())
		if _, err := ev.svc.Create(ctx, ev.a, replySender(dave, fromToken), request(), ""); err != nil {
			t.Errorf("reply to an API token transfer: %v", err)
		}

		// The original sender left the internal domains.
		if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID,
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-z.example.com"}); err != nil {
			t.Fatal(err)
		}
		check("original sender outside the domains", sender, ErrReplyNotAllowed, true)
		if _, err := ev.db.NetworkRules().Replace(ctx, ev.a.ID,
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []string{"entity-a.example.com"}); err != nil {
			t.Fatal(err)
		}
		// None of these policy refusals reached the security log.
		if got := ev.seclog.reasons(); len(got) != 0 {
			t.Errorf("reasons = %v", got)
		}

		// Unknown original, or an original of another tenant: gone.
		check("unknown original", replySender(dave, id.New(id.Transfer)), ErrOriginalGone, false)
		inB, err := ev.svc.Create(ctx, ev.b, internalSender(), request(), "")
		if err != nil {
			t.Fatal(err)
		}
		check("original of B", replySender(dave, inB.ID), ErrOriginalGone, false)
		ev.allowReply(t, ev.b, true)
		if _, err := ev.svc.Create(ctx, ev.b, sender, request(), ""); !errors.Is(err, ErrOriginalGone) {
			t.Errorf("original of A from B: %v", err)
		}

		// The original sender blocklisted (here by domain, which also
		// covers the API token sender): a policy refusal, not logged.
		ev.block(t, ev.a, store.BlockDomain, "entity-a.example.com")
		check("original sender blocklisted", sender, ErrReplyNotAllowed, true)
		check("token sender blocklisted", replySender(dave, fromToken), ErrReplyNotAllowed, false)
		if n := len(ev.seclog.reasons()); n != 0 {
			t.Errorf("%d refusals logged", n)
		}
		// The replier blocklisted: refused and logged.
		ev.block(t, ev.a, store.BlockEmail, dave)
		check("replier blocklisted", sender, ErrForbidden, true)
		if got := ev.seclog.reasons(); !reflect.DeepEqual(got, []string{securitylog.ReasonBlocklist, securitylog.ReasonBlocklist}) {
			t.Errorf("reasons = %v", got)
		}
	})
}

func TestReplyOriginalGone(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, orig := replyEnv(t, e)
		sender := replySender(dave, orig)
		pending := ev.mustCreate(t, sender, request())
		ev.complete(t, pending.ID, "")

		// The original expires during the upload: the reply is never
		// finalized, and no new reply is created.
		ev.clock.Advance(7*24*time.Hour + time.Second)
		if _, err := ev.svc.Finalize(ctx, ev.a, sender, pending.ID); !errors.Is(err, ErrOriginalGone) {
			t.Errorf("Finalize after expiry: %v", err)
		}
		if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, ErrOriginalGone) {
			t.Errorf("Create after expiry: %v", err)
		}
		if d, err := ev.db.Transfers().Get(ctx, ev.a.ID, pending.ID); err != nil || d.Status != store.TransferUploading {
			t.Errorf("pending reply = %q, %v", d.Status, err)
		}

		// The download limit of the original reached.
		req := request()
		req.MaxDownloads = intp(1)
		limited := ev.original(t, internalSender(), req)
		s, err := ev.db.Scoped(ev.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
			return ev.db.Transfers().IncrementDownloadsTx(ctx, tx, limited)
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.Create(ctx, ev.a, replySender(dave, limited), request(), ""); !errors.Is(err, ErrOriginalGone) {
			t.Errorf("download limit reached: %v", err)
		}
		// Not available yet (still uploading).
		up := ev.mustCreate(t, internalSender(), request())
		if _, err := ev.svc.Create(ctx, ev.a, replySender(dave, up.ID), request(), ""); !errors.Is(err, ErrOriginalGone) {
			t.Errorf("original uploading: %v", err)
		}
		if n := len(ev.seclog.events); n != 0 {
			t.Errorf("%d security events", n)
		}
	})
}

func TestReplyLimits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev, orig := replyEnv(t, e)
		sender := replySender(dave, orig)

		// The rules of a confidentiality level apply to a reply.
		ev.setLevels(t, ev.a, strictLevels())
		req := request()
		req.ConfidentialityLevel = "secret"
		_, err := ev.svc.Create(ctx, ev.a, sender, req, "")
		if fields := ruleFields(t, err, ErrConfidentialityRule); len(fields) == 0 {
			t.Error("no broken rule")
		}

		// An abuse block (the external quota) refuses a reply.
		ab := &fakeAbuse{check: blockWith(store.AbuseRuleExternalQuota)}
		ev.svc.abuse = ab
		var be *AbuseBlockedError
		if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.As(err, &be) ||
			be.Rule != store.AbuseRuleExternalQuota {
			t.Errorf("abuse: %v", err)
		}
		if _, blocked, _ := ab.counts(); blocked != 1 || ab.blocked[0].Kind != store.DepositorReply {
			t.Errorf("blocked = %+v", ab.blocked)
		}
		ev.svc.abuse = nil

		// The external cap on unfinished transfers.
		for range MaxOpenTransfersExternal {
			ev.mustCreate(t, sender, request())
		}
		var rl *RateLimitError
		if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.As(err, &rl) {
			t.Errorf("open cap: %v", err)
		}
	})
}

func TestReplyFaults(t *testing.T) {
	ev, orig := replyEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	sender := replySender(dave, orig)
	f := ev.faults()

	for _, name := range []string{"tenant", "transfer", "networkRules"} {
		f.fail[name] = errFault
		if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, errFault) {
			t.Errorf("%s fault: %v", name, err)
		}
		delete(f.fail, name)
	}
	// The second blocklist read is the original sender's.
	f.fail["blocked"], f.skip["blocked"] = errFault, 1
	if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, errFault) {
		t.Errorf("blocklist fault: %v", err)
	}
	delete(f.fail, "blocked")
	// A tenant being deleted: no reply.
	f.fail["tenant"] = store.ErrNotFound
	if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, ErrReplyNotAllowed) {
		t.Errorf("tenant gone: %v", err)
	}
	delete(f.fail, "tenant")
	// The original purged between the checks and the insert.
	f.fail["createTransfer"] = store.ErrNotFound
	if _, err := ev.svc.Create(ctx, ev.a, sender, request(), ""); !errors.Is(err, ErrOriginalGone) {
		t.Errorf("original purged before the insert: %v", err)
	}
	delete(f.fail, "createTransfer")
	// The original purged between the creation and the finalization.
	d := ev.mustCreate(t, sender, request())
	ev.complete(t, d.ID, "")
	f.fail["transfer"] = store.ErrNotFound
	if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); !errors.Is(err, ErrOriginalGone) {
		t.Errorf("original purged before the finalization: %v", err)
	}
	delete(f.fail, "transfer")
	if _, err := ev.svc.Finalize(ctx, ev.a, sender, d.ID); err != nil {
		t.Errorf("Finalize: %v", err)
	}
}

func TestReplyMalformed(t *testing.T) {
	ev, orig := replyEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	bad := []Sender{
		// A reply needs its original transfer, well formed.
		{Depositor: store.Depositor{Email: dave, Kind: store.DepositorReply}},
		{Depositor: store.Depositor{Email: dave, Kind: store.DepositorReply, ReplyToTransferID: "trf_bad"}},
		// A reply has no invitation.
		{Depositor: store.Depositor{Email: dave, Kind: store.DepositorReply, ReplyToTransferID: orig, InvitationID: ev.inv.ID}},
		// Only a reply has an original transfer.
		{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternal, ReplyToTransferID: orig}},
		{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: ev.inv.ID, ReplyToTransferID: orig}},
		{Depositor: store.Depositor{Email: alice, Kind: store.DepositorInternal, APITokenID: id.New(id.APIToken), ReplyToTransferID: orig}},
	}
	for _, s := range bad {
		if _, err := ev.svc.Create(ctx, ev.a, s, request(), ""); err == nil || errors.Is(err, ErrForbidden) || errors.Is(err, ErrReplyNotAllowed) {
			t.Errorf("Create(%+v): err = %v", s.Depositor, err)
		}
		if _, err := ev.svc.Finalize(ctx, ev.a, s, id.New(id.Transfer)); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Finalize(%+v): err = %v", s.Depositor, err)
		}
	}
}

// TestReplyable: an original can be replied to only while its download
// page opens, with at least one deliverable file (the rule of
// download.deliverable and download.limitReached).
func TestReplyable(t *testing.T) {
	t.Parallel()
	now := time.Date(2027, time.March, 5, 10, 0, 0, 0, time.UTC)
	file := func(st store.ScanStatus) store.TransferFile { return store.TransferFile{ScanStatus: st} }
	base := func() store.TransferDetails {
		return store.TransferDetails{
			Transfer: store.Transfer{Status: store.TransferAvailable, ExpiresAt: now.Add(time.Hour)},
			Files:    []store.TransferFile{file(store.ScanInfected), file(store.ScanClean)},
		}
	}
	for name, tc := range map[string]struct {
		mutate func(*store.TransferDetails)
		want   bool
	}{
		"available":           {func(*store.TransferDetails) {}, true},
		"not scanned (large)": {func(d *store.TransferDetails) { d.Files = []store.TransferFile{file(store.ScanNotScannedTooLarge)} }, true},
		"not scanned (enc.)":  {func(d *store.TransferDetails) { d.Files = []store.TransferFile{file(store.ScanNotScannedEncrypted)} }, true},
		"no deliverable file": {func(d *store.TransferDetails) {
			d.Files = []store.TransferFile{file(store.ScanInfected), file(store.ScanError)}
		}, false},
		"no file":           {func(d *store.TransferDetails) { d.Files = nil }, false},
		"not available":     {func(d *store.TransferDetails) { d.Status = store.TransferExpired }, false},
		"expired":           {func(d *store.TransferDetails) { d.ExpiresAt = now }, false},
		"deleted after":     {func(d *store.TransferDetails) { d.DeleteAfter = now }, false},
		"before deletion":   {func(d *store.TransferDetails) { d.DeleteAfter = now.Add(time.Minute) }, true},
		"limit reached":     {func(d *store.TransferDetails) { d.MaxDownloads, d.DownloadCount = intp(2), 2 }, false},
		"limit not reached": {func(d *store.TransferDetails) { d.MaxDownloads, d.DownloadCount = intp(2), 1 }, true},
	} {
		d := base()
		tc.mutate(&d)
		if got := replyable(d, now); got != tc.want {
			t.Errorf("%s: replyable = %v, want %v", name, got, tc.want)
		}
	}
}
