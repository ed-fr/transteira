package deposit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// carol is the second recipient of the source transfers, of a domain of
// her own so that a domain blocklist entry hits her only.
const carol = "carol@customer.example.net"

// source is an available per-recipient transfer of alice to bob and carol.
type source struct {
	store.TransferDetails
	// links are the recipient links, in recipient position order (bob,
	// carol).
	links []store.RecipientLink
}

// newSource creates a source transfer of tn, available now for 7 days with
// one clean file and one link per recipient.
func (ev *env) newSource(t *testing.T, tn *tenant.Tenant) source {
	t.Helper()
	ctx := context.Background()
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := ev.clock.Now()
	tr := store.Transfer{
		ID: id.New(id.Transfer), SenderEmail: alice, SenderKind: store.DepositorInternal, ExpiryDays: 7,
		LinkMode: store.LinkModePerRecipient,
	}
	var links []store.RecipientLink
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		wk, _, err := ev.vault.NewDEKTx(ctx, tx)
		if err != nil {
			return err
		}
		upl, err := id.NewUploadToken()
		if err != nil {
			return err
		}
		f := store.TransferFile{
			ID: id.New(id.File), Name: "plans.pdf", Size: 10, MediaType: "application/pdf",
			DEKKeyID: wk, StorageName: randomHex(t, store.StorageNameLen/2), UploadID: upl,
			SHA256: strings.Repeat("1", 64), CiphertextSize: 50, UploadedAt: now,
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, []string{bob, carol}, []store.TransferFile{f}); err != nil {
			return err
		}
		if err := ev.db.Transfers().FinalizeTx(ctx, tx, tr.ID, now); err != nil {
			return err
		}
		if err := ev.db.TransferFiles().SetScanResultTx(ctx, tx, f.ID, store.ScanClean, "", now); err != nil {
			return err
		}
		var tokens []store.LinkToken
		for range 2 {
			tok, err := id.NewDownloadToken()
			if err != nil {
				return err
			}
			kid, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(tok))
			if err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(tok))
			tokens = append(tokens, store.LinkToken{Hash: hash[:], KeyID: kid})
		}
		links, err = ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, tr.ID, tokens, now)
		return err
	})
	if err != nil {
		t.Fatalf("new source transfer: %v", err)
	}
	d, err := ev.db.Transfers().Get(ctx, tn.ID, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	return source{TransferDetails: d, links: links}
}

// target returns the reply target of the recipient at position i of src.
func (src source) target(i int) ReplyTarget {
	return ReplyTarget{
		TransferID: src.ID, LinkID: src.links[i].ID, Email: src.Recipients[i],
		Recipient: src.SenderEmail, TransferExpiresAt: src.ExpiresAt,
	}
}

// deleteSource deletes the row of src (data keys destroyed first, as the
// purge does).
func (ev *env) deleteSource(t *testing.T, tn *tenant.Tenant, src source) {
	t.Helper()
	ctx := context.Background()
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.Tx(ctx, func(tx *store.ScopedTx) error {
		for _, f := range src.Files {
			if err := ev.db.WrappedKeys().DeleteTx(ctx, tx, f.DEKKeyID); err != nil {
				return err
			}
		}
		if _, err := ev.db.RecipientLinks().DestroyKeysTx(ctx, tx, src.ID); err != nil {
			return err
		}
		return ev.db.Transfers().DeleteTx(ctx, tx, src.ID)
	})
	if err != nil {
		t.Fatalf("delete source: %v", err)
	}
}

// randomHex returns n random bytes in lowercase hex.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// wantReply checks a reply session opened through the link at position i of
// src, expiring at expires.
func wantReply(t *testing.T, what string, got SessionInfo, src source, i int, expires time.Time) {
	t.Helper()
	if got.ID == "" || got.Email != src.Recipients[i] || got.Kind != KindReply || !got.ExpiresAt.Equal(expires) ||
		got.CanInvite || got.Invitation != nil || got.ReplyToTransferID != src.ID ||
		got.RecipientLinkID != src.links[i].ID || got.Limits.MaxTransferBytes != 1<<30 || got.CSRFToken == "" {
		t.Errorf("%s: session = %+v, want a reply of %s expiring at %s", what, got, src.Recipients[i], expires)
	}
	if got.Reply == nil || got.Reply.Recipient != aliceNorm || !got.Reply.TransferExpiresAt.Equal(src.ExpiresAt) {
		t.Errorf("%s: reply = %+v, want to %s until %s", what, got.Reply, aliceNorm, src.ExpiresAt)
	}
}

func TestOpenReply(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		logs := ev.withAudit(spy)
		src := ev.newSource(t, ev.a)
		if src.ExpiresAt.IsZero() || src.Recipients[0] != bob {
			t.Fatalf("source = %+v", src.Transfer)
		}

		// Happy path: capped by the session lifetime (4 h, the source
		// lives 7 days), no recognition cookie, no invitation.
		target := src.target(0)
		target.Email, target.Recipient = "Bob@Partner.Example.org", alice
		s, err := ev.svc.OpenReply(ctx, ev.a, externalIP, target)
		if err != nil {
			t.Fatalf("OpenReply: %v", err)
		}
		now := ev.clock.Now()
		wantReply(t, "OpenReply", s.SessionInfo, src, 0, now.Add(4*time.Hour))
		if s.Recognition != "" || !validToken(id.SessionTokenPrefix, s.Token) || !ev.svc.CheckCSRF(s.Token, s.CSRFToken) {
			t.Errorf("OpenReply: token %v, recognition %q", validToken(id.SessionTokenPrefix, s.Token), s.Recognition)
		}
		events, tids, errs := spy.snapshot()
		if len(events) != 1 || len(errs) != 0 || tids[0] != ev.a.ID {
			t.Fatalf("audit events = %+v, errors %v, log %s", events, errs, logs)
		}
		wantEvent(t, events[0], audit.ActionAddressVerified, bob, audit.ObjectDepositSession, s.ID,
			map[string]any{"origin": originReply, "replyTo": src.ID})
		if ev.queue.count() != 0 || ev.seclog.String() != "" {
			t.Errorf("mails %d, security log %q", ev.queue.count(), ev.seclog.String())
		}

		// The cookie reads back the same session, the source read again.
		info, err := ev.svc.Session(ctx, ev.a, s.Token)
		if err != nil {
			t.Fatalf("Session: %v", err)
		}
		wantReply(t, "Session", info, src, 0, now.Add(4*time.Hour))
		if info.CSRFToken != s.CSRFToken {
			t.Error("Session: another CSRF token")
		}
		// Worthless in another tenant (isolation).
		_, err = ev.svc.Session(ctx, ev.b, s.Token)
		wantErr(t, "Session from B", err, ErrUnauthenticated)
		// A reply session never invites.
		_, err = ev.svc.Invite(ctx, ev.a, info, internalIP, "", "dan@partner.example.org", "", "en")
		wantErr(t, "Invite(reply)", err, ErrForbidden)

		// Capped by the source: a source expiring in one hour ends the
		// session then.
		soon := src.target(1)
		soon.TransferExpiresAt = now.Add(time.Hour)
		s2, err := ev.svc.OpenReply(ctx, ev.a, externalIP, soon)
		if err != nil {
			t.Fatalf("OpenReply(source expiring soon): %v", err)
		}
		if !s2.ExpiresAt.Equal(now.Add(time.Hour)) || s2.Email != carol || s2.RecipientLinkID != src.links[1].ID ||
			!s2.Reply.TransferExpiresAt.Equal(now.Add(time.Hour)) {
			t.Errorf("OpenReply(source expiring soon) = %+v", s2.SessionInfo)
		}
		ev.clock.Advance(time.Hour)
		_, err = ev.svc.Session(ctx, ev.a, s2.Token)
		wantErr(t, "Session(after the source expiry)", err, ErrUnauthenticated)
		if _, err := ev.svc.Session(ctx, ev.a, s.Token); err != nil {
			t.Errorf("Session(first reply) = %v", err)
		}

		// End works for a reply session.
		if err := ev.svc.End(ctx, ev.a, s.Token); err != nil {
			t.Fatalf("End: %v", err)
		}
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "Session(ended)", err, ErrUnauthenticated)
		wantErr(t, "End(again)", ev.svc.End(ctx, ev.a, s.Token), ErrUnauthenticated)
	})
}

func TestOpenReplyRefused(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		ev.withAudit(spy)
		src := ev.newSource(t, ev.a)
		other := ev.newSource(t, ev.a)
		srcB := ev.newSource(t, ev.b)

		// Unknown client IP.
		_, err := ev.svc.OpenReply(ctx, ev.a, netipZero(), src.target(0))
		wantErr(t, "OpenReply(no client IP)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="ip"`, 1)

		// Blocklisted replier: the address, then the domain.
		entry := ev.block(t, ev.a, store.BlockEmail, bob)
		_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0))
		wantErr(t, "OpenReply(blocked address)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 1)
		// The entry of A does not refuse bob in B.
		if _, err := ev.svc.OpenReply(ctx, ev.b, externalIP, srcB.target(0)); err != nil {
			t.Errorf("OpenReply(B, blocked in A only) = %v", err)
		}
		if err := ev.db.Blocklist().Delete(ctx, ev.a.ID, entry.ID); err != nil {
			t.Fatal(err)
		}
		ev.block(t, ev.a, store.BlockDomain, "customer.example.net")
		_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1))
		wantErr(t, "OpenReply(blocked domain)", err, ErrForbidden)
		ev.wantLogged(t, "deposit_refused", `reason="blocklist"`, 2)
		if _, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0)); err != nil {
			t.Errorf("OpenReply(other domain) = %v", err)
		}

		// Expired source: an expiry not after now, or none.
		for name, exp := range map[string]time.Time{
			"now": ev.clock.Now(), "past": ev.clock.Now().Add(-time.Minute), "none": {},
			"within the millisecond": ev.clock.Now().Add(time.Microsecond),
		} {
			target := src.target(0)
			target.TransferExpiresAt = exp
			_, err := ev.svc.OpenReply(ctx, ev.a, externalIP, target)
			wantErr(t, "OpenReply(expiry "+name+")", err, ErrReplyGone)
		}

		// Source or link gone, of another transfer or of another tenant
		// (isolation): all alike.
		with := func(trf, link string) ReplyTarget {
			target := src.target(0)
			target.TransferID, target.LinkID = trf, link
			return target
		}
		for name, target := range map[string]ReplyTarget{
			"missing source":         with(id.New(id.Transfer), src.links[0].ID),
			"missing link":           with(src.ID, id.New(id.RecipientLink)),
			"link of another source": with(src.ID, other.links[0].ID),
			"source of another link": with(other.ID, src.links[0].ID),
			"source of B":            with(srcB.ID, src.links[0].ID),
			"link of B":              with(src.ID, srcB.links[0].ID),
			"source and link of B":   with(srcB.ID, srcB.links[0].ID),
		} {
			_, err := ev.svc.OpenReply(ctx, ev.a, externalIP, target)
			wantErr(t, "OpenReply("+name+")", err, ErrReplyGone)
		}
		// B cannot open a reply on A's transfer.
		_, err = ev.svc.OpenReply(ctx, ev.b, externalIP, src.target(0))
		wantErr(t, "OpenReply(A's source from B)", err, ErrReplyGone)

		// Malformed identifiers and addresses are internal failures.
		for name, target := range map[string]ReplyTarget{
			"malformed source": with("trf_x", src.links[0].ID),
			"malformed link":   with(src.ID, "rcl_x"),
		} {
			_, err := ev.svc.OpenReply(ctx, ev.a, externalIP, target)
			if !errors.Is(err, store.ErrInvalid) || errors.Is(err, ErrReplyGone) {
				t.Errorf("OpenReply(%s) = %v, want an internal failure", name, err)
			}
		}
		bad := src.target(0)
		bad.Email = "not an address"
		if _, err := ev.svc.OpenReply(ctx, ev.a, externalIP, bad); err == nil || errors.Is(err, ErrForbidden) {
			t.Errorf("OpenReply(bad address) = %v", err)
		}
		bad = src.target(0)
		bad.Recipient = "not an address"
		if _, err := ev.svc.OpenReply(ctx, ev.a, externalIP, bad); err == nil || errors.Is(err, ErrForbidden) {
			t.Errorf("OpenReply(bad recipient) = %v", err)
		}

		// Only the two sessions opened were audited (B, then A).
		events, _, errs := spy.snapshot()
		if len(events) != 2 || len(errs) != 0 {
			t.Errorf("audit events = %+v, errors %v", events, errs)
		}
	})
}

func TestReplySessionSourceGone(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		src := ev.newSource(t, ev.a)
		s, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0))
		if err != nil {
			t.Fatalf("OpenReply: %v", err)
		}
		ev.deleteSource(t, ev.a, src)
		_, err = ev.svc.Session(ctx, ev.a, s.Token)
		wantErr(t, "Session(source deleted)", err, ErrUnauthenticated)
		wantErr(t, "End(source deleted)", ev.svc.End(ctx, ev.a, s.Token), ErrUnauthenticated)
		_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1))
		wantErr(t, "OpenReply(source deleted)", err, ErrReplyGone)
	})
}

// TestOpenReplyLimit: at most MaxLiveReplySessions live reply sessions per
// recipient link (P33); ended and expired sessions free their place, and
// the bound is per link.
func TestOpenReplyLimit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		src := ev.newSource(t, ev.a)
		var first Session
		for i := range MaxLiveReplySessions {
			s, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0))
			if err != nil {
				t.Fatalf("OpenReply(%d): %v", i+1, err)
			}
			if i == 0 {
				first = s
			}
		}
		_, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0))
		var rle *RateLimitError
		if !errors.As(err, &rle) || rle.RetryAfter != DefaultSessionTTL || !errors.Is(err, ErrRateLimited) {
			t.Fatalf("OpenReply(over the bound) = %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="reply_session"`, 1)
		// The other link of the transfer has its own bound.
		if _, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1)); err != nil {
			t.Fatalf("OpenReply(other link): %v", err)
		}
		// Ending a session frees a place.
		if err := ev.svc.End(ctx, ev.a, first.Token); err != nil {
			t.Fatal(err)
		}
		if _, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0)); err != nil {
			t.Fatalf("OpenReply(after End): %v", err)
		}
		_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0))
		wantErr(t, "OpenReply(full again)", err, ErrRateLimited)
		// Expired sessions free theirs (all of them, at their expiry).
		ev.clock.Advance(DefaultSessionTTL)
		if _, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0)); err != nil {
			t.Fatalf("OpenReply(after expiry): %v", err)
		}
		ev.wantLogged(t, "rate_limited", `scope="reply_session"`, 2)
	})
}

func TestReplyFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	src := ev.newSource(t, ev.a)
	s, err := ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(0))
	if err != nil {
		t.Fatalf("OpenReply: %v", err)
	}
	real := ev.svc.repo
	with := func(fails map[string]error) { ev.svc.repo = faultRepo{repo: real, fails: fails} }

	// Source row missing while the session survives (a concurrent purge).
	with(map[string]error{"transfer": store.ErrNotFound})
	_, err = ev.svc.Session(ctx, ev.a, s.Token)
	wantErr(t, "Session(source missing)", err, ErrUnauthenticated)
	with(map[string]error{"transfer": errFault})
	_, err = ev.svc.Session(ctx, ev.a, s.Token)
	if !errors.Is(err, errFault) || errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Session(source read fails) = %v", err)
	}

	with(map[string]error{"blocked": errFault})
	_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1))
	wantErr(t, "OpenReply(blocklist fails)", err, errFault)
	with(map[string]error{"createSession": errFault})
	_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1))
	if !errors.Is(err, errFault) || errors.Is(err, ErrReplyGone) {
		t.Errorf("OpenReply(create fails) = %v", err)
	}
	with(map[string]error{"countLiveReplies": errFault})
	_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1))
	if !errors.Is(err, errFault) || errors.Is(err, ErrRateLimited) {
		t.Errorf("OpenReply(count fails) = %v", err)
	}
	// A not-found from the store means the source or the link is gone.
	with(map[string]error{"createSession": store.ErrNotFound})
	_, err = ev.svc.OpenReply(ctx, ev.a, externalIP, src.target(1))
	wantErr(t, "OpenReply(create not found)", err, ErrReplyGone)
	ev.svc.repo = real
	if _, err := ev.svc.Session(ctx, ev.a, s.Token); err != nil {
		t.Errorf("Session after the faults = %v", err)
	}
}
