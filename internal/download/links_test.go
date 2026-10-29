package download

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/vcode"
)

// linkState returns the served range state of the recipient link i of p,
// nil when there is none.
func (ev *env) linkState(p published, i int) served {
	ev.t.Helper()
	b, err := ev.files.ReadState(p.tn.ID, storage.StateName(p.links[i].ID))
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		ev.t.Fatal(err)
	}
	st, err := decodeServed(b)
	if err != nil {
		ev.t.Fatal(err)
	}
	return st
}

// tracking returns the tracking of the recipients of p.
func (ev *env) tracking(p published) []store.RecipientTracking {
	ev.t.Helper()
	tr, err := ev.db.RecipientLinks().TrackingByTransfer(context.Background(), p.tn.ID, p.id)
	if err != nil {
		ev.t.Fatal(err)
	}
	return tr
}

// archive downloads the whole archive of p.
func (ev *env) archive(p published) {
	ev.t.Helper()
	ctx := context.Background()
	a, err := ev.svc.PrepareArchive(ctx, p.tn, p.token, ipOne, Cookies{})
	if err != nil {
		ev.t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := a.Write(ctx, &buf); err != nil {
		ev.t.Fatal(err)
	}
}

// receiptRecipients returns the recipients named by the first download
// mails built, and their deletion times.
func (ev *env) receiptRecipients() ([]string, []time.Time) {
	ev.notifier.mu.Lock()
	defer ev.notifier.mu.Unlock()
	return append([]string(nil), ev.notifier.recipients...), append([]time.Time(nil), ev.notifier.deleteAts...)
}

// TestRecipientTracking: each link keeps its own served ranges and
// completion; the first completed link records the first download of the
// transfer and the receipt names its recipient; the deletion after the
// first download waits for every link (P27, T-205, T-206).
func TestRecipientTracking(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{
			contents: [][]byte{random(3000), random(500)}, perRecipient: true, recipients: []string{dave, erin}, deleteAfter: true,
		})
		dl, er := p.link(0), p.link(1)
		// Half of the first file through each link: nothing is complete,
		// whatever the two links served together.
		ev.fetch(dl, "", p.files[0].ID, 0, 1500, true)
		ev.fetch(er, "", p.files[0].ID, 1500, -1, true)
		if ev.state(p) != nil || ev.linkState(p, 0) == nil || ev.linkState(p, 1) == nil {
			t.Fatal("range states not kept per link")
		}
		if d := ev.get(p); !d.FirstDownloadedAt.IsZero() {
			t.Fatal("completed by two links together")
		}
		// The first link completes.
		ev.fetch(dl, "", p.files[0].ID, 1500, -1, true)
		ev.complete(dl)
		d := ev.get(p)
		if d.FirstDownloadedAt.IsZero() || !d.DeleteAfter.IsZero() {
			t.Fatalf("after the first link: first %v, delete after %v", d.FirstDownloadedAt, d.DeleteAfter)
		}
		if ev.linkState(p, 0) != nil {
			t.Fatal("range state of the completed link kept")
		}
		ev.waitUntil("receipt", func() bool { return len(ev.firstDownloads()) == 1 })
		if who, at := ev.receiptRecipients(); len(who) != 1 || who[0] != dave || !at[0].IsZero() {
			t.Fatalf("receipt for %v deleting at %v", who, at)
		}
		tr := ev.tracking(p)
		if tr[0].CompletedAt.IsZero() || !tr[1].CompletedAt.IsZero() || len(tr[0].Downloads) != 2 {
			t.Fatalf("tracking %+v", tr)
		}
		for _, item := range tr[0].Downloads {
			if item.CompletedAt.IsZero() {
				t.Fatalf("item %+v not complete", item)
			}
		}
		// Downloading again through a completed link records nothing more.
		ev.fetch(dl, "", p.files[1].ID, 0, -1, true)
		if ev.linkState(p, 0) != nil {
			t.Fatal("range state written for a completed link")
		}
		// The second link completes with the archive: the transfer is now
		// due for deletion, and no second receipt is sent.
		ev.archive(er)
		d = ev.get(p)
		if d.DeleteAfter.IsZero() {
			t.Fatal("not due for deletion once every link completed")
		}
		if ev.linkState(p, 1) != nil {
			t.Fatal("range state of the second link kept")
		}
		tr = ev.tracking(p)
		if tr[1].CompletedAt.IsZero() {
			t.Fatalf("tracking %+v", tr)
		}
		var archived bool
		for _, item := range tr[1].Downloads {
			if item.FileID == "" && !item.CompletedAt.IsZero() {
				archived = true
			}
		}
		if !archived {
			t.Fatalf("archive not tracked: %+v", tr[1].Downloads)
		}
		if who, _ := ev.receiptRecipients(); len(who) != 1 {
			t.Fatalf("receipts %v", who)
		}
		// The downloads name the link in the audit.
		for _, a := range ev.downloadEvents(ev.a.ID) {
			if !strings.Contains(string(a.Details), `"link":"rcl_`) {
				t.Fatalf("download event without link: %s", a.Details)
			}
		}
	})
}

// TestRecipientSingleLink: with one recipient, the receipt announces the
// deletion, as for a shared link.
func TestRecipientSingleLink(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, deleteAfter: true})
		ev.archive(p)
		ev.waitUntil("receipt", func() bool { return len(ev.firstDownloads()) == 1 })
		if who, at := ev.receiptRecipients(); len(who) != 1 || who[0] != dave || at[0].IsZero() {
			t.Fatalf("receipt for %v deleting at %v", who, at)
		}
		if ev.get(p).DeleteAfter.IsZero() {
			t.Fatal("not due for deletion")
		}
		// A shared link names nobody.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		ev.archive(q)
		ev.waitUntil("second receipt", func() bool { return len(ev.firstDownloads()) == 2 })
		if who, _ := ev.receiptRecipients(); who[1] != "" {
			t.Fatalf("shared receipt names %q", who[1])
		}
	})
}

// TestRecipientStartsPerLink: two recipients behind one address are each
// counted through their own link, and the download limit counts the starts
// of every link together.
func TestRecipientStartsPerLink(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}})
		ev.fetch(p.link(0), "", p.files[0].ID, 0, 10, true)
		ev.fetch(p.link(1), "", p.files[0].ID, 0, 10, true)
		ev.fetch(p.link(1), "", p.files[0].ID, 0, 10, true) // within the window: not counted again
		links, err := ev.db.RecipientLinks().ListByTransfer(context.Background(), ev.a.ID, p.id)
		if err != nil || links[0].DownloadCount != 1 || links[1].DownloadCount != 1 || ev.get(p).DownloadCount != 2 {
			t.Fatalf("links %+v, transfer %d, %v", links, ev.get(p).DownloadCount, err)
		}

		q := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}, maxDownloads: 1})
		if err := ev.beginAs(q.link(0), ipOne, q.files[0].ID, true); err != nil {
			t.Fatal(err)
		}
		wantErr(t, ev.beginAs(q.link(1), ipTwo, q.files[0].ID, true), ErrMaxDownloads)
		a, err := ev.svc.PrepareArchive(context.Background(), ev.a, q.link(1).token, ipTwo, Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		wantErr(t, a.Begin(context.Background(), true), ErrMaxDownloads)
		links, _ = ev.db.RecipientLinks().ListByTransfer(context.Background(), ev.a.ID, q.id)
		if links[0].DownloadCount != 1 || links[1].DownloadCount != 0 {
			t.Fatalf("links %+v", links)
		}
	})
}

// TestRecipientPasswordPerLink: the wrong passwords of one link lock that
// link only (the per-IP counter is unchanged), and a grant opens its own
// link only.
func TestRecipientPasswordPerLink(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}, password: true})
		ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
		for i, ip := range ips {
			_, err := ev.svc.Unlock(ctx, ev.a, p.token, netip.MustParseAddr(ip), "wrong", Cookies{})
			if i < len(ips)-1 {
				wantErr(t, err, ErrWrongPassword)
			} else {
				wantErr(t, err, ErrLocked)
			}
		}
		_, err := ev.svc.Unlock(ctx, ev.a, p.token, ipTwo, password, Cookies{})
		wantErr(t, err, ErrLocked)
		grant, err := ev.svc.Unlock(ctx, ev.a, p.link(1).token, ipTwo, password, Cookies{})
		if err != nil {
			t.Fatalf("other link locked too: %v", err)
		}
		if v, _ := ev.svc.Resolve(ctx, ev.a, p.link(1).token, Cookies{Grant: grant}); v.Locked {
			t.Fatal("grant does not open its link")
		}
		if v, _ := ev.svc.Resolve(ctx, ev.a, p.token, Cookies{Grant: grant}); !v.Locked {
			t.Fatal("grant of a link opens another link")
		}
	})
}

// TestRecipientCompletionFaults covers the failures of the recording of a
// completion through a link.
func TestRecipientCompletionFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100)}, perRecipient: true, recipients: []string{dave, erin}})
		// The completion of the item and of the link fail: the state is
		// kept, and the next request records them.
		ev.f.set("completeItem", 1, nil)
		ev.f.set("completeLink", 1, nil)
		ev.complete(p)
		if ev.logs.count("recipient download completion not recorded") != 1 || ev.linkState(p, 0) == nil {
			t.Fatal("failures not logged or state lost")
		}
		if !ev.get(p).FirstDownloadedAt.IsZero() {
			t.Fatal("recorded despite the failure")
		}
		ev.fetch(p, "", p.files[0].ID, 0, 1, true)
		if ev.get(p).FirstDownloadedAt.IsZero() || ev.linkState(p, 0) != nil {
			t.Fatal("completion not recorded at the next request")
		}

		// A link whose start was never recorded completes without being
		// recorded, which is logged; its state is dropped.
		ev.f.set("started", 1, nil)
		ev.complete(p.link(1))
		if ev.logs.count("whose start was not recorded") != 1 || ev.linkState(p, 1) != nil {
			t.Fatal("unclaimed completion not settled")
		}

		// The state of a link is not written when the link cannot be read
		// (kept), is gone, or is complete.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(3000)}, perRecipient: true, recipients: []string{dave, erin}})
		k := key{tid: ev.a.ID, id: q.id, link: q.links[0].ID}
		st := served{q.files[0].ID: {{0, 5}}}
		ev.f.set("link", 1, nil)
		if ev.svc.write(context.Background(), k, st, 5) || ev.svc.pending[k] == nil {
			t.Fatal("state of an unreadable link not kept")
		}
		ev.f.set("link", 1, store.ErrNotFound)
		if !ev.svc.write(context.Background(), k, st, 5) || ev.linkState(q, 0) != nil {
			t.Fatal("state of a missing link written")
		}
		ev.complete(q.link(1))
		k1 := key{tid: ev.a.ID, id: q.id, link: q.links[1].ID}
		if !ev.svc.write(context.Background(), k1, st, 5) || ev.linkState(q, 1) != nil {
			t.Fatal("state of a completed link written")
		}
		if !ev.svc.write(context.Background(), k, st, 5) || ev.linkState(q, 0) == nil {
			t.Fatal("state of a live link not written")
		}
	})
}

// TestStoreRepoLinkFailures covers the failures of the recipient link and
// challenge methods of the store repository, each rolling its transaction
// back.
func TestStoreRepoLinkFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		r := ev.svc.repo.(faultRepo).inner
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, perRecipient: true, verify: true, maxDownloads: 5})
		now := ev.clock.now()
		unknown := "rcl_01JAAAAAAAAAAAAAAAAAAAAAAA"
		if _, err := r.claim(ctx, ev.a.ID, p.id, unknown, "", now, now, startEvent(p.id, unknown, archiveObject, ipOne)); err == nil {
			t.Fatal("claim through an unknown link")
		}
		if ev.get(p).DownloadCount != 0 {
			t.Fatal("claim not rolled back")
		}
		if _, err := r.link(ctx, "", p.links[0].ID); err == nil {
			t.Fatal("link of an invalid tenant")
		}
		if _, err := r.completeLink(ctx, ev.a.ID, p.id, unknown, now, time.Time{}); err == nil || errors.Is(err, errLinkUnclaimed) {
			t.Fatalf("completion of an unknown link: %v", err)
		}
		ch := store.Challenge{
			ID: "vch_0000000000000000000000", Email: dave, CodeMAC: []byte{1}, AttemptsRemaining: 1, ClientIP: ipOne,
			CreatedAt: now, ExpiresAt: now.Add(time.Minute), Purpose: store.ChallengeRecipient,
			RecipientLinkID: "bad", RecipientIntent: store.IntentDownload,
		}
		if _, err := r.createChallenge(ctx, ev.a.ID, ch, now); err == nil {
			t.Fatal("challenge of a malformed link")
		}
		ch.RecipientLinkID, ch.ClientIP = p.links[0].ID, netip.Addr{}
		if _, err := r.createChallenge(ctx, ev.a.ID, ch, now); err == nil {
			t.Fatal("challenge without client IP")
		}
		ev.start(p, "")
		pending, err := r.latestChallenge(ctx, ev.a.ID, p.links[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		chID := pending.ID
		ok := audit.Event{
			ActorKind: store.ActorRecipient, Actor: dave, Action: audit.ActionRecipientVerified,
			ObjectKind: audit.ObjectTransfer, ObjectID: p.id,
		}
		if err := r.verified(ctx, ev.a.ID, chID, unknown, now, ok); err == nil {
			t.Fatal("verification of an unknown link")
		}
		bad := ok
		bad.Actor = ""
		if err := r.verified(ctx, ev.a.ID, chID, p.links[0].ID, now, bad); err == nil {
			t.Fatal("verification with an invalid event")
		}
		// Both rolled back: the code is still pending.
		if c, err := r.latestChallenge(ctx, ev.a.ID, p.links[0].ID); err != nil || c.ID != chID || !c.Open(now) {
			t.Fatalf("challenge %+v, %v", c, err)
		}
		if err := r.verified(ctx, ev.a.ID, "vch_0000000000000000000000", p.links[0].ID, now, ok); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("verification with an unknown challenge: %v", err)
		}
		// The budget of the link is enforced in the transaction (a
		// request racing another one past a check of the service); the code
		// sent above counts.
		ch.ClientIP = ipTwo
		for i := range vcode.MaxPerAddress - 1 {
			ch.ID = fmt.Sprintf("vch_%022d", i+1)
			if _, err := r.createChallenge(ctx, ev.a.ID, ch, now.Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		ch.ID = "vch_9999999999999999999999"
		if scope, err := r.createChallenge(ctx, ev.a.ID, ch, now.Add(-time.Hour)); !errors.Is(err, errLimited) || scope != scopeCodesPerLink {
			t.Fatalf("over the link budget: %q, %v", scope, err)
		}
	})
}

// TestVerificationErrorMessages checks the messages of the error types.
func TestVerificationErrorMessages(t *testing.T) {
	t.Parallel()
	if msg := (&WrongCodeError{Remaining: 1}).Error(); !strings.Contains(msg, "1 attempt") {
		t.Errorf("WrongCodeError: %q", msg)
	}
	if msg := (&RateLimitError{RetryAfter: time.Hour}).Error(); !strings.Contains(msg, "1h0m0s") {
		t.Errorf("RateLimitError: %q", msg)
	}
	if !errors.Is(&RateLimitError{}, ErrRateLimited) || !errors.Is(&WrongCodeError{}, ErrWrongCode) {
		t.Error("error types do not match their sentinels")
	}
}
