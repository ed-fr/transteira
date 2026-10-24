package scan

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// holdCount returns the holds of the transfer trfID of tn.
func (ev *env) holdCount(tn *tenant.Tenant, trfID string) int {
	ev.w.mu.Lock()
	defer ev.w.mu.Unlock()
	if h := ev.w.holds[key{tid: tn.ID, id: trfID}]; h != nil {
		return h.count
	}
	return 0
}

// isKnown reports whether the transfer trfID of tn is queued, running or
// waiting for a retry.
func (ev *env) isKnown(tn *tenant.Tenant, trfID string) bool {
	ev.w.mu.Lock()
	defer ev.w.mu.Unlock()
	return ev.w.known[key{tid: tn.ID, id: trfID}]
}

// hold holds the transfer trfID of tn for an erasure and fails on error.
func (ev *env) hold(tn *tenant.Tenant, trfID string) func() {
	ev.t.Helper()
	return ev.holdFor(tn, trfID, lifecycle.HoldForErase)
}

// holdFor holds the transfer trfID of tn with intent and fails on error.
func (ev *env) holdFor(tn *tenant.Tenant, trfID string, intent lifecycle.HoldIntent) func() {
	ev.t.Helper()
	release, err := ev.w.Hold(context.Background(), tn.ID, trfID, intent)
	if err != nil {
		ev.t.Fatalf("Hold: %v", err)
	}
	return release
}

// holdAsync holds the transfer trfID of tn from another goroutine, waits
// until the hold is registered, and returns the channel receiving its
// release function once Hold returned.
func (ev *env) holdAsync(tn *tenant.Tenant, trfID string) <-chan func() {
	ev.t.Helper()
	before := ev.holdCount(tn, trfID)
	out := make(chan func(), 1)
	go func() {
		release, err := ev.w.Hold(context.Background(), tn.ID, trfID, lifecycle.HoldForErase)
		if err != nil {
			ev.t.Errorf("Hold: %v", err)
		}
		out <- release
	}()
	ev.waitUntil("hold registered", func() bool { return ev.holdCount(tn, trfID) > before })
	return out
}

// eraseOutside erases the transfer trfID of tn as an administrator would:
// file keys and files first, then the deleted status.
func (ev *env) eraseOutside(tn *tenant.Tenant, trfID string) {
	ev.t.Helper()
	ctx := context.Background()
	d := ev.get(tn, trfID)
	if err := ev.uploads.RemoveFiles(ctx, tn.ID, d.Files); err != nil {
		ev.t.Fatal(err)
	}
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if d.DownloadTokenKeyID != "" {
			if err := ev.vault.DestroyTx(ctx, tx, d.DownloadTokenKeyID); err != nil {
				return err
			}
		}
		return ev.db.Transfers().SetStatusTx(ctx, tx, trfID, d.Status, store.TransferDeleted, time.Now())
	})
	if err != nil {
		ev.t.Fatal(err)
	}
}

// settle waits until the worker is idle and checks that the queue holds
// exactly n jobs.
func (ev *env) settle(n int) {
	ev.t.Helper()
	ev.waitIdle()
	time.Sleep(50 * time.Millisecond)
	ev.waitIdle()
	if jobs := ev.queue.snapshot(); len(jobs) != n {
		ev.t.Fatalf("%d mail jobs, want %d: %v", len(jobs), n, templates(jobs))
	}
}

// TestHoldProcessing cancels an analysis in progress and waits for it to
// stop, without counting an attempt, concluding or mailing; the release
// queues the transfer again.
func TestHoldProcessing(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{Workers: 1})
		trfID := ev.scanning(ev.a, clean(10))
		entered, unblock := ev.scanner.blockNext() // ignores the context
		ev.start()
		<-entered
		got := ev.holdAsync(ev.a, trfID)
		select {
		case <-got:
			t.Fatal("Hold returned before the analysis stopped")
		case <-time.After(50 * time.Millisecond):
		}
		close(unblock)
		release := <-got
		d := ev.get(ev.a, trfID)
		if d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanScanning || d.Files[0].ScanAttempts != 0 {
			t.Fatalf("after the hold: %s, file %s, %d attempts", d.Status, d.Files[0].ScanStatus, d.Files[0].ScanAttempts)
		}
		if ev.f.called("countAttempt") != 0 || ev.f.called("tenant") != 0 {
			t.Fatal("an attempt was counted or the transfer concluded")
		}
		// Held: Enqueue is ignored.
		ev.w.Enqueue(ev.a.ID, trfID)
		if ev.isKnown(ev.a, trfID) {
			t.Fatal("held transfer queued")
		}
		ev.settle(0)
		release()
		release() // harmless
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitJobs(3)
		if n := ev.holdCount(ev.a, trfID); n != 0 {
			t.Fatalf("%d holds left", n)
		}
	})
}

// TestHoldQueued drops a queued transfer, which the start-up sweep then
// ignores.
func TestHoldQueued(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		other := ev.scanning(ev.a, clean(10))
		ev.w.Enqueue(ev.a.ID, trfID)
		ev.w.Enqueue(ev.a.ID, other)
		release := ev.hold(ev.a, trfID)
		if ev.isKnown(ev.a, trfID) || len(ev.w.fifo) != 1 {
			t.Fatalf("held transfer still queued: %d queued", len(ev.w.fifo))
		}
		ev.start()
		ev.waitStatus(ev.a, other, store.TransferAvailable)
		ev.settle(3)
		if d := ev.get(ev.a, trfID); d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanPending {
			t.Fatalf("held transfer processed: %s %s", d.Status, d.Files[0].ScanStatus)
		}
		release()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitJobs(6)
	})
}

// TestHoldRetry drops a transfer waiting for a retry.
func TestHoldRetry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{RetryMin: time.Hour, RetryMax: time.Hour})
		trfID := ev.scanning(ev.a, clean(10))
		ev.f.set("scan", 1, antivirus.ErrTimeout)
		ev.start()
		ev.waitUntil("retry timer", func() bool {
			ev.w.mu.Lock()
			defer ev.w.mu.Unlock()
			return len(ev.w.timers) == 1
		})
		release := ev.hold(ev.a, trfID)
		ev.w.mu.Lock()
		timers, known := len(ev.w.timers), ev.w.known[key{tid: ev.a.ID, id: trfID}]
		ev.w.mu.Unlock()
		if timers != 0 || known {
			t.Fatalf("held transfer still waiting: %d timers, known %v", timers, known)
		}
		release()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		if d.Files[0].ScanAttempts != 1 {
			t.Fatalf("%d attempts", d.Files[0].ScanAttempts)
		}
	})
}

// TestHoldRelease queues a transfer again on release only when it is still
// scanning.
func TestHoldRelease(t *testing.T) {
	runEach := func(name string, fn func(t *testing.T, ev *env)) {
		t.Run(name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				ev.start()
				fn(t, ev)
			})
		})
	}
	runEach("deleted", func(t *testing.T, ev *env) {
		trfID := ev.scanning(ev.a, clean(10))
		release := ev.hold(ev.a, trfID)
		ev.eraseOutside(ev.a, trfID)
		release()
		ev.settle(0)
		if ev.scanner.count() != 0 || ev.get(ev.a, trfID).Status != store.TransferDeleted {
			t.Fatal("erased transfer analyzed")
		}
	})
	runEach("row deleted", func(t *testing.T, ev *env) {
		release := ev.hold(ev.a, "trf_unknown")
		release()
		ev.settle(0)
		if ev.f.called("transfer") != 1 {
			t.Fatalf("%d reads", ev.f.called("transfer"))
		}
	})
	runEach("malformed tenant", func(t *testing.T, ev *env) {
		release, err := ev.w.Hold(context.Background(), "not a tenant", "trf_x", lifecycle.HoldForErase)
		if err != nil {
			t.Fatal(err)
		}
		release()
		ev.settle(0)
		if ev.scanner.count() != 0 || ev.logs.count("queued anyway") != 0 {
			t.Fatal("malformed key queued")
		}
	})
	runEach("read failure", func(t *testing.T, ev *env) {
		trfID := ev.scanning(ev.a, clean(10))
		release := ev.hold(ev.a, trfID)
		ev.f.set("transfer", 1, nil)
		release()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		if ev.logs.count("held transfer not read on release, queued anyway") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
	runEach("refcount", func(t *testing.T, ev *env) {
		trfID := ev.scanning(ev.a, clean(10))
		first := ev.hold(ev.a, trfID)
		second := ev.hold(ev.a, trfID)
		first()
		first() // counted once
		ev.w.Enqueue(ev.a.ID, trfID)
		ev.settle(0)
		if ev.holdCount(ev.a, trfID) != 1 || ev.scanner.count() != 0 {
			t.Fatalf("%d holds, %d scans", ev.holdCount(ev.a, trfID), ev.scanner.count())
		}
		second()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
	})
}

// TestHoldContextDone gives up a hold whose context ends before the
// analysis stopped: the transfer is processed again.
func TestHoldContextDone(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{Workers: 1})
		trfID := ev.scanning(ev.a, clean(10))
		entered, unblock := ev.scanner.blockNext()
		ev.start()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := ev.w.Hold(ctx, ev.a.ID, trfID, lifecycle.HoldForErase)
			done <- err
		}()
		ev.waitUntil("hold registered", func() bool { return ev.holdCount(ev.a, trfID) == 1 })
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("Hold = %v", err)
		}
		if n := ev.holdCount(ev.a, trfID); n != 0 {
			t.Fatalf("%d holds left", n)
		}
		close(unblock)
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitJobs(3)
	})
}

// TestHoldClose holds across Close: the release does nothing, and Hold
// works on a closed worker.
func TestHoldClose(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{Workers: 1})
		trfID := ev.scanning(ev.a, clean(10))
		entered, unblock := ev.scanner.blockNext()
		ev.start()
		<-entered
		got := ev.holdAsync(ev.a, trfID)
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		closed := make(chan error, 1)
		go func() { closed <- ev.w.Close(ctx) }()
		close(unblock)
		release := <-got
		if err := <-closed; err != nil {
			t.Fatalf("Close: %v", err)
		}
		release()
		later := ev.hold(ev.a, trfID)
		later()
		if ev.f.called("transfer") != 1 || ev.isKnown(ev.a, trfID) {
			t.Fatalf("closed worker read %d times", ev.f.called("transfer"))
		}
	})
}

// waitHookHold makes the next call of the step name (repo, vault or
// notifier fault) hold the transfer for an erasure from another goroutine
// and wait until the hold is registered; the hold's release is sent on the
// returned channel.
func (ev *env) waitHookHold(name string, tn *tenant.Tenant, trfID string) <-chan func() {
	return ev.waitHookHoldFor(name, tn, trfID, lifecycle.HoldForErase)
}

// waitHookHoldFor is waitHookHold with the hold intent.
func (ev *env) waitHookHoldFor(name string, tn *tenant.Tenant, trfID string, intent lifecycle.HoldIntent) <-chan func() {
	out := make(chan func(), 1)
	ev.f.onCall(name, func() {
		// Counted before the hold is taken: with a hold already in place
		// (another hook), waiting for a non-zero count would not wait for
		// this one.
		before := ev.holdCount(tn, trfID)
		go func() {
			release, err := ev.w.Hold(context.Background(), tn.ID, trfID, intent)
			if err != nil {
				ev.t.Errorf("Hold: %v", err)
			}
			out <- release
		}()
		for ev.holdCount(tn, trfID) <= before {
			time.Sleep(time.Millisecond)
		}
	})
	return out
}

// TestHoldBeforeConclusion stops a transfer held after its files were
// analyzed, before the conclusion commits.
func TestHoldBeforeConclusion(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		got := ev.waitHookHold("tenant", ev.a, trfID)
		ev.start()
		release := <-got
		d := ev.get(ev.a, trfID)
		if d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanClean {
			t.Fatalf("held transfer: %s, file %s", d.Status, d.Files[0].ScanStatus)
		}
		if ev.f.called("makeAvailable") != 0 || ev.logs.count("stopped before its conclusion") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		ev.settle(0)
		release()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitJobs(3)
	})
}

// TestHoldDuringCommit sends no mail for a transfer held for an erasure
// while its conclusion was committing, or while its mails were being built
// (between the first check of the hold and the queueing).
func TestHoldDuringCommit(t *testing.T) {
	for _, step := range []string{"makeAvailable", "reject", "recipients", "problems"} {
		t.Run(step, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				content, want := clean(10), store.TransferAvailable
				if step == "reject" || step == "problems" {
					content, want = antivirustest.EICAR(), store.TransferRejected
				}
				trfID := ev.scanning(ev.a, content)
				got := ev.waitHookHold(step, ev.a, trfID)
				ev.start()
				release := <-got
				ev.waitStatus(ev.a, trfID, want)
				ev.settle(0)
				if ev.logs.count("transfer held for erasure: no mail sent") != 1 {
					t.Fatalf("logs:\n%s", ev.logs.all())
				}
				ev.eraseOutside(ev.a, trfID)
				release()
				ev.settle(0)
			})
		})
	}
}

// removeRecipient removes the recipient email from the transfer trfID of
// tn, as a GDPR erasure does under an edit hold.
func (ev *env) removeRecipient(tn *tenant.Tenant, trfID, email string) {
	ev.t.Helper()
	ctx := context.Background()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	if err := s.Tx(ctx, func(tx *store.ScopedTx) error {
		return ev.db.Transfers().RemoveRecipientTx(ctx, tx, trfID, email)
	}); err != nil {
		ev.t.Fatal(err)
	}
}

// downloadLink returns the download link of the available transfer d,
// unsealed from the database.
func (ev *env) downloadLink(tn *tenant.Tenant, d store.TransferDetails) string {
	ev.t.Helper()
	raw, err := ev.vault.Open(context.Background(), tn.ID, crypto.PurposeSecret, d.DownloadTokenKeyID)
	if err != nil {
		ev.t.Fatal(err)
	}
	return id.DownloadURL(tn.FQDN, string(raw))
}

// TestHoldForEditDefersMails defers the mails of a conclusion committed, or
// built, while the transfer was held for an edit: the last release sends
// them from the current state of the transfer, to its remaining
// recipients, with its download link.
func TestHoldForEditDefersMails(t *testing.T) {
	for _, step := range []string{"makeAvailable", "reject", "recipients", "problems"} {
		t.Run(step, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				rejected := step == "reject" || step == "problems"
				content, want := clean(10), store.TransferAvailable
				if rejected {
					content, want = antivirustest.EICAR(), store.TransferRejected
				}
				trfID := ev.scanning(ev.a, content)
				got := ev.waitHookHoldFor(step, ev.a, trfID, lifecycle.HoldForEdit)
				ev.start()
				release := <-got
				d := ev.waitStatus(ev.a, trfID, want)
				ev.settle(0)
				if ev.logs.count("mails deferred to the release") != 1 {
					t.Fatalf("logs:\n%s", ev.logs.all())
				}
				// A second edit hold: only the last release sends.
				second := ev.holdFor(ev.a, trfID, lifecycle.HoldForEdit)
				ev.removeRecipient(ev.a, trfID, erin)
				release()
				ev.settle(0)
				second()
				if rejected {
					jobs := ev.waitJobs(1)
					if templates(jobs)[0] != mail.TemplateFileProblems || !slices.Equal(jobs[0].Message.To, []string{alice}) {
						t.Fatalf("jobs %v", templates(jobs))
					}
					ev.settle(1)
					return
				}
				jobs := ev.waitJobs(2)
				ev.settle(2)
				link := ev.downloadLink(ev.a, d)
				notif := byTemplate(jobs, mail.TemplateTransferNotification)
				if len(notif) != 1 || !slices.Equal(notif[0].Message.To, []string{dave}) || !strings.Contains(notif[0].Message.Text, link) {
					t.Fatalf("recipient mails %v", templates(jobs))
				}
				conf := byTemplate(jobs, mail.TemplateTransferConfirmation)
				if len(conf) != 1 || !strings.Contains(conf[0].Message.Text, link) {
					t.Fatalf("confirmation %v", templates(jobs))
				}
			})
		})
	}
}

// TestHoldForEditThenErase cancels the deferred mails when an erasure hold
// is taken before the release, whatever the outcome of the erasure.
func TestHoldForEditThenErase(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		got := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
		ev.start()
		edit := <-got
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.settle(0)
		erase := ev.hold(ev.a, trfID)
		edit()
		erase()
		ev.settle(0)
	})
}

// TestHoldForEditUnderErase drops the mails of a conclusion committed while
// the transfer was held both for an edit and for an erasure.
func TestHoldForEditUnderErase(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		gotEdit := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
		got := ev.waitHookHold("seal", ev.a, trfID)
		ev.start()
		edit, erase := <-gotEdit, <-got
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.settle(0)
		if ev.logs.count("transfer held for erasure: no mail sent") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		edit()
		erase()
		ev.settle(0)
	})
}

// TestHoldForEditReleaseEdges covers the last release of a transfer whose
// mails were deferred, when they cannot be sent.
func TestHoldForEditReleaseEdges(t *testing.T) {
	runEach := func(name string, fn func(t *testing.T, ev *env, trfID string, release func())) {
		t.Run(name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				trfID := ev.scanning(ev.a, clean(10))
				got := ev.waitHookHoldFor("makeAvailable", ev.a, trfID, lifecycle.HoldForEdit)
				ev.start()
				release := <-got
				ev.waitStatus(ev.a, trfID, store.TransferAvailable)
				ev.settle(0)
				fn(t, ev, trfID, release)
			})
		})
	}
	runEach("ended", func(t *testing.T, ev *env, trfID string, release func()) {
		ev.eraseOutside(ev.a, trfID)
		release()
		ev.settle(0)
		if ev.logs.count("deferred notification mails dropped") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
	runEach("row deleted", func(_ *testing.T, ev *env, _ string, release func()) {
		ev.f.set("transfer", 1, store.ErrNotFound)
		release()
		ev.settle(0)
	})
	runEach("read failure", func(t *testing.T, ev *env, _ string, release func()) {
		ev.f.set("transfer", 1, nil)
		release()
		ev.settle(0)
		if ev.logs.count("deferred notification mails not sent") != 1 || ev.logs.count("queued anyway") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
	runEach("tenant failure", func(t *testing.T, ev *env, _ string, release func()) {
		ev.f.set("tenant", 1, nil)
		release()
		ev.settle(0)
		if ev.logs.count("deferred notification mails not sent: tenant not read") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
	runEach("token failure", func(t *testing.T, ev *env, _ string, release func()) {
		ev.f.set("openSecret", 1, nil)
		release()
		ev.settle(0)
		if ev.logs.count("deferred notification mails not sent: download token not opened") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
	runEach("closed", func(t *testing.T, ev *env, _ string, release func()) {
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := ev.w.Close(ctx); err != nil {
			t.Fatal(err)
		}
		release()
		if ev.logs.count("worker closed: deferred notification mails not sent") != 1 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
		if jobs := ev.queue.snapshot(); len(jobs) != 0 {
			t.Fatalf("jobs %v", templates(jobs))
		}
	})
}

// TestEraseWhileScanning erases, through lifecycle, a transfer whose
// analysis is in progress: it is never made available and nobody is
// mailed.
func TestEraseWhileScanning(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{Workers: 1})
		sweeper := lifecycle.New(lifecycle.Deps{
			DB: ev.db, Vault: ev.vault, Remover: ev.uploads, Files: ev.files, Holder: ev.w,
		}, lifecycle.Options{})
		trfID := ev.scanning(ev.a, clean(10), clean(20))
		entered, unblock := ev.scanner.blockNext()
		ev.start()
		<-entered
		type result struct {
			res lifecycle.EraseResult
			err error
		}
		done := make(chan result, 1)
		go func() {
			res, err := sweeper.EraseTransfer(context.Background(), ev.a.ID, trfID, lifecycle.MarkDeleted)
			done <- result{res, err}
		}()
		ev.waitUntil("hold registered", func() bool { return ev.holdCount(ev.a, trfID) == 1 })
		close(unblock)
		r := <-done
		if r.err != nil || r.res != lifecycle.Erased {
			t.Fatalf("EraseTransfer = %v, %v", r.res, r.err)
		}
		ev.settle(0)
		d := ev.get(ev.a, trfID)
		if d.Status != store.TransferDeleted || d.DownloadTokenKeyID != "" {
			t.Fatalf("status %s", d.Status)
		}
		for i, f := range d.Files {
			if f.DEKKeyID != "" {
				t.Fatalf("file %d keeps its key", i)
			}
		}
		if ev.scanner.count() != 1 || ev.f.called("makeAvailable") != 0 || ev.holdCount(ev.a, trfID) != 0 {
			t.Fatalf("%d scans, %d conclusions", ev.scanner.count(), ev.f.called("makeAvailable"))
		}
	})
}

// recAudit records the audit events written through the real writer; err
// fails every write instead.
type recAudit struct {
	inner *audit.Writer
	err   error

	mu     sync.Mutex
	events []audit.Event
	calls  int
}

func (a *recAudit) RecordScoped(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	if err := a.inner.RecordScoped(ctx, tid, ev); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *recAudit) snapshot() ([]audit.Event, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Event(nil), a.events...), a.calls
}

// recUsage counts the virus detections per tenant.
type recUsage struct {
	mu    sync.Mutex
	count map[tenant.ID]int
}

func (u *recUsage) VirusDetected(tid tenant.ID, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if at.IsZero() {
		panic("zero time")
	}
	u.count[tid]++
}

func (u *recUsage) get(tid tenant.ID) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.count[tid]
}

// withAudit replaces the audit and usage of the worker of ev.
func (ev *env) withAudit(err error) (*recAudit, *recUsage) {
	a := &recAudit{inner: audit.New(ev.db), err: err}
	u := &recUsage{count: map[tenant.ID]int{}}
	ev.w.audit, ev.w.usage = a, u
	return a, u
}

func TestAuditAndUsage(t *testing.T) {
	cases := []struct {
		name    string
		result  *antivirus.Result
		action  audit.Action
		details map[string]any
		viruses int
	}{
		{
			"infected", &antivirus.Result{Verdict: antivirus.Infected, Signature: "Eicar-Test-Signature"},
			audit.ActionFileInfected,
			map[string]any{"signature": "Eicar-Test-Signature"},
			1,
		},
		{
			"infected, signature with an at sign", &antivirus.Result{Verdict: antivirus.Infected, Signature: "Mail.Worm@x"},
			audit.ActionFileInfected,
			map[string]any{},
			1,
		},
		{
			"infected without signature", &antivirus.Result{Verdict: antivirus.Infected},
			audit.ActionFileInfected,
			map[string]any{},
			1,
		},
		{
			"too large", &antivirus.Result{Verdict: antivirus.TooLarge, Detail: antivirus.DetailClientLimit},
			audit.ActionFileNotScanned,
			map[string]any{"reason": "too_large"},
			0,
		},
		{
			"encrypted", &antivirus.Result{Verdict: antivirus.Unscannable},
			audit.ActionFileNotScanned,
			map[string]any{"reason": "encrypted"},
			0,
		},
		{"clean", nil, "", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				a, u := ev.withAudit(nil)
				ev.scanner.result = c.result
				trfID := ev.scanning(ev.a, clean(10))
				ev.start()
				ev.waitIdle()
				d := ev.get(ev.a, trfID)
				events, _ := a.snapshot()
				if u.get(ev.a.ID) != c.viruses {
					t.Fatalf("%d virus detections, want %d", u.get(ev.a.ID), c.viruses)
				}
				if c.action == "" {
					if len(events) != 0 {
						t.Fatalf("events %v", events)
					}
					return
				}
				if len(events) != 1 {
					t.Fatalf("%d events", len(events))
				}
				ev0 := events[0]
				if ev0.Action != c.action || ev0.ActorKind != store.ActorSystem || ev0.Actor != SystemActor ||
					ev0.ObjectKind != audit.ObjectFile || ev0.ObjectID != d.Files[0].ID || ev0.Details["transferId"] != trfID {
					t.Fatalf("event %+v", ev0)
				}
				for k, v := range c.details {
					if ev0.Details[k] != v {
						t.Fatalf("details %v, want %s=%v", ev0.Details, k, v)
					}
				}
				if _, ok := ev0.Details["signature"]; ok && c.details["signature"] == nil {
					t.Fatalf("signature kept: %v", ev0.Details)
				}
				// The event reached the audit log of the tenant.
				page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{TenantID: ev.a.ID, Limit: 10})
				if err != nil {
					t.Fatal(err)
				}
				if len(page.Items) != 1 || page.Items[0].Action != string(c.action) {
					t.Fatalf("audit log %+v", page.Items)
				}
			})
		})
	}
}

// TestAuditFailure logs an audit failure without changing the outcome.
func TestAuditFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		a, u := ev.withAudit(errFault)
		ev.scanner.result = &antivirus.Result{Verdict: antivirus.Infected, Signature: "Eicar-Test-Signature"}
		trfID := ev.scanning(ev.a, clean(10), clean(10))
		ev.start()
		ev.waitStatus(ev.a, trfID, store.TransferRejected)
		ev.waitIdle()
		if _, calls := a.snapshot(); calls != 2 || u.get(ev.a.ID) != 2 {
			t.Fatalf("%d audit calls, %d detections", calls, u.get(ev.a.ID))
		}
		if ev.logs.count("audit write failed") != 2 {
			t.Fatalf("logs:\n%s", ev.logs.all())
		}
	})
}
