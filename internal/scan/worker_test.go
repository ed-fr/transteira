package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestSweep resumes at start-up the scanning transfers of every tenant,
// page after page.
func TestSweep(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.w.sweepLimit = 2 // pages of 2: the sweep needs three pages
		trfA1 := ev.scanning(ev.a, clean(10))
		trfA2 := ev.scanning(ev.a, clean(10))
		trfB := ev.scanning(ev.b, clean(10))
		ev.start()
		if err := ev.w.Start(context.Background()); !errors.Is(err, ErrStarted) {
			t.Errorf("second Start: %v", err)
		}
		ev.waitStatus(ev.a, trfA1, store.TransferAvailable)
		ev.waitStatus(ev.a, trfA2, store.TransferAvailable)
		ev.waitStatus(ev.b, trfB, store.TransferAvailable)
		jobs := ev.waitJobs(9)
		perTenant := map[string]int{}
		for _, j := range jobs {
			perTenant[j.TenantID]++
		}
		if perTenant[ev.a.ID.String()] != 6 || perTenant[ev.b.ID.String()] != 3 {
			t.Errorf("jobs per tenant %v", perTenant)
		}
		ev.waitUntil("last sweep", func() bool { return ev.f.called("sweep") >= 2 })
	})
}

// TestSweepDuringOutage keeps sweeping without spinning while the swept
// transfers wait for clamd, and stops at shutdown.
func TestSweepDuringOutage(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.w.sweepLimit = 1
		ev.clamd.Stop()
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		ev.waitUntil("second sweep", func() bool { return ev.f.called("sweep") >= 2 })
		// The page holds a transfer waiting for a retry: the sweeper waits
		// for a release instead of sweeping again at once, however many
		// retries happen meanwhile.
		scans := ev.scanner.count()
		ev.waitUntil("three more retries", func() bool { return ev.scanner.count() >= scans+3 })
		if n := ev.f.called("sweep"); n != 2 {
			t.Errorf("%d sweeps during the outage", n)
		}
		ev.clamd.Restart(t)
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitUntil("third sweep", func() bool { return ev.f.called("sweep") >= 3 })
	})
}

// TestSweepStopsAtShutdown stops a sweeper waiting for the queue.
func TestSweepStopsAtShutdown(t *testing.T) {
	for _, outage := range []bool{false, true} {
		t.Run(fmt.Sprint("outage=", outage), func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{Workers: 1})
				ev.w.sweepLimit = 1
				if outage {
					ev.clamd.Stop()
				}
				ev.scanning(ev.a, clean(10))
				entered, release := ev.scanner.blockNext()
				ev.start()
				<-entered
				if outage {
					close(release)
					ev.waitUntil("second sweep", func() bool { return ev.f.called("sweep") >= 2 })
				}
				ctx, cancel := context.WithTimeout(context.Background(), waitFor)
				defer cancel()
				done := make(chan error)
				go func() { done <- ev.w.Close(ctx) }()
				if !outage {
					ev.waitUntil("shutdown", func() bool {
						ev.w.mu.Lock()
						defer ev.w.mu.Unlock()
						return ev.w.closed
					})
					close(release)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

// TestSweepFailures reports a failed first sweep and logs a failed later
// one.
func TestSweepFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.f.set("sweep", 1, nil)
		if err := ev.w.Start(context.Background()); !errors.Is(err, errFault) {
			t.Fatalf("Start: %v", err)
		}
		// The workers run anyway.
		trfID := ev.scanning(ev.a, clean(10))
		ev.w.Enqueue(ev.a.ID, trfID)
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
	})
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev2 := newEnv(t, e, Options{})
		ev2.w.sweepLimit = 1
		ev2.scanning(ev2.a, clean(10))
		ev2.f.failAfter("sweep", 1) // the second sweep fails
		ev2.start()
		ev2.waitUntil("failed sweep log", func() bool { return ev2.logs.count("antivirus sweep failed") == 1 })
	})
}

// TestDedup processes once a transfer enqueued several times.
func TestDedup(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{Workers: 4})
		ev.f.set("sweep", 0, nil)
		trfID := ev.scanning(ev.a, clean(10), clean(20))
		entered, release := ev.scanner.blockNext()
		ev.w.Enqueue(ev.a.ID, trfID) // before Start: queued
		ev.w.Enqueue(ev.a.ID, trfID)
		ev.start() // the sweep finds it too
		<-entered
		for range 5 {
			ev.w.Enqueue(ev.a.ID, trfID) // being processed: ignored
		}
		close(release)
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitJobs(3)
		if n := ev.scanner.count(); n != 2 {
			t.Errorf("%d scans, want 2", n)
		}
	})
}

// TestShutdownMidScan leaves the file scanning, without counting an
// attempt, when the worker stops during an analysis.
func TestShutdownMidScan(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.clamd.SetMode(antivirustest.ModeHang)
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		// The file is marked scanning before the scan starts.
		ev.waitUntil("scan in progress", func() bool { return ev.scanner.count() == 1 })
		ctx, cancel := context.WithTimeout(context.Background(), waitFor)
		defer cancel()
		if err := ev.w.Close(ctx); err != nil {
			t.Fatal(err)
		}
		d := ev.get(ev.a, trfID)
		if d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanScanning || d.Files[0].ScanAttempts != 0 {
			t.Errorf("after shutdown: %s %s %d", d.Status, d.Files[0].ScanStatus, d.Files[0].ScanAttempts)
		}
		if ev.logs.count("antivirus unavailable") != 0 || ev.logs.count("failed") != 0 {
			t.Errorf("logs:\n%s", ev.logs.all())
		}
		// Closed: new transfers are ignored, and Close is idempotent.
		ev.w.Enqueue(ev.a.ID, trfID)
		if err := ev.w.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if len(ev.w.fifo) != 0 {
			t.Errorf("transfer queued after Close")
		}
		// A new worker resumes it.
		ev.clamd.SetMode(antivirustest.ModeScan)
		w2 := New(Deps{
			DB: ev.db, Vault: ev.vault, Files: ev.files, Scanner: ev.client, Remover: ev.uploads,
			Notifier: notify.New(ev.vault, ev.db.SMTPSettings(), nil, notify.Options{}), Mail: ev.queue,
		}, Options{RetryMin: retryMin, RetryMax: retryMax})
		if err := w2.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w2.Close(ctx) }()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
	})
}

// TestShutdownDuringDBStep stops without retrying when a database step
// fails because of the shutdown.
func TestShutdownDuringDBStep(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		ev.f.set("setScanning", 1, nil)
		ev.f.onCall("setScanning", func() { ev.w.cancel() })
		ev.start()
		ev.waitUntil("worker stopped", func() bool {
			ev.w.mu.Lock()
			defer ev.w.mu.Unlock()
			return ev.w.closed && ev.w.running == 0
		})
		if d := ev.get(ev.a, trfID); d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanPending {
			t.Errorf("after shutdown: %s %s", d.Status, d.Files[0].ScanStatus)
		}
		if ev.logs.count("will retry") != 0 {
			t.Errorf("retry logged at shutdown")
		}
	})
}

// TestCloseTimeout returns the context error when a worker does not stop in
// time, and Close before Start does nothing harmful.
func TestCloseTimeout(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		entered, release := ev.scanner.blockNext() // ignores the context
		ev.start()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := ev.w.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("Close: %v", err)
		}
		close(release)

		w := New(Deps{}, Options{})
		if err := w.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		w.Enqueue(ev.a.ID, trfID)
		if len(w.fifo) != 0 {
			t.Errorf("queued after Close")
		}
	})
}

// TestMailRetry retries the mails refused by a full queue or an open
// circuit, and drops the others with an error line.
func TestMailRetry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.queue.errs = []error{mail.ErrQueueFull, mail.ErrCircuitOpen, mail.ErrQueueClosed, mail.ErrQueueFull}
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		// 3 jobs: the first round refuses all three (one for good), the
		// second round refuses one of the remaining two, the third takes it.
		ev.waitJobs(2)
		if ev.logs.count("refused by the queue, will retry") != 2 || ev.logs.count("notification mail refused") != 1 {
			t.Errorf("logs:\n%s", ev.logs.all())
		}
	})
}

// TestMailRetryGivesUp drops the mails still refused at the deadline.
func TestMailRetryGivesUp(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{MailRetryFor: 3 * retryMin})
		ev.queue.failAll = mail.ErrCircuitOpen
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitUntil("drop", func() bool { return ev.logs.count("kept refusing") == 1 })
		ev.waitIdle()
		if n := ev.logs.count("refused by the queue, will retry"); n != 1 {
			t.Errorf("%d retries, want 1", n)
		}
	})
}

// TestMailRetryLostAtShutdown logs the mails waiting for a retry when the
// worker stops.
func TestMailRetryLostAtShutdown(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{RetryMin: time.Hour, RetryMax: time.Hour, MailRetryFor: 2 * time.Hour})
		ev.queue.failAll = mail.ErrQueueFull
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		ev.waitUntil("retry scheduled", func() bool { return ev.logs.count("will retry") == 1 })
		if err := ev.w.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if ev.logs.count("dropped at shutdown") != 1 {
			t.Errorf("logs:\n%s", ev.logs.all())
		}
		// A retry scheduled once closed is dropped and logged too.
		ev.w.schedule(context.Background(), task{mails: &mailBatch{k: key{tid: ev.a.ID, id: trfID}, jobs: make([]mail.Job, 2)}}, time.Millisecond)
		if ev.logs.count("dropped at shutdown") != 2 {
			t.Errorf("logs:\n%s", ev.logs.all())
		}
	})
}

// TestNoSMTP logs one error and sends nothing for a tenant without SMTP
// settings; the transfer is available anyway.
func TestNoSMTP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.c, clean(10), clean(1000))
		ev.start()
		ev.waitStatus(ev.c, trfID, store.TransferAvailable)
		ev.waitIdle()
		if n := len(ev.queue.snapshot()); n != 0 {
			t.Errorf("%d jobs", n)
		}
		if ev.logs.count("no SMTP settings") != 1 {
			t.Errorf("logs:\n%s", ev.logs.all())
		}
	})
}

// TestNotificationBuildFailure skips a mail that cannot be built and sends
// the others.
func TestNotificationBuildFailure(t *testing.T) {
	for _, tc := range []struct {
		fault string
		want  []string
	}{
		{"recipients", []string{mail.TemplateTransferConfirmation}},
		{"confirm", []string{mail.TemplateTransferNotification, mail.TemplateTransferNotification}},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				ev.f.set(tc.fault, 1, nil)
				trfID := ev.scanning(ev.a, clean(10))
				ev.start()
				ev.waitStatus(ev.a, trfID, store.TransferAvailable)
				jobs := ev.waitJobs(len(tc.want))
				if !slices.Equal(templates(jobs), tc.want) || ev.logs.count("notification mail not built") != 1 {
					t.Errorf("jobs %v\nlogs:\n%s", templates(jobs), ev.logs.all())
				}
			})
		})
	}
}

// TestRepoBadTenant refuses a malformed tenant before any transaction.
func TestRepoBadTenant(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		r := storeRepo{db: ev.db, vault: ev.vault}
		if err := r.setScanning(context.Background(), "bad", "fil_x"); err == nil {
			t.Error("malformed tenant accepted")
		}
	})
}

// TestIsolation sends the mails of each tenant with its own SMTP settings
// and builds each link from the tenant's FQDN.
func TestIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfA := ev.scanning(ev.a, clean(10), antivirustest.EICAR())
		trfB := ev.scanning(ev.b, clean(10))
		ev.start()
		ev.waitStatus(ev.a, trfA, store.TransferAvailable)
		ev.waitStatus(ev.b, trfB, store.TransferAvailable)
		jobs := ev.waitJobs(7)
		for _, j := range jobs {
			switch j.TenantID {
			case ev.a.ID.String():
				if j.Settings.Host != smtpA || j.Settings.FromAddress != "noreply@"+hostA {
					t.Errorf("tenant A mail via %s", j.Settings.Host)
				}
			case ev.b.ID.String():
				if j.Settings.Host != smtpB || slices.Contains([]string{hostA, smtpA}, j.Settings.Host) {
					t.Errorf("tenant B mail via %s", j.Settings.Host)
				}
			default:
				t.Errorf("job of tenant %s", j.TenantID)
			}
		}
		// Each tenant sees only its own transfer.
		if _, err := ev.db.Transfers().Get(context.Background(), ev.b.ID, trfA); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("tenant B reads tenant A's transfer: %v", err)
		}
		// A transfer enqueued under the wrong tenant is not found and left
		// alone.
		trfX := ev.scanning(ev.a, clean(10))
		ev.w.Enqueue(ev.b.ID, trfX)
		ev.waitUntil("not found logged", func() bool { return ev.logs.count("transfer to analyze not found") == 1 })
		ev.waitIdle()
		if d := ev.get(ev.a, trfX); d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanPending {
			t.Errorf("transfer of A touched through B: %s", d.Status)
		}
	})
}

// TestTransientFailures retries every step that can fail transiently, and
// ends with the right status.
func TestTransientFailures(t *testing.T) {
	steps := []struct {
		fault  string
		skip   int // successful calls before the failure
		status store.TransferStatus
		files  int // 0: clean + infected; 1: clean only
	}{
		{"transfer", 0, store.TransferAvailable, 0},
		{"transfer", 1, store.TransferAvailable, 0}, // the reload of the conclusion
		{"tenant", 0, store.TransferAvailable, 0},
		{"setScanning", 0, store.TransferAvailable, 0},
		{"setResult", 0, store.TransferAvailable, 0},
		{"remove", 0, store.TransferAvailable, 0},
		{"makeAvailable", 0, store.TransferAvailable, 0},
		{"seal", 0, store.TransferAvailable, 0},
		{"token", 0, store.TransferAvailable, 1},
		{"reject", 0, store.TransferRejected, 2},
	}
	for _, s := range steps {
		t.Run(fmt.Sprintf("%s-%d", s.fault, s.skip), func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				var trfID string
				switch s.files {
				case 0:
					trfID = ev.scanning(ev.a, clean(10), antivirustest.EICAR())
				case 1:
					trfID = ev.scanning(ev.a, clean(10))
				default:
					trfID = ev.scanning(ev.a, antivirustest.EICAR())
				}
				if s.fault == "token" {
					failed := false
					ev.w.newToken = func() (string, error) {
						if !failed {
							failed = true
							return "", errFault
						}
						return "dl_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", nil
					}
				} else {
					ev.f.failAfter(s.fault, s.skip)
				}
				ev.f.set("sweep", 0, nil)
				ev.w.Enqueue(ev.a.ID, trfID)
				ev.start()
				d := ev.waitStatus(ev.a, trfID, s.status)
				ev.waitIdle()
				if ev.logs.count("will retry") == 0 {
					t.Errorf("no retry logged:\n%s", ev.logs.all())
				}
				for _, f := range d.Files {
					if f.ScanStatus == store.ScanInfected && f.DEKKeyID != "" {
						t.Errorf("infected key kept")
					}
				}
			})
		})
	}
}

// TestFileOpenFailures counts the failures to open a file's content.
func TestFileOpenFailures(t *testing.T) {
	for _, fault := range []string{"open", "openRead", "missing", "header", "countAttempt"} {
		t.Run(fault, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{MaxFileErrors: 2})
				trfID := ev.scanning(ev.a, clean(10), clean(20))
				switch fault {
				case "header":
					empty := "0123456789abcdef0123456789abcdef"
					out, err := ev.files.Create(ev.a.ID, empty)
					if err != nil {
						t.Fatal(err)
					}
					_ = out.Close()
					ev.w.files = headerFiles{inner: ev.files, broken: ev.get(ev.a, trfID).Files[1].StorageName, empty: empty}
				case "countAttempt":
					ev.f.set("scan", 1, fmt.Errorf("%w: test", antivirus.ErrSource))
					ev.f.set("countAttempt", 1, nil)
				case "missing":
					ev.f.set("openRead", -1, fmt.Errorf("test: %w", storage.ErrNotFound))
				default:
					// Transient: more failures than MaxFileErrors.
					ev.f.set(fault, 3, nil)
				}
				ev.f.set("sweep", 0, nil)
				ev.w.Enqueue(ev.a.ID, trfID)
				ev.start()
				switch fault {
				case "open", "openRead":
					// Retried without counting attempts.
					d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
					for _, f := range d.Files {
						if f.ScanStatus != store.ScanClean || f.ScanAttempts != 0 {
							t.Errorf("file %s %d", f.ScanStatus, f.ScanAttempts)
						}
					}
				case "missing":
					// Every stored file is missing: rejected.
					d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
					for _, f := range d.Files {
						if f.ScanStatus != store.ScanError || f.ScanAttempts != 2 {
							t.Errorf("file %s %d", f.ScanStatus, f.ScanAttempts)
						}
					}
				case "header":
					d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
					if d.Files[1].ScanStatus != store.ScanError {
						t.Errorf("file %s", d.Files[1].ScanStatus)
					}
				default:
					ev.waitStatus(ev.a, trfID, store.TransferAvailable)
				}
				ev.waitIdle()
			})
		})
	}
}

// TestDefaults checks the default options.
func TestDefaults(t *testing.T) {
	w := New(Deps{}, Options{RetryMin: time.Minute})
	o := w.opts
	if o.Workers != DefaultWorkers || o.RetryMin != time.Minute || o.RetryMax != DefaultRetryMax ||
		o.MaxFileErrors != DefaultMaxFileErrors || o.MailRetryFor != DefaultMailRetryFor || w.sweepLimit != store.ScanSweepLimit {
		t.Errorf("options %+v", o)
	}
	w = New(Deps{}, Options{RetryMin: time.Hour, RetryMax: time.Second})
	if w.opts.RetryMax != time.Hour {
		t.Errorf("RetryMax %v", w.opts.RetryMax)
	}
	w = New(Deps{}, Options{})
	if w.opts.RetryMin != DefaultRetryMin || w.opts.RetryMax != DefaultRetryMax {
		t.Errorf("retry %v %v", w.opts.RetryMin, w.opts.RetryMax)
	}
	for n, want := range map[int]time.Duration{1: time.Minute / 2, 2: time.Minute, 5: 8 * time.Minute, 6: 10 * time.Minute, 60: 10 * time.Minute} {
		if got := w.backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// TestStoppedTimer ignores a retry timer that fired while shutdown stopped
// it.
func TestStoppedTimer(t *testing.T) {
	// In a synctest bubble, time only advances once every goroutine of the
	// bubble is durably blocked: the timer cannot fire before the test
	// sleeps, which is after it removed the timer from the map like a
	// shutdown racing with the timer does.
	synctest.Test(t, func(t *testing.T) {
		w := New(Deps{}, Options{Logger: slog.New(slog.DiscardHandler)})
		w.mu.Lock()
		w.scheduleLocked(task{k: key{id: "trf"}}, time.Millisecond)
		clear(w.timers)
		w.mu.Unlock()
		time.Sleep(time.Second) // the timer fires and its callback returns
		synctest.Wait()
		w.mu.Lock()
		defer w.mu.Unlock()
		if len(w.fifo) != 0 {
			t.Errorf("stopped timer queued its task")
		}
	})
}
