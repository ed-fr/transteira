package scan

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestSignatureBounds keeps every signature the antivirus client returns
// storable.
func TestSignatureBounds(t *testing.T) {
	if antivirus.MaxSignatureLen > store.MaxScanSignatureBytes {
		t.Errorf("antivirus.MaxSignatureLen %d > store.MaxScanSignatureBytes %d",
			antivirus.MaxSignatureLen, store.MaxScanSignatureBytes)
	}
}

// TestTimeoutCountsAttempts gives scan_error to a file that blocks clamd,
// without reporting an outage.
func TestTimeoutCountsAttempts(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{MaxFileErrors: 2})
		ev.clamd.SetMode(antivirustest.ModeHang)
		ev.scanner.inner = antivirus.NewClient(ev.clamd.Network(), ev.clamd.Addr(), antivirus.WithScanTimeout(100*time.Millisecond))
		trfID := ev.scanning(ev.a, clean(10))
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
		if f := d.Files[0]; f.ScanStatus != store.ScanError || f.ScanAttempts != 2 {
			t.Errorf("file %s %d", f.ScanStatus, f.ScanAttempts)
		}
		if ev.logs.count("antivirus unavailable") != 0 {
			t.Errorf("timeout reported as an outage:\n%s", ev.logs.all())
		}
	})
}

// TestConnectionLost counts an attempt when clamd drops the connection but
// still answers a ping, and treats it as an outage when it does not.
func TestConnectionLost(t *testing.T) {
	t.Run("clamd answers", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e, Options{MaxFileErrors: 2})
			ev.clamd.SetMode(antivirustest.ModeCloseMidStream)
			trfID := ev.scanning(ev.a, clean(10))
			ev.start()
			d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
			if f := d.Files[0]; f.ScanStatus != store.ScanError || f.ScanAttempts != 2 {
				t.Errorf("file %s %d", f.ScanStatus, f.ScanAttempts)
			}
			if ev.clamd.Pings() != 2 || ev.logs.count("antivirus unavailable") != 0 {
				t.Errorf("%d pings\n%s", ev.clamd.Pings(), ev.logs.all())
			}
		})
	})
	t.Run("clamd down", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			// A content that drops the connection while clamd is down: it
			// reaches scan_error, and the other transfers resume once
			// clamd answers again.
			ev := newEnv(t, e, Options{Workers: 1, MaxFileErrors: 3})
			ev.w.scanner = &lostScanner{inner: ev.scanner, size: 13}
			ev.clamd.Stop()
			bad := ev.scanning(ev.a, clean(13))
			good := ev.scanning(ev.b, clean(10))
			ev.f.set("sweep", 0, nil)
			ev.w.Enqueue(ev.a.ID, bad)
			ev.w.Enqueue(ev.b.ID, good)
			ev.start()
			d := ev.waitStatus(ev.a, bad, store.TransferRejected)
			if f := d.Files[0]; f.ScanStatus != store.ScanError || f.ScanAttempts != 3 {
				t.Errorf("crashing file %s %d", f.ScanStatus, f.ScanAttempts)
			}
			if g := ev.get(ev.b, good); g.Status != store.TransferScanning || g.Files[0].ScanAttempts != 0 {
				t.Errorf("other transfer during the outage: %s %d", g.Status, g.Files[0].ScanAttempts)
			}
			if ev.logs.count("antivirus unavailable") != 1 || !strings.Contains(ev.logs.all(), "file="+d.Files[0].ID) {
				t.Errorf("outage warning without the culprit:\n%s", ev.logs.all())
			}
			ev.clamd.Restart(t)
			ev.waitStatus(ev.b, good, store.TransferAvailable)
			if ev.logs.count("antivirus available again") != 1 {
				t.Errorf("logs:\n%s", ev.logs.all())
			}
		})
	})
}

// lostScanner drops the connection on the contents of a given size, like a
// file crashing clamd.
type lostScanner struct {
	inner Scanner
	size  int64
}

func (s *lostScanner) Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error) {
	if size != s.size {
		return s.inner.Scan(ctx, r, size)
	}
	_, _ = io.Copy(io.Discard, r)
	return antivirus.Result{}, fmt.Errorf("%w: %w: test", antivirus.ErrUnavailable, antivirus.ErrConnectionLost)
}

func (s *lostScanner) Ping(ctx context.Context) error { return s.inner.Ping(ctx) }

// TestPartialAnalysis delivers, flagged, the files clamd could not analyze
// completely.
func TestPartialAnalysis(t *testing.T) {
	for _, tc := range []struct {
		mode antivirustest.Mode
		want store.ScanStatus
		// flag and reason are the lines of the recipient and sender mails.
		flag, reason string
	}{
		{
			antivirustest.ModeLimitsExceeded, store.ScanNotScannedTooLarge,
			"Not scanned by the antivirus: the file is too large or too complex to be fully analyzed.",
			"Reason: the file is too large or too complex to be fully analyzed.",
		},
		{
			antivirustest.ModeEncrypted, store.ScanNotScannedEncrypted,
			"Could not be analyzed by the antivirus: encrypted archive.", "Reason: encrypted archive",
		},
	} {
		t.Run(string(tc.want), func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				ev.clamd.SetMode(tc.mode)
				trfID := ev.scanning(ev.a, clean(10))
				ev.start()
				d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
				if f := d.Files[0]; f.ScanStatus != tc.want || f.ScanSignature != "" {
					t.Errorf("file %s %q", f.ScanStatus, f.ScanSignature)
				}
				jobs := ev.waitJobs(4)
				ns := byTemplate(jobs, mail.TemplateFileNotScanned)
				if len(ns) != 1 || !strings.Contains(ns[0].Message.Text, tc.reason) {
					t.Errorf("templates %v", templates(jobs))
				}
				for _, j := range append(byTemplate(jobs, mail.TemplateTransferNotification),
					byTemplate(jobs, mail.TemplateTransferConfirmation)...) {
					if !strings.Contains(j.Message.Text, tc.flag) {
						t.Errorf("%s lacks %q:\n%s", j.Template, tc.flag, j.Message.Text)
					}
				}
				if ev.logs.count("align StreamMaxLength") != 0 {
					t.Errorf("misaligned limit logged")
				}
			})
		})
	}
}

// TestStreamLimitWarnedOnce logs a single warning when clamd refuses files
// the client sent.
func TestStreamLimitWarnedOnce(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.clamd.SetSizeLimit(50)
		trf1 := ev.scanning(ev.a, clean(100))
		trf2 := ev.scanning(ev.a, clean(200), clean(300))
		ev.start()
		ev.waitStatus(ev.a, trf1, store.TransferAvailable)
		ev.waitStatus(ev.a, trf2, store.TransferAvailable)
		if n := ev.logs.count("align StreamMaxLength"); n != 1 {
			t.Errorf("%d misalignment warnings, want 1", n)
		}
	})
}

// TestRefusedResult records an infected file without the signature the
// store refuses, and leaves a conflicting result to the conclusion.
func TestRefusedResult(t *testing.T) {
	t.Run("signature", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e, Options{})
			ev.scanner.result = &antivirus.Result{Verdict: antivirus.Infected, Signature: "Bad\nSignature"}
			trfID := ev.scanning(ev.a, clean(10))
			ev.start()
			d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
			if f := d.Files[0]; f.ScanStatus != store.ScanInfected || f.ScanSignature != "" || f.DEKKeyID != "" {
				t.Errorf("file %+v", f)
			}
			if ev.logs.count("recorded without it") != 1 {
				t.Errorf("logs:\n%s", ev.logs.all())
			}
		})
	})
	t.Run("conflict", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e, Options{})
			ev.f.set("setResult", 1, store.ErrConflict)
			trfID := ev.scanning(ev.a, clean(10))
			ev.start()
			ev.waitStatus(ev.a, trfID, store.TransferAvailable)
			if ev.logs.count("scan result not recorded") != 1 || ev.logs.count("file not analyzed yet") != 1 {
				t.Errorf("logs:\n%s", ev.logs.all())
			}
		})
	})
	t.Run("refused twice", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e, Options{})
			ev.f.set("setResult", 2, store.ErrInvalid)
			trfID := ev.scanning(ev.a, clean(10))
			ev.start()
			d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
			if f := d.Files[0]; f.ScanStatus != store.ScanError {
				t.Errorf("file %s", f.ScanStatus)
			}
			if ev.logs.count("scan result not recorded") != 2 || ev.logs.count("file withheld") != 1 {
				t.Errorf("logs:\n%s", ev.logs.all())
			}
		})
	})
	t.Run("always refused", func(t *testing.T) {
		for _, protocol := range []bool{false, true} {
			t.Run(fmt.Sprint("scan_error=", protocol), func(t *testing.T) {
				storetest.Run(t, func(t *testing.T, e storetest.Engine) {
					ev := newEnv(t, e, Options{MaxFileErrors: 1})
					if protocol {
						// The refused result is already scan_error.
						ev.clamd.SetMode(antivirustest.ModeGarbage)
					}
					ev.f.set("setResult", -1, store.ErrConflict)
					trfID := ev.scanning(ev.a, clean(10))
					ev.start()
					ev.waitUntil("give up", func() bool { return ev.logs.count("transfer left scanning") == 1 })
					ev.waitIdle()
					if d := ev.get(ev.a, trfID); d.Status != store.TransferScanning || d.Files[0].ScanStatus.Deliverable() {
						t.Errorf("transfer %s, file %s", d.Status, d.Files[0].ScanStatus)
					}
					ev.w.mu.Lock()
					defer ev.w.mu.Unlock()
					if len(ev.w.refusals) != 0 {
						t.Errorf("refusals kept: %v", ev.w.refusals)
					}
				})
			})
		}
	})
}

// TestConcludeSkipsChangedTransfer leaves alone a transfer that stopped
// scanning before the conclusion.
func TestConcludeSkipsChangedTransfer(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10))
		ev.f.onCall("tenant", func() {
			s, err := ev.db.Scoped(ev.a.ID)
			if err != nil {
				t.Error(err)
				return
			}
			err = s.Tx(context.Background(), func(tx *store.ScopedTx) error {
				return ev.db.Transfers().SetStatusTx(context.Background(), tx, trfID, store.TransferScanning, store.TransferDeleted, time.Now())
			})
			if err != nil {
				t.Error(err)
			}
		})
		ev.start()
		ev.waitUntil("conclusion", func() bool { return ev.f.called("tenant") == 1 })
		ev.waitIdle()
		if d := ev.get(ev.a, trfID); d.Status != store.TransferDeleted || d.DownloadTokenHash != nil {
			t.Errorf("transfer %s", d.Status)
		}
		if n := len(ev.queue.snapshot()); n != 0 || strings.Contains(ev.logs.all(), "transfer available") {
			t.Errorf("%d mails", n)
		}
	})
}
