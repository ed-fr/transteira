package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestClean makes a clean transfer available: token hash stored, raw token
// sealed, one mail per recipient and a confirmation to the sender.
func TestClean(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		c1, c2 := clean(100), clean(70000)
		trfID := ev.scanning(ev.a, c1, c2)
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		for _, f := range d.Files {
			if f.ScanStatus != store.ScanClean || f.ScannedAt.IsZero() || f.ScanSignature != "" || f.DEKKeyID == "" {
				t.Errorf("file %+v", f)
			}
		}
		if d.AvailableAt.IsZero() || len(d.DownloadTokenHash) != sha256.Size || !id.Valid(id.WrappedKey, d.DownloadTokenKeyID) {
			t.Fatalf("link: %x %q %v", d.DownloadTokenHash, d.DownloadTokenKeyID, d.AvailableAt)
		}
		// The expiry runs from the availability.
		if want := d.AvailableAt.Add(time.Duration(d.ExpiryDays) * 24 * time.Hour); !d.ExpiresAt.Equal(want) {
			t.Errorf("expires at %v, want %v", d.ExpiresAt, want)
		}
		raw, err := ev.vault.Open(context.Background(), ev.a.ID, crypto.PurposeSecret, d.DownloadTokenKeyID)
		if err != nil {
			t.Fatal(err)
		}
		token := string(raw)
		if sum := sha256.Sum256(raw); !id.DownloadTokenValid(token) || !bytes.Equal(sum[:], d.DownloadTokenHash) {
			t.Fatalf("sealed token %q does not match the hash", token)
		}
		// What clamd received is the plaintext.
		scans := ev.clamd.Scans()
		if len(scans) != 2 || !bytes.Equal(scans[0].Data, c1) || !bytes.Equal(scans[1].Data, c2) {
			t.Errorf("clamd received %d scans", len(scans))
		}
		jobs := ev.waitJobs(3)
		want := []string{mail.TemplateTransferConfirmation, mail.TemplateTransferNotification, mail.TemplateTransferNotification}
		if got := templates(jobs); !slices.Equal(got, want) {
			t.Fatalf("templates %v, want %v", got, want)
		}
		link := "https://" + hostA + "/d/" + token
		var to []string
		for _, j := range byTemplate(jobs, mail.TemplateTransferNotification) {
			to = append(to, j.Message.To...)
			if !strings.Contains(j.Message.Text, link) || len(j.Message.Inline) != 1 {
				t.Errorf("recipient mail without the link or the QR code")
			}
		}
		slices.Sort(to)
		if !slices.Equal(to, []string{dave, erin}) {
			t.Errorf("recipients %v", to)
		}
		conf := byTemplate(jobs, mail.TemplateTransferConfirmation)[0]
		if !slices.Equal(conf.Message.To, []string{alice}) || !strings.Contains(conf.Message.Text, link) {
			t.Errorf("confirmation %v", conf.Message.To)
		}
		for _, j := range jobs {
			if j.TenantID != ev.a.ID.String() || j.Settings.Host != smtpA {
				t.Errorf("job of tenant %s via %s", j.TenantID, j.Settings.Host)
			}
		}
		// Enqueued again once available: ignored.
		ev.w.Enqueue(ev.a.ID, trfID)
		ev.waitIdle()
		if n := len(ev.clamd.Scans()); n != 2 {
			t.Errorf("%d scans after a second enqueue", n)
		}
	})
}

// TestInfected erases the infected file of a transfer and delivers the
// other one.
func TestInfected(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, clean(10), antivirustest.EICAR())
		before := ev.get(ev.a, trfID).Files[1]
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
		good, bad := d.Files[0], d.Files[1]
		if good.ScanStatus != store.ScanClean || good.DEKKeyID == "" {
			t.Errorf("clean file %+v", good)
		}
		if bad.ScanStatus != store.ScanInfected || bad.ScanSignature != antivirustest.EicarSignature || bad.DEKKeyID != "" {
			t.Errorf("infected file %+v", bad)
		}
		if _, err := ev.vault.Open(context.Background(), ev.a.ID, crypto.PurposeDEK, before.DEKKeyID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("infected key still opens: %v", err)
		}
		if _, _, err := ev.files.OpenRead(ev.a.ID, before.StorageName); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("infected file still on disk: %v", err)
		}
		if _, _, err := ev.files.OpenRead(ev.a.ID, good.StorageName); err != nil {
			t.Errorf("clean file gone: %v", err)
		}
		jobs := ev.waitJobs(4)
		virus := byTemplate(jobs, mail.TemplateFileProblems)
		if len(virus) != 1 || !slices.Equal(virus[0].Message.To, []string{alice}) ||
			!strings.Contains(virus[0].Message.Text, antivirustest.EicarSignature) {
			t.Fatalf("virus mail %+v", virus)
		}
		for _, j := range byTemplate(jobs, mail.TemplateTransferNotification) {
			if strings.Contains(j.Message.Text, "file-1.bin") || strings.Contains(j.Message.Text, antivirustest.EicarSignature) {
				t.Errorf("recipient mail mentions the infected file")
			}
		}
	})
}

// TestAllInfected rejects a transfer without a deliverable file and tells
// only the sender.
func TestAllInfected(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		trfID := ev.scanning(ev.a, antivirustest.EICAR(), antivirustest.EICAR())
		ev.start()
		d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
		if d.DownloadTokenHash != nil || d.DownloadTokenKeyID != "" {
			t.Errorf("rejected transfer has a link")
		}
		for _, f := range d.Files {
			if f.ScanStatus != store.ScanInfected || f.DEKKeyID != "" {
				t.Errorf("file %+v", f)
			}
		}
		jobs := ev.waitJobs(1)
		if jobs[0].Template != mail.TemplateFileProblems || !slices.Equal(jobs[0].Message.To, []string{alice}) {
			t.Errorf("job %s to %v", jobs[0].Template, jobs[0].Message.To)
		}
	})
}

// TestTooLarge delivers a file clamd refuses as too large, or that is above
// the client limit, flagged in the mails.
func TestTooLarge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(ev *env)
		scans int
	}{
		{"clamd limit", func(ev *env) { ev.clamd.SetSizeLimit(50) }, 2},
		{"client limit", func(ev *env) {
			ev.scanner.inner = antivirus.NewClient(ev.clamd.Network(), ev.clamd.Addr(), antivirus.WithMaxScanBytes(50))
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storetest.Run(t, func(t *testing.T, e storetest.Engine) {
				ev := newEnv(t, e, Options{})
				tc.setup(ev)
				trfID := ev.scanning(ev.a, clean(10), clean(100))
				ev.start()
				d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
				if d.Files[0].ScanStatus != store.ScanClean || d.Files[1].ScanStatus != store.ScanNotScannedTooLarge {
					t.Errorf("statuses %s %s", d.Files[0].ScanStatus, d.Files[1].ScanStatus)
				}
				if n := len(ev.clamd.Scans()); n != tc.scans {
					t.Errorf("%d scans, want %d", n, tc.scans)
				}
				jobs := ev.waitJobs(4)
				if len(byTemplate(jobs, mail.TemplateFileNotScanned)) != 1 {
					t.Fatalf("templates %v", templates(jobs))
				}
				for _, j := range byTemplate(jobs, mail.TemplateTransferNotification) {
					if !strings.Contains(j.Message.Text, "Not scanned by the antivirus") {
						t.Errorf("recipient mail without the not scanned flag")
					}
				}
			})
		})
	}
}

// TestClamdDown keeps the transfer scanning while clamd is down, with a
// single warning, then makes it available once clamd is back.
func TestClamdDown(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, Options{})
		ev.clamd.Stop()
		trf1 := ev.scanning(ev.a, clean(10))
		trf2 := ev.scanning(ev.b, clean(10))
		ev.start()
		// Several retry rounds.
		ev.waitUntil("retries", func() bool { return ev.scanner.count() >= 6 })
		for _, k := range []struct {
			tn  string
			trf string
		}{{"a", trf1}, {"b", trf2}} {
			tn := ev.a
			if k.tn == "b" {
				tn = ev.b
			}
			d := ev.get(tn, k.trf)
			if d.Status != store.TransferScanning || d.Files[0].ScanStatus != store.ScanScanning || d.Files[0].ScanAttempts != 0 {
				t.Fatalf("during the outage: %s %s %d", d.Status, d.Files[0].ScanStatus, d.Files[0].ScanAttempts)
			}
		}
		if n := ev.logs.count("antivirus unavailable"); n != 1 {
			t.Errorf("%d unavailability warnings, want 1", n)
		}
		if len(ev.queue.snapshot()) != 0 {
			t.Errorf("mails sent during the outage")
		}
		ev.clamd.Restart(t)
		ev.waitStatus(ev.a, trf1, store.TransferAvailable)
		ev.waitStatus(ev.b, trf2, store.TransferAvailable)
		ev.waitJobs(6)
		if n := ev.logs.count("antivirus available again"); n != 1 {
			t.Errorf("%d recovery lines, want 1", n)
		}
	})
}

// TestFileErrors counts the file-specific failures and gives scan_error at
// the limit.
func TestFileErrors(t *testing.T) {
	t.Run("protocol only", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e, Options{MaxFileErrors: 3})
			ev.clamd.SetMode(antivirustest.ModeGarbage)
			trfID := ev.scanning(ev.a, clean(10))
			ev.start()
			d := ev.waitStatus(ev.a, trfID, store.TransferRejected)
			if f := d.Files[0]; f.ScanStatus != store.ScanError || f.ScanAttempts != 3 || f.DEKKeyID == "" {
				t.Errorf("file %+v", f)
			}
			// Only the sender is told: the file is withheld, the transfer
			// was not sent.
			jobs := ev.waitJobs(1)
			ev.waitIdle()
			if n := len(ev.queue.snapshot()); n != 1 {
				t.Errorf("%d mails for a scan_error-only rejection, want 1", n)
			}
			if j := jobs[0]; j.Template != mail.TemplateFileProblems || !slices.Equal(j.Message.To, []string{alice}) ||
				!strings.Contains(j.Message.Text, "file-0.bin") || !strings.Contains(j.Message.Text, "withheld for safety") ||
				!strings.Contains(j.Message.Text, "the transfer was not sent") || strings.Contains(j.Message.Text, "threat") {
				t.Errorf("withheld mail %s to %v:\n%s", j.Template, j.Message.To, j.Message.Text)
			}
			if ev.logs.count("file analysis failed") != 3 {
				t.Errorf("logs:\n%s", ev.logs.all())
			}
		})
	})
	t.Run("mixed", func(t *testing.T) {
		storetest.Run(t, func(t *testing.T, e storetest.Engine) {
			ev := newEnv(t, e, Options{MaxFileErrors: 2})
			trfID := ev.scanning(ev.a, clean(10), clean(20), antivirustest.EICAR())
			// The second file fails twice: a protocol error, then a result
			// without verdict.
			ev.w.scanner = &sizeScanner{inner: ev.scanner, size: 20}
			ev.start()
			d := ev.waitStatus(ev.a, trfID, store.TransferAvailable)
			got := []store.ScanStatus{d.Files[0].ScanStatus, d.Files[1].ScanStatus, d.Files[2].ScanStatus}
			want := []store.ScanStatus{store.ScanClean, store.ScanError, store.ScanInfected}
			if !slices.Equal(got, want) || d.Files[1].ScanAttempts != 2 {
				t.Fatalf("statuses %v attempts %d", got, d.Files[1].ScanAttempts)
			}
			jobs := ev.waitJobs(4)
			for _, j := range byTemplate(jobs, mail.TemplateTransferNotification) {
				if strings.Contains(j.Message.Text, "file-1.bin") || strings.Contains(j.Message.HTML, "file-1.bin") {
					t.Errorf("recipient mail mentions the withheld file")
				}
			}
			for _, name := range []string{mail.TemplateTransferConfirmation, mail.TemplateFileProblems} {
				js := byTemplate(jobs, name)
				if len(js) != 1 || !strings.Contains(js[0].Message.Text, "file-1.bin") ||
					!strings.Contains(js[0].Message.Text, "withheld for safety") {
					t.Errorf("%s does not report the withheld file: %v", name, templates(jobs))
				}
			}
			// The problems mail covers both the infected and the withheld file.
			if p := byTemplate(jobs, mail.TemplateFileProblems); len(p) == 1 &&
				(!strings.Contains(p[0].Message.Text, "file-2.bin") || !strings.Contains(p[0].Message.Text, antivirustest.EicarSignature)) {
				t.Errorf("problems mail:\n%s", p[0].Message.Text)
			}
		})
	})
}

// sizeScanner fails the files of a given size: first with a protocol error,
// then with a result without verdict.
type sizeScanner struct {
	inner Scanner
	size  int64

	mu    sync.Mutex
	fails int
}

func (s *sizeScanner) Scan(ctx context.Context, r io.Reader, size int64) (antivirus.Result, error) {
	if size != s.size {
		return s.inner.Scan(ctx, r, size)
	}
	_, _ = io.Copy(io.Discard, r)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fails++
	if s.fails == 1 {
		return antivirus.Result{}, fmt.Errorf("%w: test", antivirus.ErrProtocol)
	}
	return antivirus.Result{}, nil
}

func (s *sizeScanner) Ping(ctx context.Context) error { return s.inner.Ping(ctx) }
