package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// withScanner returns server options pointing TT_CLAMAV_ADDR at a fake
// clamd that really answers INSTREAM (antivirustest), so that finalized
// transfers are analyzed. Without it the servers of these tests use a clamd
// that only answers PING, and finalized transfers never become available.
func withScanner(t *testing.T, o serverOptions) (serverOptions, *antivirustest.Server) {
	t.Helper()
	av := antivirustest.New(t)
	o.clamd = av.Addr()
	return o, av
}

// TestScanWiring checks the wiring of the antivirus worker: a finalized
// transfer with a clean and an infected file becomes available, the
// infected file carries its signature (sender-only view) and the sender
// sees the download link built from the stored FQDN. The detailed scan
// scenarios belong to the scan tests.
func TestScanWiring(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o, _ := withScanner(t, serverOptions{})
		d := startDeposit(t, e, o, true)
		alice, _ := internalSession(t, d, "alice")
		eicar := antivirustest.EICAR()
		clean := []byte("plain clean content")
		req := oneFile("infected.com", int64(len(eicar)))
		req.Files = append(req.Files, fileDecl{Name: "clean.txt", Size: int64(len(clean))})
		tr := alice.mustCreate(t, req)
		alice.upload(t, tr.Files[0].UploadURL, eicar)
		alice.upload(t, tr.Files[1].UploadURL, clean)
		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		var got senderTransferJSON
		eventually(t, "the transfer becomes available", func() bool {
			got = alice.mustGet(t, tr.ID)
			return got.Status == "available"
		})
		// The sender view carries no link (P27): follow the first recipient.
		got = alice.withFirstLink(t, got)
		if !strings.HasPrefix(got.DownloadURL, id.DownloadURL(hostA, "dl_")) || got.FinalizedAt == nil || got.ExpiresAt == nil {
			t.Errorf("available transfer = %+v, want a download link on %s, finalizedAt and expiresAt", got, hostA)
		}
		if f := got.Files[0]; f.ScanStatus != "infected" || f.ScanSig != antivirustest.EicarSignature {
			t.Errorf("infected file = %+v", f)
		}
		if f := got.Files[1]; f.ScanStatus != "clean" || f.ScanSig != "" {
			t.Errorf("clean file = %+v", f)
		}
		noSecretInLogs(t, d.server, strings.TrimPrefix(got.DownloadURL, id.DownloadURL(hostA, "")))
	})
}
