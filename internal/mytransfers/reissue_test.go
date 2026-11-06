package mytransfers

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestReissueLink replaces the token of an available link-only transfer
// of the session address and returns its link once; any other transfer
// is refused.
func TestReissueLink(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newFixture(t, e)
		lo := f.seed(f.a, seedOptions{linkOnly: true})
		before := f.transfer(f.a, lo).DownloadTokenHash

		url, err := f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, lo)
		if err != nil {
			t.Fatalf("ReissueLink: %v", err)
		}
		token, ok := strings.CutPrefix(url, "https://"+hostA+id.DownloadPath)
		if !ok || !id.DownloadTokenValid(token) {
			t.Fatalf("url = %q", url)
		}
		after := f.transfer(f.a, lo)
		if !bytes.Equal(after.DownloadTokenHash, id.HashToken(token)) || bytes.Equal(after.DownloadTokenHash, before) ||
			after.DownloadTokenKeyID != "" {
			t.Errorf("stored token %x (before %x) sealed %q", after.DownloadTokenHash, before, after.DownloadTokenKeyID)
		}
		evs := f.auditEvents(f.a.ID, audit.ActionTransferLinkReissued)
		if len(evs) != 1 || evs[0].Actor != aliceNorm || evs[0].ObjectID != lo || evs[0].IP != clientIP {
			t.Errorf("audit = %+v", evs)
		}

		// Still scanning: reissued, the link works once available.
		scanningLO := f.seed(f.a, seedOptions{linkOnly: true, status: store.TransferScanning})
		url, err = f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, scanningLO)
		token, _ = strings.CutPrefix(url, "https://"+hostA+id.DownloadPath)
		if err != nil || !bytes.Equal(f.transfer(f.a, scanningLO).DownloadTokenHash, id.HashToken(token)) {
			t.Errorf("ReissueLink(scanning) = %q, %v", url, err)
		}
		// Not link-only: a state conflict.
		for name, trfID := range map[string]string{"shared": f.available, "per recipient": f.leveled} {
			_, err := f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, trfID)
			wantErr(t, name, err, ErrNotReissuable)
		}
		// Not a transfer of the sender in progress: not found.
		for name, trfID := range map[string]string{
			"uploading": f.uploading, "expired": f.expired, "api token": f.byToken, "other sender": f.ofBob,
			"other tenant": f.inB, "malformed": "trf_x",
		} {
			_, err := f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, trfID)
			wantErr(t, name, err, ErrNotFound)
		}
		// Past its expiry, before the cleanup.
		f.clock.Advance(8 * day)
		_, err = f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, lo)
		wantErr(t, "past expiry", err, ErrNotReissuable)
		if n := len(f.auditEvents(f.a.ID, audit.ActionTransferLinkReissued)); n != 2 {
			t.Errorf("%d reissues audited", n)
		}
	})
}

// TestReissueLinkFaults covers the token draw and the store failures.
func TestReissueLinkFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newFixture(t, storetest.SQLite(t))
	lo := f.seed(f.a, seedOptions{linkOnly: true})
	f.svc.newToken = func(string, int) (string, error) { return "", errBoom }
	if _, err := f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, lo); !errors.Is(err, errBoom) {
		t.Errorf("token: %v", err)
	}
	f.svc.newToken = id.NewToken
	f.fail("reissue")
	if _, err := f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, lo); !errors.Is(err, errBoom) {
		t.Errorf("store: %v", err)
	}
	// A conflict of the store (the transfer ended meanwhile).
	f.repo.errs["reissue"] = store.ErrConflict
	_, err := f.svc.ReissueLink(ctx, f.a, f.sess, clientIP, lo)
	wantErr(t, "conflict", err, ErrNotReissuable)
	r := storeRepo{db: f.db}
	if err := r.reissue(ctx, "", lo, aliceNorm, nil, func(store.SenderTransferDetail) error { return nil }); err == nil {
		t.Error("reissue accepted an empty tenant")
	}
}
