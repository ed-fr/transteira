package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// End-to-end tests of the tus 1.0.0 upload resources (CLAUDE.md sections
// 8.6 and 17; api/openapi.yaml, "Large uploads (tus)"; threat model T-21 to
// T-24, T-30, T-123) against a real server, on both engines.

// checkpointEvery mirrors upload.DefaultCheckpointEvery: the server
// persists the progress of a request every 64 MiB (and at its end). It is
// not configurable through the environment.
const checkpointEvery = 64 << 20

// TestUploadInterruptedPatch cuts PATCH requests in the middle of their
// body, both by an abrupt reset after an in-request checkpoint and by a
// half-close, then resumes from the offset HEAD reports: the stored file is
// byte-identical to the original.
func TestUploadInterruptedPatch(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		const seed, size = 30, checkpointEvery + 8<<20 + 12345
		tr := alice.mustCreate(t, oneFile("interrupted.bin", size))
		url := tr.Files[0].UploadURL
		row := d.fileRow(t, tr.ID, tr.Files[0].ID)

		// 1. Abrupt reset (RST) once the server checkpointed inside the
		// request: the bytes past the checkpoint that the server read are
		// saved by the end-of-request checkpoint.
		const sent1 = checkpointEvery + 2<<20
		conn := alice.rawPatch(t, url, 0, size)
		part1 := seededRange(t, seed, 0, sent1)
		written := make(chan error, 1)
		go func() {
			_, err := io.Copy(conn, part1)
			written <- err
		}()
		var (
			werr error
			done bool
		)
		eventually(t, "in-request checkpoint", func() bool {
			if !done {
				select {
				case werr = <-written:
					done = true
				default:
				}
			}
			if done && werr != nil {
				t.Fatalf("the server cut the PATCH before its checkpoint: %v\nserver errors:\n%s", werr, d.errorLines())
			}
			return exists(t, d.ckptPath(row.StorageName))
		})
		if !done {
			werr = <-written
		}
		if werr != nil {
			t.Fatalf("write the first part: %v\nserver errors:\n%s", werr, d.errorLines())
		}
		_ = conn.SetLinger(0)
		_ = conn.Close()
		alice.waitUnlocked(t, tr.ID)
		off1, length := alice.offsetOf(t, url)
		if off1 < checkpointEvery || off1 > sent1 || length != size {
			t.Fatalf("offset after the reset = %d/%d, want in [%d, %d] of %d", off1, length, checkpointEvery, sent1, size)
		}

		// 2. Half-close in the middle of the body: the server reads every
		// byte sent, answers 400 without body, and HEAD reports exactly
		// those bytes.
		const sent2 = 1<<20 + 7
		conn = alice.rawPatch(t, url, off1, size-off1)
		if _, err := io.Copy(conn, seededRange(t, seed, off1, off1+sent2)); err != nil {
			t.Fatal(err)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		expectTusError(t, "half-closed PATCH", readRawResponse(t, conn), http.StatusBadRequest)
		off2, _ := alice.offsetOf(t, url)
		if off2 != off1+sent2 {
			t.Fatalf("offset after the half-close = %d, want %d", off2, off1+sent2)
		}

		// 3. Resume to the end.
		resp, err := alice.tryTus(http.MethodPatch, url, func(h http.Header) {
			h.Set(hdrUploadOffset, strconv.FormatInt(off2, 10))
		}, seededRange(t, seed, off2, size), size-off2, uploadTimeout)
		if err != nil || resp.status != http.StatusNoContent || resp.header.Get(hdrUploadOffset) != strconv.Itoa(size) {
			t.Fatalf("resume: %v, %d %v", err, resp.status, resp.header)
		}
		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		got := alice.mustGet(t, tr.ID)
		want := seededRange(t, seed, 0, size)
		if !sameStream(t, d.openFile(t, d.fileRow(t, tr.ID, tr.Files[0].ID)), want) {
			t.Error("the resumed upload does not decrypt to the original")
		}
		hw := newHashingReader(seededRange(t, seed, 0, size))
		if _, err := io.Copy(io.Discard, hw); err != nil {
			t.Fatal(err)
		}
		if got.Files[0].Sha256 != hw.Hex() {
			t.Errorf("sha256 = %s, want %s", got.Files[0].Sha256, hw.Hex())
		}
	})
}

// TestUploadIdleTimeout covers TT_UPLOAD_IDLE_TIMEOUT (threat T-123): a
// PATCH whose body stalls is cut with a bodyless 400, the bytes received
// are kept, and the upload resumes from them.
func TestUploadIdleTimeout(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		const idle = 5 * time.Second // the minimum accepted by the configuration
		d := startDeposit(t, e, serverOptions{env: map[string]string{config.EnvUploadIdleTimeout: idle.String()}}, true)
		alice, _ := internalSession(t, d, "alice")
		data := seededBytes(t, 31, 1<<20)
		tr := alice.mustCreate(t, oneFile("stalled.bin", int64(len(data))))
		url := tr.Files[0].UploadURL

		const sent = 300000
		conn := alice.rawPatch(t, url, 0, int64(len(data)))
		if _, err := conn.Write(data[:sent]); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		resp := readRawResponse(t, conn) // the client stalls: no more bytes
		elapsed := time.Since(start)
		expectTusError(t, "stalled PATCH", resp, http.StatusBadRequest)
		if elapsed < idle-time.Second || elapsed > idle+20*time.Second {
			t.Errorf("stalled PATCH cut after %s, want about %s", elapsed, idle)
		}
		if off, _ := alice.offsetOf(t, url); off != sent {
			t.Fatalf("offset after the idle timeout = %d, want %d", off, sent)
		}
		alice.mustPatch(t, url, sent, data[sent:])
		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		if !bytes.Equal(d.decrypt(t, d.fileRow(t, tr.ID, tr.Files[0].ID)), data) {
			t.Error("the resumed upload does not decrypt to the original")
		}
	})
}

// TestUploadProtocolErrors covers the tus error responses: concurrent
// PATCHes (409), wrong offsets (409), bytes beyond Upload-Length (413), a
// missing or unsupported Tus-Resumable (412 with Tus-Version), a wrong
// media type (415), malformed offsets (400), missing authentication or CSRF
// token and unknown uploads. Every error has no body and carries
// Tus-Resumable.
func TestUploadProtocolErrors(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		long := seededBytes(t, 40, 4<<20)
		req := oneFile("long.bin", int64(len(long)))
		req.Files = append(req.Files, fileDecl{Name: "short.bin", Size: 1000})
		tr := alice.mustCreate(t, req)
		longURL, shortURL := tr.Files[0].UploadURL, tr.Files[1].UploadURL

		// Two concurrent PATCHes on the same upload: the second gets 409
		// while the first holds the upload lock (its encrypted file exists
		// once the lock is taken), as do the termination, the cancellation
		// and the finalization.
		pr, pw := io.Pipe()
		first := make(chan response, 1)
		go func() {
			resp, err := alice.tryTus(http.MethodPatch, longURL, func(h http.Header) { h.Set(hdrUploadOffset, "0") }, pr, int64(len(long)), waitTimeout)
			if err != nil {
				t.Errorf("first PATCH: %v", err)
			}
			first <- resp
		}()
		if _, err := pw.Write(long[:1<<20]); err != nil {
			t.Fatal(err)
		}
		row := d.fileRow(t, tr.ID, tr.Files[0].ID)
		eventually(t, "first PATCH holds the lock", func() bool { return exists(t, d.encPath(row.StorageName)) })
		expectTusError(t, "concurrent PATCH", alice.patch(t, longURL, 0, long[:10]), http.StatusConflict)
		expectTusError(t, "DELETE during PATCH", alice.terminate(t, longURL), http.StatusConflict)
		expectProblem(t, alice.cancelTransfer(t, tr.ID), http.StatusConflict, "state-conflict")
		expectProblem(t, alice.finalize(t, tr.ID), http.StatusConflict, "state-conflict")
		if resp := alice.head(t, longURL); resp.status != http.StatusOK {
			t.Errorf("HEAD during PATCH: %d, want 200 (HEAD takes no lock)", resp.status)
		}
		if _, err := pw.Write(long[1<<20:]); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		if resp := <-first; resp.status != http.StatusNoContent || resp.header.Get(hdrUploadOffset) != strconv.Itoa(len(long)) {
			t.Fatalf("first PATCH: %d %v", resp.status, resp.header)
		}

		// Offsets.
		expectTusError(t, "offset ahead", alice.patch(t, shortURL, 5, make([]byte, 10)), http.StatusConflict)
		alice.mustPatch(t, shortURL, 0, make([]byte, 100))
		expectTusError(t, "offset behind", alice.patch(t, shortURL, 50, make([]byte, 10)), http.StatusConflict)
		expectTusError(t, "offset ahead after progress", alice.patch(t, shortURL, 101, make([]byte, 10)), http.StatusConflict)
		for _, bad := range []string{"", "abc", "-1", "1e3", "99999999999999999999999"} {
			resp := alice.tusRequest(t, http.MethodPatch, shortURL, func(h http.Header) { h.Set(hdrUploadOffset, bad) },
				bytes.NewReader(make([]byte, 10)), 10)
			expectTusError(t, "Upload-Offset "+strconv.Quote(bad), resp, http.StatusBadRequest)
		}
		// Bytes beyond Upload-Length: 413; the bytes up to the length are
		// kept, an empty PATCH completes the upload, and one more byte on
		// the completed upload is 413 again.
		expectTusError(t, "beyond length", alice.patch(t, shortURL, 100, make([]byte, 901)), http.StatusRequestEntityTooLarge)
		if off, length := alice.offsetOf(t, shortURL); off != 1000 || length != 1000 {
			t.Fatalf("HEAD after 413 = %d/%d, want 1000/1000", off, length)
		}
		resp := alice.patch(t, shortURL, 1000, nil)
		if resp.status != http.StatusNoContent || resp.header.Get(hdrUploadOffset) != "1000" || resp.header.Get(hdrUploadExpires) != "" {
			t.Errorf("empty PATCH at the end: %d %v, want 204, offset 1000, no Upload-Expires", resp.status, resp.header)
		}
		expectTusError(t, "beyond a completed upload", alice.patch(t, shortURL, 1000, []byte{1}), http.StatusRequestEntityTooLarge)
		expectTusError(t, "wrong offset on a completed upload", alice.patch(t, shortURL, 0, []byte{1}), http.StatusConflict)

		// Tus-Resumable.
		for _, method := range []string{http.MethodHead, http.MethodPatch, http.MethodDelete} {
			for _, v := range []string{"", "0.2.2", "1.0.0, 1.0.0", "1.0"} {
				resp := alice.tusRequest(t, method, longURL, func(h http.Header) {
					h.Set(hdrTusResumable, v)
					h.Set(hdrUploadOffset, strconv.Itoa(len(long)))
				}, nil, 0)
				what := method + " Tus-Resumable " + strconv.Quote(v)
				expectTusError(t, what, resp, http.StatusPreconditionFailed)
				if got := resp.header.Get("Tus-Version"); got != tusVersion {
					t.Errorf("%s: Tus-Version = %q, want %q", what, got, tusVersion)
				}
			}
		}
		// OPTIONS needs no Tus-Resumable.
		opt := d.do(t, request{method: http.MethodOptions, host: hostA, path: pathUploads})
		if opt.status != http.StatusNoContent || opt.header.Get("Tus-Version") != tusVersion || opt.header.Get(hdrTusResumable) != tusVersion ||
			opt.header.Get("Tus-Extension") != "expiration,termination" ||
			opt.header.Get("Tus-Max-Size") != strconv.Itoa(1<<30) {
			t.Errorf("OPTIONS /uploads: %d %v", opt.status, opt.header)
		}

		// Media type.
		for _, ct := range []string{"application/octet-stream", "", "text/plain", "application/offset+octet-stream-x"} {
			resp := alice.tusRequest(t, http.MethodPatch, longURL, func(h http.Header) {
				h.Set("Content-Type", ct)
				h.Set(hdrUploadOffset, strconv.Itoa(len(long)))
			}, bytes.NewReader([]byte{1}), 1)
			expectTusError(t, "Content-Type "+strconv.Quote(ct), resp, http.StatusUnsupportedMediaType)
		}
		// Parameters are accepted on the right media type.
		resp = alice.tusRequest(t, http.MethodPatch, longURL, func(h http.Header) {
			h.Set("Content-Type", "Application/Offset+Octet-Stream; charset=binary")
			h.Set(hdrUploadOffset, strconv.Itoa(len(long)))
		}, nil, 0)
		if resp.status != http.StatusNoContent {
			t.Errorf("PATCH with media type parameters: %d, want 204", resp.status)
		}

		// Authentication, CSRF and unknown uploads.
		anon := &depositor{d: d, host: hostA, ip: insideA}
		expectTusError(t, "HEAD without session", anon.head(t, longURL), http.StatusUnauthorized)
		expectTusError(t, "PATCH without session", anon.patch(t, longURL, 0, []byte{1}), http.StatusUnauthorized)
		noCSRF := *alice
		noCSRF.csrf = ""
		expectTusError(t, "PATCH without CSRF", noCSRF.patch(t, longURL, int64(len(long)), nil), http.StatusForbidden)
		expectTusError(t, "DELETE without CSRF", noCSRF.terminate(t, longURL), http.StatusForbidden)
		for _, u := range []string{pathUploads + "/upl_unknown0000000000000000", pathUploads + "/" + strings.Repeat("x", 300), pathUploads + "/" + tr.Files[0].ID} {
			expectTusError(t, "HEAD "+u, alice.head(t, u), http.StatusNotFound)
			expectTusError(t, "PATCH "+u, alice.patch(t, u, 0, []byte{1}), http.StatusNotFound)
			expectTusError(t, "DELETE "+u, alice.terminate(t, u), http.StatusNotFound)
		}

		// None of the refused requests changed the uploads.
		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		short := d.fileRow(t, tr.ID, tr.Files[1].ID)
		if !bytes.Equal(d.decrypt(t, d.fileRow(t, tr.ID, tr.Files[0].ID)), long) || !bytes.Equal(d.decrypt(t, short), make([]byte, 1000)) {
			t.Error("the uploads do not decrypt to the originals")
		}
	})
}

// TestUploadCrashRecovery simulates a crash between a data write and its
// checkpoint (garbage appended to the encrypted file, checkpoint
// unchanged): the next PATCH gets 409, the upload is reset to offset 0 with
// a new data key and storage name, the old key is destroyed, and a new
// upload from 0 stores the right content.
func TestUploadCrashRecovery(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{}, true)
		alice, _ := internalSession(t, d, "alice")
		data := seededBytes(t, 50, 3<<20+17)
		tr := alice.mustCreate(t, oneFile("crash.bin", int64(len(data))))
		url := tr.Files[0].UploadURL
		alice.mustPatch(t, url, 0, data[:1<<20])
		before := d.fileRow(t, tr.ID, tr.Files[0].ID)

		f, err := os.OpenFile(d.encPath(before.StorageName), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(bytes.Repeat([]byte{0xEE}, 4096+3)); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		expectTusError(t, "PATCH after the crash", alice.patch(t, url, 1<<20, data[1<<20:1<<20+10]), http.StatusConflict)
		if off, _ := alice.offsetOf(t, url); off != 0 {
			t.Fatalf("offset after the reset = %d, want 0", off)
		}
		after := d.fileRow(t, tr.ID, tr.Files[0].ID)
		if after.DEKKeyID == before.DEKKeyID || after.StorageName == before.StorageName || after.DEKKeyID == "" {
			t.Errorf("reset kept the data key or the storage name: %+v -> %+v", before, after)
		}
		d.expectKeyDestroyed(t, before.DEKKeyID)
		if exists(t, d.encPath(before.StorageName)) || exists(t, d.ckptPath(before.StorageName)) {
			t.Error("the files of the reset upload are left on disk")
		}
		if !exists(t, d.encPath(after.StorageName)) || !exists(t, d.ckptPath(after.StorageName)) {
			t.Error("the reset did not create the new file and its checkpoint")
		}
		if !strings.Contains(d.appLog.String(), "upload reset") {
			t.Error("the reset is not logged")
		}

		alice.mustPatch(t, url, 0, data[:2<<20])
		alice.mustPatch(t, url, 2<<20, data[2<<20:])
		if resp := alice.finalize(t, tr.ID); resp.status != http.StatusAccepted {
			t.Fatalf("finalize: %d %s", resp.status, resp.body)
		}
		final := d.fileRow(t, tr.ID, tr.Files[0].ID)
		if !bytes.Equal(d.decrypt(t, final), data) || final.SHA256 != sha256Hex(data) {
			t.Error("the re-uploaded file does not decrypt to the original")
		}
	})
}

// TestUploadExpiry covers the expiration of an inactive incomplete upload
// (threat T-23): HEAD and PATCH get 410 once the checkpoint is older than
// TT_UPLOAD_TTL. The configuration accepts no TTL under one hour, so the
// last activity (the checkpoint modification time) is moved back instead.
func TestUploadExpiry(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		d := startDeposit(t, e, serverOptions{env: map[string]string{config.EnvUploadTTL: "1h"}}, true)
		alice, _ := internalSession(t, d, "alice")
		tr := alice.mustCreate(t, oneFile("late.bin", 1000))
		url := tr.Files[0].UploadURL
		alice.mustPatch(t, url, 0, make([]byte, 300))
		h := alice.head(t, url)
		exp, err := http.ParseTime(h.header.Get(hdrUploadExpires))
		if err != nil || exp.Before(time.Now().Add(59*time.Minute)) || exp.After(time.Now().Add(61*time.Minute)) {
			t.Errorf("Upload-Expires = %q, want about one hour ahead", h.header.Get(hdrUploadExpires))
		}

		row := d.fileRow(t, tr.ID, tr.Files[0].ID)
		past := time.Now().Add(-61 * time.Minute)
		if err := os.Chtimes(d.ckptPath(row.StorageName), past, past); err != nil {
			t.Fatal(err)
		}
		// The expiry counts from the latest activity of the transfer, its
		// creation included: move the creation into the past too.
		execSystem(t, e, fmt.Sprintf(`UPDATE transfers SET created_at = created_at - %d WHERE id = '%s'`,
			(61*time.Minute).Milliseconds(), tr.ID))
		expectTusError(t, "HEAD after expiry", alice.head(t, url), http.StatusGone)
		expectTusError(t, "PATCH after expiry", alice.patch(t, url, 300, make([]byte, 700)), http.StatusGone)
		if row2 := d.fileRow(t, tr.ID, tr.Files[0].ID); !row2.UploadedAt.IsZero() {
			t.Error("the expired upload was completed")
		}
	})
}
