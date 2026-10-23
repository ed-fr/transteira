package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestNewDefaults(t *testing.T) {
	e := newEngine(nil, nil, nil, Options{})
	if e.ttl != DefaultUploadTTL || e.maxAge != DefaultMaxAge || e.every != DefaultCheckpointEvery || e.now == nil || e.log == nil {
		t.Fatalf("defaults not applied: ttl %v max age %v every %d", e.ttl, e.maxAge, e.every)
	}
	// The maximum age never falls below the TTL.
	if e = newEngine(nil, nil, nil, Options{UploadTTL: 48 * time.Hour, MaxAge: time.Hour}); e.maxAge != 48*time.Hour {
		t.Fatalf("max age = %v", e.maxAge)
	}
	now := func() time.Time { return time.Unix(0, 0) }
	e = newEngine(nil, nil, nil, Options{UploadTTL: time.Hour, CheckpointEvery: 10, Now: now})
	if e.ttl != time.Hour || e.every != 10 || !e.now().Equal(time.Unix(0, 0)) {
		t.Fatal("options not applied")
	}
}

func TestHappyPathSeveralChunks(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 5000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})

		st := ev.statusOK(t, u)
		if st.Offset != 0 || st.Length != 5000 || st.Completed || st.ExpiresAt.IsZero() {
			t.Fatalf("initial status = %+v", st)
		}
		// Offset before any byte: no checkpoint yet.
		off, exp, err := ev.eng.Offset(ctx, u.tid, ev.file(t, u), time.Now(), time.Now())
		if err != nil || off != 0 || exp.IsZero() {
			t.Fatalf("Offset = %d, %v, %v", off, exp, err)
		}

		var offset int64
		for _, n := range []int{1, 1023, 1500, 2000} {
			st = ev.appendOK(t, u, offset, data[offset:offset+int64(n)])
			offset += int64(n)
			if st.Offset != offset || st.Completed {
				t.Fatalf("after %d bytes: %+v", offset, st)
			}
			if got := ev.statusOK(t, u); got.Offset != offset {
				t.Fatalf("Status offset = %d, want %d", got.Offset, offset)
			}
			off, _, err := ev.eng.Offset(ctx, u.tid, ev.file(t, u), time.Now(), time.Now())
			if err != nil || off != offset {
				t.Fatalf("Offset = %d, %v, want %d", off, err, offset)
			}
		}
		st = ev.appendOK(t, u, offset, data[offset:])
		if !st.Completed || st.Offset != 5000 || !st.ExpiresAt.IsZero() {
			t.Fatalf("final status = %+v", st)
		}
		f := ev.file(t, u)
		sum := sha256.Sum256(data)
		if f.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("sha256 = %s", f.SHA256)
		}
		if got := ev.decrypt(t, u); !bytes.Equal(got, data) {
			t.Fatal("decrypted content differs")
		}
		if _, err := os.Stat(ev.path(u.tid, f, ".ckpt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("checkpoint left after completion: %v", err)
		}
		if got := ev.statusOK(t, u); !got.Completed || got.Offset != 5000 {
			t.Fatalf("status after completion = %+v", got)
		}
		off, exp, err = ev.eng.Offset(ctx, u.tid, f, time.Now(), time.Now())
		if err != nil || off != 5000 || !exp.IsZero() {
			t.Fatalf("Offset after completion = %d, %v, %v", off, exp, err)
		}

		// tus: a PATCH at the length of a completed upload is a no-op; a
		// wrong offset or extra bytes are refused.
		if st := ev.appendOK(t, u, 5000, nil); !st.Completed {
			t.Fatalf("empty append on completed = %+v", st)
		}
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 10, bytes.NewReader(nil))
		expectErr(t, err, ErrOffsetMismatch)
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 5000, strings.NewReader("x"))
		expectErr(t, err, ErrTooLarge)
	})
}

func TestExternalSender(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		p := ev.external(t, ev.a)
		data := randomBytes(t, 3000)
		u := ev.newUpload(t, ev.a, p, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data)
		if !bytes.Equal(ev.decrypt(t, u), data) {
			t.Fatal("decrypted content differs")
		}
	})
}

func TestResumeAfterCut(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 6000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})

		// The body breaks in the middle of a chunk.
		body := io.MultiReader(bytes.NewReader(data[:2500]), errReader{io.ErrUnexpectedEOF})
		st, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 0, body)
		expectErr(t, err, ErrInterrupted)
		expectErr(t, err, io.ErrUnexpectedEOF)
		if st.Offset != 2500 || st.Completed || st.Length != 6000 {
			t.Fatalf("status after cut = %+v", st)
		}
		if got := ev.statusOK(t, u); got.Offset != 2500 {
			t.Fatalf("HEAD offset = %d", got.Offset)
		}
		ev.appendOK(t, u, 2500, data[2500:])
		if !bytes.Equal(ev.decrypt(t, u), data) {
			t.Fatal("decrypted content differs after resume")
		}
	})
}

func TestContextCanceled(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		data := randomBytes(t, 4000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		// The first read succeeds and cancels the context.
		body := &cancelReader{r: bytes.NewReader(data), cancel: cancel, n: 1200}
		st, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 0, body)
		expectErr(t, err, ErrInterrupted)
		expectErr(t, err, context.Canceled)
		if st.Offset != 1200 {
			t.Fatalf("offset after cancel = %d", st.Offset)
		}
		ev.appendOK(t, u, 1200, data[1200:])
		if !bytes.Equal(ev.decrypt(t, u), data) {
			t.Fatal("decrypted content differs")
		}
	})
}

// cancelReader returns n bytes (over as many reads as needed), then
// cancels.
type cancelReader struct {
	r      io.Reader
	cancel func()
	n      int
}

func (c *cancelReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b[:min(len(b), c.n)])
	if c.n -= n; c.n <= 0 {
		c.cancel()
	}
	return n, err
}

func TestCrashBetweenWriteAndCheckpoint(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 5000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data[:2100])
		before := ev.file(t, u)

		// Ciphertext written after the checkpoint, never checkpointed.
		f, err := os.OpenFile(ev.path(u.tid, before, ".ttef"), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(make([]byte, 1040)); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		// HEAD still reports the checkpoint; the PATCH resets the upload.
		if got := ev.statusOK(t, u); got.Offset != 2100 {
			t.Fatalf("HEAD before reset = %d", got.Offset)
		}
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 2100, bytes.NewReader(data[2100:]))
		expectErr(t, err, ErrOffsetMismatch)

		after := ev.file(t, u)
		if after.DEKKeyID == before.DEKKeyID || after.StorageName == before.StorageName {
			t.Fatal("reset kept the key or the storage name")
		}
		if _, err := ev.vault.Open(ctx, u.tid, crypto.PurposeDEK, before.DEKKeyID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("old key still opens: %v", err)
		}
		for _, ext := range []string{".ttef", ".ckpt"} {
			if _, err := os.Stat(ev.path(u.tid, before, ext)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("old %s still on disk: %v", ext, err)
			}
		}
		if got := ev.statusOK(t, u); got.Offset != 0 {
			t.Fatalf("HEAD after reset = %d", got.Offset)
		}
		if !strings.Contains(ev.logs.String(), "upload reset") || strings.Contains(ev.logs.String(), u.id) {
			t.Fatalf("reset log: %s", ev.logs.String())
		}
		ev.appendOK(t, u, 0, data)
		if !bytes.Equal(ev.decrypt(t, u), data) {
			t.Fatal("decrypted content differs after reset")
		}
	})
}

func TestResetCases(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		cases := map[string]func(t *testing.T, u upl, f store.TransferFile){
			"file missing": func(t *testing.T, u upl, f store.TransferFile) {
				if err := os.Remove(ev.path(u.tid, f, ".ttef")); err != nil {
					t.Fatal(err)
				}
			},
			"file without checkpoint": func(t *testing.T, u upl, f store.TransferFile) {
				if err := os.Remove(ev.path(u.tid, f, ".ckpt")); err != nil {
					t.Fatal(err)
				}
			},
			"garbage checkpoint": func(t *testing.T, u upl, f store.TransferFile) {
				if err := os.WriteFile(ev.path(u.tid, f, ".ckpt"), []byte("garbage"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			"oversized checkpoint": func(t *testing.T, u upl, f store.TransferFile) {
				if err := os.WriteFile(ev.path(u.tid, f, ".ckpt"), make([]byte, storage.MaxCheckpointSize+1), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			"tampered checkpoint": func(t *testing.T, u upl, f store.TransferFile) {
				p := ev.path(u.tid, f, ".ckpt")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-1] ^= 1
				if err := os.WriteFile(p, b, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		}
		for name, damage := range cases {
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				data := randomBytes(t, 3000)
				u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
				ev.appendOK(t, u, 0, data[:1500])
				before := ev.file(t, u)
				damage(t, u, before)
				_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 1500, bytes.NewReader(data[1500:]))
				expectErr(t, err, ErrOffsetMismatch)
				if after := ev.file(t, u); after.DEKKeyID == before.DEKKeyID {
					t.Fatal("no reset")
				}
				ev.appendOK(t, u, 0, data)
				if !bytes.Equal(ev.decrypt(t, u), data) {
					t.Fatal("decrypted content differs")
				}
			})
		}
	})
}

func TestBadHashStateResets(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		data := randomBytes(t, 3000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data[:1000])
		before := ev.file(t, u)
		ev.eng.resumeWriter = func(dst io.Writer, dek []byte, tid, fid string, st *crypto.State, size int64) (*crypto.Writer, []byte, error) {
			w, _, err := crypto.ResumeWriter(dst, dek, tid, fid, st, size)
			return w, []byte("not a sha256 state"), err
		}
		_, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 1000, bytes.NewReader(data[1000:]))
		expectErr(t, err, ErrOffsetMismatch)
		if ev.file(t, u).DEKKeyID == before.DEKKeyID {
			t.Fatal("no reset")
		}
	})
}

func TestConcurrentAppendBusy(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 4000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 0, pr)
			done <- err
		}()
		// Once a write is consumed, the first Append holds the lock.
		if _, err := pw.Write(data[:100]); err != nil {
			t.Fatal(err)
		}
		_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 0, bytes.NewReader(data))
		expectErr(t, err, ErrBusy)
		expectErr(t, ev.eng.Terminate(ctx, u.tid, u.p, u.id), ErrBusy)
		if _, err := ev.eng.LockFiles([]string{u.fileID}); !errors.Is(err, ErrBusy) {
			t.Fatalf("LockFiles = %v", err)
		}
		_ = pw.Close()
		if err := <-done; err != nil {
			t.Fatalf("first Append: %v", err)
		}
		if got := ev.statusOK(t, u); got.Offset != 100 {
			t.Fatalf("offset = %d", got.Offset)
		}
	})
}

func TestOffsetMismatch(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 3000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		// Not started: only 0 is accepted, and nothing is created.
		_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 5, bytes.NewReader(data))
		expectErr(t, err, ErrOffsetMismatch)
		if _, err := os.Stat(ev.path(u.tid, ev.file(t, u), ".ttef")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file created on mismatch: %v", err)
		}
		ev.appendOK(t, u, 0, data[:1000])
		for _, off := range []int64{0, 999, 1001} {
			_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, off, bytes.NewReader(data[off:]))
			expectErr(t, err, ErrOffsetMismatch)
		}
		ev.appendOK(t, u, 1000, data[1000:])
		if !bytes.Equal(ev.decrypt(t, u), data) {
			t.Fatal("decrypted content differs")
		}
	})
}

func TestOverflow(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		data := randomBytes(t, 1500)
		u := ev.newUpload(t, ev.a, internal, 1000, time.Time{})
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, bytes.NewReader(data))
		expectErr(t, err, ErrTooLarge)
		if st.Offset != 1000 || st.Completed {
			t.Fatalf("status = %+v", st)
		}
		// Nothing beyond the declared length reached the disk: the file
		// holds exactly what the checkpoint covers.
		f := ev.file(t, u)
		b, err := os.ReadFile(ev.path(u.tid, f, ".ckpt"))
		if err != nil {
			t.Fatal(err)
		}
		cst, err := crypto.UnmarshalState(b)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(ev.path(u.tid, f, ".ttef"))
		if err != nil {
			t.Fatal(err)
		}
		if cst.PlaintextSize() != 1000 || info.Size() != cst.CiphertextSize() {
			t.Fatalf("checkpoint covers %d, file %d bytes, want %d", cst.PlaintextSize(), info.Size(), cst.CiphertextSize())
		}
		// An empty PATCH at the length completes the upload.
		if st := ev.appendOK(t, u, 1000, nil); !st.Completed {
			t.Fatalf("status = %+v", st)
		}
		if !bytes.Equal(ev.decrypt(t, u), data[:1000]) {
			t.Fatal("decrypted content differs")
		}
	})
}

func TestExpiry(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		// Never started: the transfer creation is the last activity.
		old := ev.newUpload(t, ev.a, internal, 100, time.Now().Add(-25*time.Hour))
		_, err := ev.eng.Status(ctx, old.tid, old.p, old.id)
		expectErr(t, err, ErrExpired)
		_, err = ev.eng.Append(ctx, old.tid, old.p, old.id, 0, bytes.NewReader(make([]byte, 100)))
		expectErr(t, err, ErrExpired)

		// Started: the checkpoint is the last activity.
		u := ev.newUpload(t, ev.a, internal, 3000, time.Now().Add(-23*time.Hour))
		ev.appendOK(t, u, 0, make([]byte, 1000))
		st := ev.statusOK(t, u)
		if d := time.Until(st.ExpiresAt); d < 23*time.Hour || d > 25*time.Hour {
			t.Fatalf("expires in %v", d)
		}
		ev.eng.now = func() time.Time { return time.Now().Add(DefaultUploadTTL + time.Minute) }
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrExpired)
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 1000, bytes.NewReader(make([]byte, 2000)))
		expectErr(t, err, ErrExpired)
		// Termination stays possible.
		if err := ev.eng.Terminate(ctx, u.tid, u.p, u.id); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
	})
}

func TestAuthorization(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ext := ev.external(t, ev.a)
		u := ev.newUpload(t, ev.a, internal, 100, time.Time{})
		ue := ev.newUpload(t, ev.a, ext, 100, time.Time{})
		other := ev.external(t, ev.a)
		cases := map[string]struct {
			u   upl
			tid tenant.ID
			p   Principal
			id  string
		}{
			"foreign tenant":     {u, ev.b, internal, u.id},
			"other sender":       {u, ev.a, Principal{Email: "eve@entity-a.example.com", Kind: store.DepositorInternal}, u.id},
			"invalid email":      {u, ev.a, Principal{Email: "not an address", Kind: store.DepositorInternal}, u.id},
			"kind mismatch":      {u, ev.a, Principal{Email: internal.Email, Kind: store.DepositorExternal, InvitationID: ext.InvitationID}, u.id},
			"other invitation":   {ue, ev.a, other, ue.id},
			"internal as extern": {ue, ev.a, Principal{Email: ext.Email, Kind: store.DepositorInternal}, ue.id},
			"unknown upload":     {u, ev.a, internal, "upl_0000000000000000000000000000000000000000000"},
			"malformed upload":   {u, ev.a, internal, "../../etc/passwd"},
			"malformed tenant":   {u, "ten_bad", internal, u.id},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				tid := c.tid
				_, err := ev.eng.Status(ctx, tid, c.p, c.id)
				expectErr(t, err, ErrNotFound)
				_, err = ev.eng.Append(ctx, tid, c.p, c.id, 0, bytes.NewReader(make([]byte, 100)))
				expectErr(t, err, ErrNotFound)
				expectErr(t, ev.eng.Terminate(ctx, tid, c.p, c.id), ErrNotFound)
			})
		}
		// The rightful senders still have their uploads untouched.
		if st := ev.statusOK(t, u); st.Offset != 0 {
			t.Fatalf("status = %+v", st)
		}
		ev.appendOK(t, ue, 0, make([]byte, 100))
	})
}

// TestAuthorizationAPIToken checks that an API token reaches only the
// uploads of its own transfers, and a deposit session never those of a
// token, even with the same address.
func TestAuthorizationAPIToken(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		tok, tok2 := ev.token(t, ev.a), ev.token(t, ev.a)
		ut := ev.newUpload(t, ev.a, tok, 100, time.Time{})
		us := ev.newUpload(t, ev.a, internal, 100, time.Time{})
		withEmail := tok
		withEmail.Email = internal.Email
		cases := map[string]struct {
			tid tenant.ID
			p   Principal
			id  string
		}{
			"other token":               {ev.a, tok2, ut.id},
			"session of the same email": {ev.a, internal, ut.id},
			"token on a session upload": {ev.a, tok, us.id},
			"token with the address":    {ev.a, withEmail, us.id},
			"foreign tenant":            {ev.b, tok, ut.id},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				_, err := ev.eng.Status(ctx, c.tid, c.p, c.id)
				expectErr(t, err, ErrNotFound)
				_, err = ev.eng.Append(ctx, c.tid, c.p, c.id, 0, bytes.NewReader(make([]byte, 100)))
				expectErr(t, err, ErrNotFound)
				expectErr(t, ev.eng.Terminate(ctx, c.tid, c.p, c.id), ErrNotFound)
			})
		}
		// The token uploads its own file; the session still has its own.
		ev.appendOK(t, ut, 0, make([]byte, 100))
		if st := ev.statusOK(t, us); st.Offset != 0 {
			t.Fatalf("status = %+v", st)
		}
		if err := ev.eng.Terminate(t.Context(), ut.tid, tok, ut.id); err != nil {
			t.Fatalf("Terminate by its token: %v", err)
		}
	})
}

func TestTerminate(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 3000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data[:1500])
		f := ev.file(t, u)
		if err := ev.eng.Terminate(ctx, u.tid, u.p, u.id); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		if _, err := ev.vault.Open(ctx, u.tid, crypto.PurposeDEK, f.DEKKeyID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("key still opens: %v", err)
		}
		for _, ext := range []string{".ttef", ".ckpt"} {
			if _, err := os.Stat(ev.path(u.tid, f, ext)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s still on disk: %v", ext, err)
			}
		}
		_, err := ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrNotFound)
		d, err := ev.db.Transfers().Get(ctx, u.tid, u.transfer)
		if err != nil {
			t.Fatal(err)
		}
		if d.TotalBytes != 0 || len(d.Files) != 0 {
			t.Fatalf("transfer after termination: %d bytes, %d files", d.TotalBytes, len(d.Files))
		}
	})
}

func TestFinalizedTransfer(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		data := randomBytes(t, 1000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		ev.appendOK(t, u, 0, data)
		s, err := ev.db.Scoped(u.tid)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			return ev.db.Transfers().FinalizeTx(ctx, tx, u.transfer, time.Now())
		})
		if err != nil {
			t.Fatal(err)
		}
		if st := ev.statusOK(t, u); !st.Completed {
			t.Fatalf("status of a scanning transfer = %+v", st)
		}
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 1000, bytes.NewReader(nil))
		expectErr(t, err, ErrFinalized)
		expectErr(t, ev.eng.Terminate(ctx, u.tid, u.p, u.id), ErrFinalized)

		// Other states, through altered reads.
		ev.mutate = func(fu *store.FileUpload) { fu.Transfer.Status = store.TransferAvailable }
		if st := ev.statusOK(t, u); !st.Completed {
			t.Fatalf("status of an available transfer = %+v", st)
		}
		ev.mutate = func(fu *store.FileUpload) { fu.Transfer.Status = store.TransferRejected }
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrFinalized)
		ev.mutate = func(fu *store.FileUpload) {
			fu.Transfer.Status = store.TransferExpired
			fu.File.UploadedAt = time.Time{}
		}
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrFinalized)
		ev.mutate = func(fu *store.FileUpload) { fu.File.DEKKeyID = "" }
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrNotFound)
		ev.mutate = nil
	})
}

func TestInvalidArguments(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		u := ev.newUpload(t, ev.a, internal, 10, time.Time{})
		_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, -1, bytes.NewReader(nil))
		expectErr(t, err, ErrInvalid)
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 0, nil)
		expectErr(t, err, ErrInvalid)
	})
}

func TestLockFiles(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		u1 := ev.newUpload(t, ev.a, internal, 100, time.Time{})
		u2 := ev.newUpload(t, ev.a, internal, 100, time.Time{})
		unlock, err := ev.eng.LockFiles([]string{u1.fileID, u2.fileID, u1.fileID})
		if err == nil {
			t.Fatal("LockFiles with a duplicate succeeded")
		}
		expectErr(t, err, ErrBusy)
		if unlock != nil {
			t.Fatal("unlock returned on failure")
		}
		unlock, err = ev.eng.LockFiles([]string{u1.fileID, u2.fileID})
		if err != nil {
			t.Fatalf("LockFiles: %v", err)
		}
		_, err = ev.eng.Append(ctx, u2.tid, u2.p, u2.id, 0, bytes.NewReader(make([]byte, 100)))
		expectErr(t, err, ErrBusy)
		// A failed LockFiles takes nothing: u3 stays free.
		u3 := ev.newUpload(t, ev.a, internal, 100, time.Time{})
		if _, err := ev.eng.LockFiles([]string{u3.fileID, u1.fileID}); !errors.Is(err, ErrBusy) {
			t.Fatalf("LockFiles = %v", err)
		}
		ev.appendOK(t, u3, 0, make([]byte, 100))
		unlock()
		unlock()
		ev.appendOK(t, u1, 0, make([]byte, 100))
		ev.appendOK(t, u2, 0, make([]byte, 100))
	})
}

func TestRemoveFile(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		u := ev.newUpload(t, ev.a, internal, 3000, time.Time{})
		ev.appendOK(t, u, 0, make([]byte, 1500))
		f := ev.file(t, u)
		if err := ev.eng.RemoveFile(ctx, u.tid, f); err != nil {
			t.Fatalf("RemoveFile: %v", err)
		}
		if _, err := ev.vault.Open(ctx, u.tid, crypto.PurposeDEK, f.DEKKeyID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("key still opens: %v", err)
		}
		if _, err := os.Stat(ev.path(u.tid, f, ".ttef")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file still on disk: %v", err)
		}
		if ev.file(t, u).DEKKeyID != "" {
			t.Fatal("row still references the key")
		}
		// Idempotent: the key is already destroyed (stale and fresh rows).
		if err := ev.eng.RemoveFile(ctx, u.tid, f); err != nil {
			t.Fatalf("RemoveFile again: %v", err)
		}
		if err := ev.eng.RemoveFile(ctx, u.tid, ev.file(t, u)); err != nil {
			t.Fatalf("RemoveFile without key: %v", err)
		}
		// An invalid tenant fails before anything is touched.
		if err := ev.eng.RemoveFile(ctx, "ten_bad", f); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("RemoveFile(bad tenant) = %v", err)
		}
	})
}

func TestWriteEmpty(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		dek := randomBytes(t, crypto.DEKSize)
		name := storage.NewName()
		sum, size, err := ev.eng.WriteEmpty(ctx, ev.a, "fil_empty", dek, name)
		if err != nil {
			t.Fatalf("WriteEmpty: %v", err)
		}
		empty := sha256.Sum256(nil)
		if sum != hex.EncodeToString(empty[:]) || size != crypto.HeaderSize+16 {
			t.Fatalf("WriteEmpty = %s, %d", sum, size)
		}
		src, err := os.Open(ev.path(ev.a, store.TransferFile{StorageName: name}, ".ttef"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = src.Close() }()
		r, err := crypto.NewReader(src, dek, string(ev.a), "fil_empty")
		if err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(r); err != nil || len(b) != 0 {
			t.Fatalf("decrypt = %q, %v", b, err)
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, _, err := ev.eng.WriteEmpty(canceled, ev.a, "fil_empty", dek, storage.NewName()); !errors.Is(err, context.Canceled) {
			t.Fatalf("WriteEmpty(canceled) = %v", err)
		}
	})
}

func TestEmptyFileCompletesOnFirstAppend(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		u := ev.newUpload(t, ev.a, internal, 0, time.Time{})
		if st := ev.appendOK(t, u, 0, nil); !st.Completed || st.Length != 0 {
			t.Fatalf("status = %+v", st)
		}
		if len(ev.decrypt(t, u)) != 0 {
			t.Fatal("not empty")
		}
	})
}

func TestCheckpointCadence(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ev.eng.every = 4096
		var writes int
		ev.faults.set(func(op string) error {
			if op == "writeckpt" {
				writes++
			}
			return nil
		})
		data := randomBytes(t, 20000)
		u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
		st, err := ev.eng.Append(t.Context(), u.tid, u.p, u.id, 0, &pieceReader{r: bytes.NewReader(data[:10000]), n: 1000})
		if err != nil || st.Offset != 10000 {
			t.Fatalf("Append = %+v, %v", st, err)
		}
		// Two in-request checkpoints (after 5000 and 10000 bytes); the final
		// one is skipped, nothing having arrived since the last.
		if writes != 2 {
			t.Fatalf("checkpoints written = %d, want 2", writes)
		}
		// The last read reaches the length: no checkpoint at all, the file
		// completes.
		writes = 0
		ev.appendOK(t, u, 10000, data[10000:])
		if writes != 0 {
			t.Fatalf("checkpoints written = %d, want 0", writes)
		}
		ev.faults.set(nil)
		if !bytes.Equal(ev.decrypt(t, u), data) {
			t.Fatal("decrypted content differs")
		}
	})
}
