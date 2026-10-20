package upload

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
)

// TestTransferLevelActivity uploads the files of a transfer one after the
// other: a file not started yet expires with its transfer, not 24 h after
// the creation of the transfer.
func TestTransferLevelActivity(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		created := time.Now().Add(-25 * time.Hour)
		ups := ev.newTransfer(t, ev.a, internal, []int64{3000, 2000, 1000}, created)
		u1, u2, u3 := ups[0], ups[1], ups[2]

		// Created 25 h ago and nothing sent: the whole transfer expired.
		_, err := ev.eng.Status(ctx, u2.tid, u2.p, u2.id)
		expectErr(t, err, ErrExpired)
		files, err := ev.db.TransferFiles().ListByTransfer(ctx, u1.tid, u1.transfer)
		if err != nil {
			t.Fatal(err)
		}
		last, exp, err := ev.eng.TransferActivity(ctx, u1.tid, files, created)
		if err != nil || !last.Equal(created) || !exp.Equal(created.Add(DefaultUploadTTL)) {
			t.Fatalf("TransferActivity = %v, %v, %v", last, exp, err)
		}

		// File 1 started within the window and was checkpointed 1 h ago.
		ev.eng.now = func() time.Time { return created.Add(time.Hour) }
		ev.appendOK(t, u1, 0, make([]byte, 1000))
		ev.eng.now = time.Now
		ckpt := ev.path(u1.tid, ev.file(t, u1), ".ckpt")
		hourAgo := time.Now().Add(-time.Hour)
		if err := os.Chtimes(ckpt, hourAgo, hourAgo); err != nil {
			t.Fatal(err)
		}

		// File 2 has no checkpoint but follows the transfer activity.
		st := ev.statusOK(t, u2)
		if st.Offset != 0 || st.ExpiresAt.Sub(hourAgo.Add(DefaultUploadTTL)).Abs() > time.Second {
			t.Fatalf("status of file 2 = %+v", st)
		}
		ev.appendOK(t, u2, 0, make([]byte, 2000))

		// A completed file counts too, and a checkpoint that is not a
		// regular file is ignored.
		files, err = ev.db.TransferFiles().ListByTransfer(ctx, u1.tid, u1.transfer)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(ckpt); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(ckpt, 0o750); err != nil {
			t.Fatal(err)
		}
		last, _, err = ev.eng.TransferActivity(ctx, u1.tid, files, created)
		if err != nil || !last.Equal(files[1].UploadedAt) {
			t.Fatalf("TransferActivity = %v, %v, want %v", last, err, files[1].UploadedAt)
		}
		if err := os.Remove(ckpt); err != nil {
			t.Fatal(err)
		}

		// Offset keeps the later of the transfer activity and the file's
		// own checkpoint.
		ev.appendOK(t, u3, 0, make([]byte, 500))
		f3 := ev.file(t, u3)
		_, exp, err = ev.eng.Offset(ctx, u3.tid, f3, created, created)
		if err != nil || time.Until(exp) < DefaultUploadTTL-time.Minute {
			t.Fatalf("Offset expiry = %v, %v", exp, err)
		}
		future := time.Now().Add(time.Hour)
		_, exp, err = ev.eng.Offset(ctx, u3.tid, f3, future, future)
		if err != nil || !exp.Equal(future.Add(DefaultUploadTTL)) {
			t.Fatalf("Offset expiry = %v, %v", exp, err)
		}
	})
}

func TestFaultsActivity(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		t.Cleanup(func() { ev.faults.set(nil) })
		for _, op := range []string{"list", "ckpttime"} {
			t.Run(op, func(t *testing.T) {
				ctx := t.Context()
				ups := ev.newTransfer(t, ev.a, internal, []int64{3000, 1000}, time.Time{})
				ev.appendOK(t, ups[0], 0, make([]byte, 500))
				ev.faults.set(failOn(op))
				_, err := ev.eng.Status(ctx, ups[1].tid, ups[1].p, ups[1].id)
				expectErr(t, err, errBoom)
				_, err = ev.eng.Append(ctx, ups[1].tid, ups[1].p, ups[1].id, 0, bytes.NewReader(make([]byte, 1000)))
				expectErr(t, err, errBoom)
				ev.faults.set(nil)
				if st := ev.statusOK(t, ups[1]); st.Offset != 0 {
					t.Fatalf("status = %+v", st)
				}
			})
		}
	})
}

func TestRemoveFilesBatch(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		t.Cleanup(func() { ev.faults.set(nil) })
		t.Run("one scrub for the batch", func(t *testing.T) {
			ctx := t.Context()
			ups := ev.newTransfer(t, ev.a, internal, []int64{3000, 3000, 3000}, time.Time{})
			var files []store.TransferFile
			for _, u := range ups {
				ev.appendOK(t, u, 0, make([]byte, 1500))
				files = append(files, ev.file(t, u))
			}
			files = append(files, store.TransferFile{ID: "fil_nokey", StorageName: files[0].StorageName})
			scrubs := 0
			ev.faults.set(func(op string) error {
				if op == "scrub" {
					scrubs++
				}
				return nil
			})
			if err := ev.eng.RemoveFiles(ctx, ev.a, files); err != nil {
				t.Fatalf("RemoveFiles: %v", err)
			}
			if scrubs != 1 {
				t.Fatalf("scrubs = %d, want 1", scrubs)
			}
			for _, f := range files[:3] {
				if _, err := ev.vault.Open(ctx, ev.a, crypto.PurposeDEK, f.DEKKeyID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("key of %s still opens: %v", f.ID, err)
				}
				if _, err := os.Stat(ev.path(ev.a, f, ".ttef")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s still on disk: %v", f.ID, err)
				}
			}
		})
		t.Run("a failed removal does not stop the batch", func(t *testing.T) {
			ctx := t.Context()
			ups := ev.newTransfer(t, ev.a, internal, []int64{3000, 3000}, time.Time{})
			var files []store.TransferFile
			for _, u := range ups {
				ev.appendOK(t, u, 0, make([]byte, 1500))
				files = append(files, ev.file(t, u))
			}
			ev.faults.set(failNth("remove", 1))
			err := ev.eng.RemoveFiles(ctx, ev.a, files)
			expectErr(t, err, errBoom)
			ev.faults.set(nil)
			if _, err := os.Stat(ev.path(ev.a, files[1], ".ttef")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("second file still on disk: %v", err)
			}
			if _, err := ev.vault.Open(ctx, ev.a, crypto.PurposeDEK, files[0].DEKKeyID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("key of the first file still opens: %v", err)
			}
		})
		t.Run("a failed transaction removes nothing", func(t *testing.T) {
			ctx := t.Context()
			ups := ev.newTransfer(t, ev.a, internal, []int64{3000, 3000}, time.Time{})
			var files []store.TransferFile
			for _, u := range ups {
				ev.appendOK(t, u, 0, make([]byte, 1500))
				files = append(files, ev.file(t, u))
			}
			ev.faults.set(failNth("destroy", 2))
			expectErr(t, ev.eng.RemoveFiles(ctx, ev.a, files), errBoom)
			ev.faults.set(nil)
			for _, u := range ups {
				if st := ev.statusOK(t, u); st.Offset != 1500 {
					t.Fatalf("status = %+v", st)
				}
			}
		})
	})
}

// TestEngineChunkSize checks that the engine passes its own chunk size to
// crypto.NewWriter: the files it writes use chunkSize whatever the crypto
// default.
func TestEngineChunkSize(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ev.eng.newWriter = crypto.NewWriter
		t.Cleanup(func() { ev.eng.newWriter = smallChunks })
		u := ev.newUpload(t, ev.a, internal, 3*chunkSize, time.Time{})
		ev.appendOK(t, u, 0, make([]byte, chunkSize+10))
		b, err := os.ReadFile(ev.path(u.tid, ev.file(t, u), ".ckpt"))
		if err != nil {
			t.Fatal(err)
		}
		st, err := crypto.UnmarshalState(b)
		if err != nil {
			t.Fatal(err)
		}
		if st.ChunkSize() != chunkSize {
			t.Fatalf("chunk size = %d, want %d", st.ChunkSize(), chunkSize)
		}
	})
}

// TestMaxAge checks that activity cannot keep an upload alive longer than
// Options.MaxAge after the creation of its transfer.
func TestMaxAge(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		created := time.Now().Add(-DefaultMaxAge + time.Hour).Truncate(time.Millisecond)
		limit := created.Add(DefaultMaxAge)
		u := ev.newUpload(t, ev.a, internal, 3000, created)
		// Started within the TTL, and active again just now (checkpoint
		// time): the TTL alone would let it live 24 more hours, the maximum
		// age 1 hour only.
		ev.eng.now = func() time.Time { return created.Add(time.Hour) }
		ev.appendOK(t, u, 0, make([]byte, 1000))
		ev.eng.now = time.Now
		files, err := ev.db.TransferFiles().ListByTransfer(ctx, u.tid, u.transfer)
		if err != nil {
			t.Fatal(err)
		}
		if _, exp, err := ev.eng.TransferActivity(ctx, u.tid, files, created); err != nil || !exp.Equal(limit) {
			t.Fatalf("TransferActivity = %v, %v; want %v", exp, err, limit)
		}
		recent := time.Now().Add(-time.Minute)
		if _, exp, err := ev.eng.Offset(ctx, u.tid, files[0], created, recent); err != nil || !exp.Equal(limit) {
			t.Fatalf("Offset expiry = %v, %v; want %v", exp, err, limit)
		}
		if _, exp, err := ev.eng.Offset(ctx, u.tid, files[0], recent, recent); err != nil || exp.Before(recent.Add(DefaultUploadTTL)) {
			t.Fatalf("Offset expiry of a young transfer = %v, %v", exp, err)
		}
		if st := ev.appendOK(t, u, 1000, make([]byte, 1000)); !st.ExpiresAt.Equal(limit) {
			t.Fatalf("PATCH expiry = %v, want %v", st.ExpiresAt, limit)
		}
		if st := ev.statusOK(t, u); !st.ExpiresAt.Equal(limit) {
			t.Fatalf("HEAD expiry = %v, want %v", st.ExpiresAt, limit)
		}
		// Past the maximum age, the upload is expired whatever its activity.
		ev.eng.now = func() time.Time { return limit.Add(time.Second) }
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrExpired)
		_, err = ev.eng.Append(ctx, u.tid, u.p, u.id, 2000, bytes.NewReader(make([]byte, 10)))
		expectErr(t, err, ErrExpired)
	})
}

// TestEmptyPatchKeepsActivity checks that a PATCH without bytes neither
// rewrites the checkpoint nor creates a file, so that it cannot refresh the
// activity of an upload.
func TestEmptyPatchKeepsActivity(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		// Not started: no file is created and the expiry is unchanged.
		fresh := ev.newUpload(t, ev.a, internal, 3000, time.Time{})
		before := ev.statusOK(t, fresh)
		st := ev.appendOK(t, fresh, 0, nil)
		if st.Offset != 0 || st.Completed || !st.ExpiresAt.Equal(before.ExpiresAt) {
			t.Fatalf("status = %+v, want expiry %v", st, before.ExpiresAt)
		}
		f := ev.file(t, fresh)
		for _, ext := range []string{".ttef", ".ckpt"} {
			if _, err := os.Stat(ev.path(fresh.tid, f, ext)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s created by an empty PATCH: %v", ext, err)
			}
		}
		st, err := ev.eng.Append(ctx, fresh.tid, fresh.p, fresh.id, 0, errReader{errBoom})
		expectErr(t, err, ErrInterrupted)
		if st.Offset != 0 || !errors.Is(err, errBoom) {
			t.Fatalf("interrupted: %+v, %v", st, err)
		}

		// Started: the checkpoint keeps its time.
		u := ev.newUpload(t, ev.a, internal, 3000, time.Now().Add(-3*time.Hour))
		ev.appendOK(t, u, 0, make([]byte, 1000))
		ckpt := ev.path(u.tid, ev.file(t, u), ".ckpt")
		old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
		if err := os.Chtimes(ckpt, old, old); err != nil {
			t.Fatal(err)
		}
		want := old.Add(DefaultUploadTTL)
		if st := ev.appendOK(t, u, 1000, nil); st.Offset != 1000 || !st.ExpiresAt.Equal(want) {
			t.Fatalf("empty PATCH = %+v, want expiry %v", st, want)
		}
		if _, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 1000, errReader{errBoom}); !errors.Is(err, ErrInterrupted) {
			t.Fatalf("interrupted: %v", err)
		}
		info, err := os.Stat(ckpt)
		if err != nil || !info.ModTime().Equal(old) {
			t.Fatalf("checkpoint time = %v, %v; want %v", info.ModTime(), err, old)
		}
		// A PATCH with bytes refreshes it, and its expiry comes from the
		// time of the checkpoint it wrote, as HEAD computes it.
		st = ev.appendOK(t, u, 1000, make([]byte, 500))
		info, err = os.Stat(ckpt)
		if err != nil || !st.ExpiresAt.Equal(info.ModTime().Add(DefaultUploadTTL)) {
			t.Fatalf("PATCH expiry %v, checkpoint time %v, %v", st.ExpiresAt, info.ModTime(), err)
		}
		if head := ev.statusOK(t, u); !head.ExpiresAt.Equal(st.ExpiresAt) {
			t.Fatalf("HEAD expiry %v, PATCH expiry %v", head.ExpiresAt, st.ExpiresAt)
		}
		// Unreadable checkpoint time after the write: the clock is used.
		t.Cleanup(func() { ev.faults.set(nil) })
		ev.faults.set(failNth("ckpttime", 2))
		st = ev.appendOK(t, u, 1500, make([]byte, 500))
		if d := time.Until(st.ExpiresAt); d < DefaultUploadTTL-time.Minute || d > DefaultUploadTTL {
			t.Fatalf("fallback expiry in %v", d)
		}
		ev.faults.set(nil)
		// A file whose offset equals its length still completes.
		if st := ev.appendOK(t, u, 2000, make([]byte, 1000)); !st.Completed {
			t.Fatalf("status = %+v", st)
		}
	})
}
