package upload

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
)

// limitedWriter returns a NewWriter hook whose destination fails beyond
// limit bytes.
func limitedWriter(limit int64) func(io.Writer, []byte, string, string, ...crypto.Option) (*crypto.Writer, error) {
	return func(dst io.Writer, dek []byte, tid, fid string, opts ...crypto.Option) (*crypto.Writer, error) {
		return smallChunks(&failWriter{w: dst, limit: limit}, dek, tid, fid, opts...)
	}
}

// failingNewWriter is a NewWriter hook that always fails.
func failingNewWriter(io.Writer, []byte, string, string, ...crypto.Option) (*crypto.Writer, error) {
	return nil, errBoom
}

// Upload states the fault cases start from.
const (
	fresh   = iota // created, nothing sent
	partial        // 1500 of 3000 bytes sent
	broken         // partial, then its checkpoint removed: the next Append resets
)

func TestFaultsAppend(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		// Built per engine: failNth hooks count their calls.
		cases := []struct {
			name   string
			state  int
			hook   hookFunc
			writer func(io.Writer, []byte, string, string, ...crypto.Option) (*crypto.Writer, error)
			resume bool // resumeWriter fails with a generic error
			offset int64
			body   int // bytes sent
			every  int64
		}{
			{name: "load", state: fresh, hook: failOn("get"), body: 100},
			{name: "reload under lock", state: fresh, hook: failNth("get", 2), body: 100},
			{name: "read checkpoint", state: partial, hook: failOn("readckpt"), offset: 1500, body: 100},
			{name: "open key", state: partial, hook: failOn("open"), offset: 1500, body: 100},
			{name: "create file", state: fresh, hook: failOn("create"), body: 100},
			{name: "start writer", state: fresh, writer: failingNewWriter, body: 100},
			{name: "open for resume", state: partial, hook: failOn("openappend"), offset: 1500, body: 100},
			{name: "probe file", state: fresh, hook: failOn("openappend"), body: 100},
			{name: "resume writer", state: partial, resume: true, offset: 1500, body: 100},
			{name: "chunk write", state: fresh, writer: limitedWriter(crypto.HeaderSize), body: 2000},
			{name: "final chunk write", state: fresh, writer: limitedWriter(crypto.HeaderSize + 2*(crypto.MinChunkSize+16)), body: 3000},
			{name: "sync checkpoint", state: fresh, hook: failOn("sync"), body: 100},
			{name: "write checkpoint", state: fresh, hook: failOn("writeckpt"), body: 100},
			{name: "periodic checkpoint", state: fresh, hook: failOn("writeckpt"), body: 2500, every: 1024},
			{name: "sync final", state: fresh, hook: failOn("sync"), body: 3000},
			{name: "complete", state: fresh, hook: failOn("complete"), body: 3000},
			{name: "reset new key", state: broken, hook: failOn("newdek"), offset: 1500, body: 100},
			{name: "reset replace key", state: broken, hook: failOn("replacedek"), offset: 1500, body: 100},
			{name: "reset destroy key", state: broken, hook: failOn("destroy"), offset: 1500, body: 100},
			{name: "reset create file", state: broken, hook: failOn("create"), offset: 1500, body: 100},
			{name: "reset checkpoint", state: broken, hook: failOn("writeckpt"), offset: 1500, body: 100},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ctx := t.Context()
				data := randomBytes(t, 3000)
				u := ev.newUpload(t, ev.a, internal, int64(len(data)), time.Time{})
				if c.state != fresh {
					ev.appendOK(t, u, 0, data[:1500])
				}
				if c.state == broken {
					if err := os.Remove(ev.path(u.tid, ev.file(t, u), ".ckpt")); err != nil {
						t.Fatal(err)
					}
				}
				if c.writer != nil {
					ev.eng.newWriter = c.writer
				}
				if c.resume {
					ev.eng.resumeWriter = func(io.Writer, []byte, string, string, *crypto.State, int64) (*crypto.Writer, []byte, error) {
						return nil, nil, errBoom
					}
				}
				if c.every != 0 {
					ev.eng.every = c.every
				}
				ev.faults.set(c.hook)
				t.Cleanup(func() {
					ev.faults.set(nil)
					ev.eng.newWriter, ev.eng.resumeWriter, ev.eng.every = smallChunks, crypto.ResumeWriter, 1<<20
				})
				body := &pieceReader{r: bytes.NewReader(data[c.offset : c.offset+int64(c.body)]), n: 600}
				_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, c.offset, body)
				expectErr(t, err, errBoom)
			})
		}
	})
}

func TestFaultsLoggedOnly(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		t.Cleanup(func() { ev.faults.set(nil) })

		// Removal of the previous files and scrub during a reset.
		u := ev.newUpload(t, ev.a, internal, 3000, time.Time{})
		ev.appendOK(t, u, 0, make([]byte, 1500))
		if err := os.Remove(ev.path(u.tid, ev.file(t, u), ".ckpt")); err != nil {
			t.Fatal(err)
		}
		ev.faults.set(failOn("remove", "scrub"))
		_, err := ev.eng.Append(ctx, u.tid, u.p, u.id, 1500, bytes.NewReader(make([]byte, 1500)))
		expectErr(t, err, ErrOffsetMismatch)
		logs := ev.logs.String()
		if !strings.Contains(logs, "previous encrypted file left on disk") || !strings.Contains(logs, "scrubbing destroyed keys failed") {
			t.Fatalf("logs: %s", logs)
		}

		// Removal of the checkpoint of a completed file.
		ev.faults.set(failOn("removeckpt"))
		if st := ev.appendOK(t, u, 0, make([]byte, 3000)); !st.Completed {
			t.Fatalf("status = %+v", st)
		}
		if !strings.Contains(ev.logs.String(), "checkpoint of a completed file left on disk") {
			t.Fatalf("logs: %s", ev.logs.String())
		}

		// Removal of the files of a terminated upload.
		ev.faults.set(failOn("remove"))
		if err := ev.eng.Terminate(ctx, u.tid, u.p, u.id); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		if !strings.Contains(ev.logs.String(), "terminated upload left on disk") {
			t.Fatalf("logs: %s", ev.logs.String())
		}
		ev.faults.set(nil)
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, ErrNotFound)
	})
}

func TestFaultsStatus(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		ctx := t.Context()
		t.Cleanup(func() { ev.faults.set(nil) })
		u := ev.newUpload(t, ev.a, internal, 3000, time.Time{})
		ev.faults.set(failOn("get"))
		_, err := ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, errBoom)
		ev.faults.set(failOn("readckpt"))
		_, err = ev.eng.Status(ctx, u.tid, u.p, u.id)
		expectErr(t, err, errBoom)
		_, _, err = ev.eng.Offset(ctx, u.tid, ev.file(t, u), time.Now(), time.Now())
		expectErr(t, err, errBoom)
	})
}

func TestFaultsTerminate(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		t.Cleanup(func() { ev.faults.set(nil) })
		for _, op := range []string{"get", "destroy", "deletefile"} {
			t.Run(op, func(t *testing.T) {
				ctx := t.Context()
				u := ev.newUpload(t, ev.a, internal, 3000, time.Time{})
				ev.appendOK(t, u, 0, make([]byte, 1000))
				ev.faults.set(failOn(op))
				expectErr(t, ev.eng.Terminate(ctx, u.tid, u.p, u.id), errBoom)
				ev.faults.set(nil)
				// Nothing was deleted: the upload goes on.
				if st := ev.statusOK(t, u); st.Offset != 1000 {
					t.Fatalf("status = %+v", st)
				}
			})
		}
	})
}

func TestFaultsRemoveFile(t *testing.T) {
	run(t, func(t *testing.T, ev *env) {
		t.Cleanup(func() { ev.faults.set(nil) })
		for _, op := range []string{"destroy", "remove"} {
			t.Run(op, func(t *testing.T) {
				ctx := t.Context()
				u := ev.newUpload(t, ev.a, internal, 3000, time.Time{})
				ev.appendOK(t, u, 0, make([]byte, 1000))
				ev.faults.set(failOn(op))
				expectErr(t, ev.eng.RemoveFile(ctx, u.tid, ev.file(t, u)), errBoom)
			})
		}
	})
}

func TestFaultsWriteEmpty(t *testing.T) {
	cases := []struct {
		name   string
		hook   hookFunc
		writer func(io.Writer, []byte, string, string, ...crypto.Option) (*crypto.Writer, error)
	}{
		{name: "create", hook: failOn("create")},
		{name: "start writer", writer: failingNewWriter},
		{name: "final chunk", writer: limitedWriter(crypto.HeaderSize)},
		{name: "sync", hook: failOn("sync")},
		{name: "sync directory", hook: failOn("syncdir")},
	}
	run(t, func(t *testing.T, ev *env) {
		dek := randomBytes(t, crypto.DEKSize)
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ctx := t.Context()
				if c.writer != nil {
					ev.eng.newWriter = c.writer
				}
				ev.faults.set(c.hook)
				t.Cleanup(func() {
					ev.faults.set(nil)
					ev.eng.newWriter = smallChunks
				})
				name := storage.NewName()
				_, _, err := ev.eng.WriteEmpty(ctx, ev.a, "fil_empty", dek, name)
				expectErr(t, err, errBoom)
				// The file is removed on failure.
				if _, err := os.Stat(ev.path(ev.a, store.TransferFile{StorageName: name}, ".ttef")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("file left on disk: %v", err)
				}
			})
		}
	})
}
