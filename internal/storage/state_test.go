package storage

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestStateName(t *testing.T) {
	trf := id.New(id.Transfer)
	n := StateName(trf)
	if !ValidName(n) {
		t.Fatalf("StateName(%q) = %q, not a storage name", trf, n)
	}
	if StateName(trf) != n {
		t.Fatal("StateName is not deterministic")
	}
	if StateName(id.New(id.Transfer)) == n || StateName("") == n {
		t.Fatal("distinct keys share a state name")
	}
	// Pinned value: the download layer finds existing states after an
	// upgrade only if the derivation never changes.
	if got := StateName("trf_01J00000000000000000000000"); got != "3542ed8e680abe6a85432111a8e0b0f8" {
		t.Fatalf("StateName pinned value = %q", got)
	}
}

func TestStateRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := StateName(id.New(id.Transfer))

	_, err := s.ReadState(tid, name)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing state: got %v", err)
	}
	noLeak(t, err, dir)

	if err := s.WriteState(tid, name, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState(tid, name, []byte("second")); err != nil {
		t.Fatal(err)
	}
	data, err := s.ReadState(tid, name)
	if err != nil || string(data) != "second" {
		t.Fatalf("ReadState = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, string(tid), name+".dlstate")); err != nil {
		t.Fatalf("expected <name>.dlstate: %v", err)
	}

	// Maximum size accepted, one more byte refused (the previous state
	// stays).
	maxData := bytes.Repeat([]byte{2}, MaxStateSize)
	if err := s.WriteState(tid, name, maxData); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState(tid, name, append(maxData, 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized write: got %v", err)
	}
	if data, err := s.ReadState(tid, name); err != nil || !bytes.Equal(data, maxData) {
		t.Fatalf("state after a refused write: %d bytes, %v", len(data), err)
	}

	for range 2 {
		if err := s.RemoveState(tid, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ReadState(tid, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after RemoveState: got %v", err)
	}
	// Missing tenant directory is fine as well.
	if err := s.RemoveState(newTenant(), name); err != nil {
		t.Fatal(err)
	}
}

// TestStateNamespaces checks that a stored file, its checkpoint and a state
// of the same name are distinct entries: removing one kind never removes
// another.
func TestStateNamespaces(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()
	writeFile(t, s, tid, name, []byte("data"))
	if err := s.WriteCheckpoint(tid, name, []byte("ckpt")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState(tid, name, []byte("state")); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(tid, name); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, filepath.Join(dir, string(tid))); !slices.Equal(got, []string{name + ".dlstate"}) {
		t.Fatalf("after Remove: %v", got)
	}
	if data, err := s.ReadState(tid, name); err != nil || string(data) != "state" {
		t.Fatalf("state after Remove = %q, %v", data, err)
	}

	writeFile(t, s, tid, name, []byte("data"))
	if err := s.WriteCheckpoint(tid, name, []byte("ckpt")); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveState(tid, name); err != nil {
		t.Fatal(err)
	}
	got := listDir(t, filepath.Join(dir, string(tid)))
	slices.Sort(got)
	if !slices.Equal(got, []string{name + ".ckpt", name + ".ttef"}) {
		t.Fatalf("after RemoveState: %v", got)
	}
}

func TestStateValidation(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	calls := map[string]func(tenant.ID, string) error{
		"WriteState": func(t tenant.ID, n string) error { return s.WriteState(t, n, []byte("x")) },
		"ReadState": func(t tenant.ID, n string) error {
			_, err := s.ReadState(t, n)
			return err
		},
		"RemoveState": s.RemoveState,
	}
	for op, call := range calls {
		for _, c := range []struct {
			tid  tenant.ID
			name string
		}{
			{"", NewName()},
			{"../" + tid, NewName()},
			{tid, ""},
			{tid, "../" + NewName()[3:]},
			{tid, strings.ToUpper(NewName())},
			{tid, NewName() + ".dlstate"},
		} {
			err := call(c.tid, c.name)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s(%q, %q): got %v", op, c.tid, c.name, err)
			}
			noLeak(t, err, dir)
		}
	}
	if got := listDir(t, dir); len(got) != 0 {
		t.Fatalf("file system touched: %v", got)
	}
}

func TestStateFaults(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	name := NewName()

	// A directory in place of the state is not a regular file.
	if err := os.MkdirAll(filepath.Join(dir, string(tid), name+".dlstate"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadState(tid, name); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ReadState on a directory: got %v", err)
	}

	// An oversized state on disk is refused.
	other := NewName()
	big := bytes.Repeat([]byte{1}, MaxStateSize+1)
	if err := os.WriteFile(filepath.Join(dir, string(tid), other+".dlstate"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadState(tid, other); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized state: got %v", err)
	}

	s.ops.readAll = func(io.Reader) ([]byte, error) { return nil, errFault }
	if _, err := s.ReadState(tid, other); !errors.Is(err, errFault) {
		t.Fatalf("read fault: got %v", err)
	}

	// A failed write leaves the previous state and no temporary file.
	if err := s.WriteState(tid, other, []byte("old")); err != nil {
		t.Fatal(err)
	}
	s.ops.rename = func(o, n string) error {
		return &os.LinkError{Op: "rename", Old: filepath.Join(dir, o), New: filepath.Join(dir, n), Err: errFault}
	}
	err := s.WriteState(tid, other, []byte("new"))
	if !errors.Is(err, errFault) {
		t.Fatalf("rename fault: got %v", err)
	}
	noLeak(t, err, dir)
	if got, err := os.ReadFile(filepath.Join(dir, string(tid), other+".dlstate")); err != nil || string(got) != "old" {
		t.Fatalf("previous state = %q, %v", got, err)
	}
	for _, n := range listDir(t, filepath.Join(dir, string(tid))) {
		if strings.HasSuffix(n, ".tmp") {
			t.Fatalf("temporary file left: %s", n)
		}
	}

	s.ops.remove = func(n string) error {
		return &fs.PathError{Op: "remove", Path: filepath.Join(dir, n), Err: errFault}
	}
	err = s.RemoveState(tid, other)
	if !errors.Is(err, errFault) {
		t.Fatalf("remove fault: got %v", err)
	}
	noLeak(t, err, dir)
}
