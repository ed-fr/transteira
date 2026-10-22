package storage

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ed-fr/transteira/internal/tenant"
)

func TestAssetRoundTrip(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	for _, name := range []string{AssetLogo, AssetBackground} {
		if _, err := s.ReadAsset(tid, name); !errors.Is(err, ErrNotFound) || !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("missing %s: %v", name, err)
		}
		if err := s.RemoveAsset(tid, name); err != nil {
			t.Fatalf("remove missing %s: %v", name, err)
		}
		if err := s.WriteAsset(tid, name, []byte("v1-"+name)); err != nil {
			t.Fatal(err)
		}
		if err := s.WriteAsset(tid, name, []byte("v2-"+name)); err != nil {
			t.Fatal(err)
		}
		got, err := s.ReadAsset(tid, name)
		if err != nil || !bytes.Equal(got, []byte("v2-"+name)) {
			t.Fatalf("read %s = %q, %v", name, got, err)
		}
	}
	if got := listDir(t, filepath.Join(dir, string(tid))); len(got) != 2 {
		t.Fatalf("entries = %v", got)
	}
	entries, err := s.List(tid)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Kind != KindAsset || (e.Name != AssetLogo && e.Name != AssetBackground) {
			t.Fatalf("entry %+v", e)
		}
	}
	for _, name := range []string{AssetLogo, AssetBackground} {
		if err := s.RemoveAsset(tid, name); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadAsset(tid, name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("after remove: %v", err)
		}
	}
}

func TestAssetValidation(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	for _, c := range []struct {
		tid  tenant.ID
		name string
	}{
		{"bad", AssetLogo},
		{tid, "favicon"},
		{tid, "../logo"},
		{tid, NewName()},
		{tid, ""},
	} {
		if err := s.WriteAsset(c.tid, c.name, []byte("x")); !errors.Is(err, ErrInvalid) {
			t.Errorf("WriteAsset(%q, %q) = %v", c.tid, c.name, err)
		}
		if _, err := s.ReadAsset(c.tid, c.name); !errors.Is(err, ErrInvalid) {
			t.Errorf("ReadAsset(%q, %q) = %v", c.tid, c.name, err)
		}
		if err := s.RemoveAsset(c.tid, c.name); !errors.Is(err, ErrInvalid) {
			t.Errorf("RemoveAsset(%q, %q) = %v", c.tid, c.name, err)
		}
	}
	if got := listDir(t, dir); len(got) != 0 {
		t.Fatalf("file system touched: %v", got)
	}
	if err := s.WriteAsset(tid, AssetLogo, make([]byte, MaxAssetSize+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too large: %v", err)
	}
}

func TestAssetReadErrors(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	if err := os.MkdirAll(filepath.Join(dir, string(tid), AssetLogo+assetExt), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadAsset(tid, AssetLogo); !errors.Is(err, ErrInvalid) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("directory: %v", err)
	}
}

func TestClassifyAsset(t *testing.T) {
	cases := []struct {
		file, name string
		kind       Kind
	}{
		{"logo.asset", "logo", KindAsset},
		{"background.asset", "background", KindAsset},
		{tempName("logo", assetExt), "logo", KindTemp},
		{tempName("background", assetExt), "background", KindTemp},
		{"logo", "logo", KindUnknown},
		{"logo.png", "logo.png", KindUnknown},
		{"favicon.asset", "favicon.asset", KindUnknown},
		{"logo.asset.0123456789abcdef", "logo.asset.0123456789abcdef", KindUnknown},
		{"logo.asset.0123456789abcde.tmp", "logo.asset.0123456789abcde.tmp", KindUnknown},
		{"logo.asset.x", "logo.asset.x", KindUnknown},
	}
	for _, c := range cases {
		name, kind := classify(c.file)
		if name != c.name || kind != c.kind {
			t.Errorf("classify(%q) = %q, %v; want %q, %v", c.file, name, kind, c.name, c.kind)
		}
	}
	if KindAsset.String() != "asset" {
		t.Fatal(KindAsset.String())
	}
}

func TestRemoveAssetTemp(t *testing.T) {
	s, dir := newTestStore(t)
	tid := newTenant()
	tmp := tempName(AssetLogo, assetExt)
	if err := os.MkdirAll(filepath.Join(dir, string(tid)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, string(tid), tmp), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveTemp(tid, tmp); err != nil {
		t.Fatal(err)
	}
	if got := listDir(t, filepath.Join(dir, string(tid))); len(got) != 0 {
		t.Fatalf("left: %v", got)
	}
}
