package masterkey_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestNew(t *testing.T) {
	t.Parallel()
	a, b := newKey(t), newKey(t)
	if _, err := masterkey.New(nil, b); !errors.Is(err, masterkey.ErrNoCurrentKey) {
		t.Errorf("New(nil) = %v", err)
	}
	k1, k2 := masterkeytest.Key(t, "same"), masterkeytest.Key(t, "same")
	if _, err := masterkey.New(k1, k2); !errors.Is(err, masterkey.ErrSameKey) || !strings.Contains(err.Error(), k1.ID()) {
		t.Errorf("New(same key) = %v", err)
	}

	kr := keyring(t, a, nil)
	if kr.CurrentID() != a.ID() || kr.NewID() != "" || kr.WrapID() != a.ID() {
		t.Errorf("keyring(a) = %s, %q, %s", kr.CurrentID(), kr.NewID(), kr.WrapID())
	}
	kr = keyring(t, a, b)
	if kr.CurrentID() != a.ID() || kr.NewID() != b.ID() || kr.WrapID() != b.ID() {
		t.Errorf("keyring(a, b) = %s, %s, %s", kr.CurrentID(), kr.NewID(), kr.WrapID())
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cur, curID := masterkeytest.WriteLabeledKeyFile(t, dir, "current")
	next, nextID := masterkeytest.WriteLabeledKeyFile(t, dir, "new")
	same, _ := masterkeytest.WriteLabeledKeyFile(t, t.TempDir(), "current")
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := masterkey.Load(&config.Config{}); !errors.Is(err, masterkey.ErrNoCurrentKey) ||
		!strings.Contains(err.Error(), config.EnvMasterKeyFile) {
		t.Errorf("Load(no file) = %v", err)
	}
	if _, err := masterkey.Load(&config.Config{MasterKeyFile: filepath.Join(dir, "missing.key")}); err == nil ||
		!strings.Contains(err.Error(), config.EnvMasterKeyFile+":") {
		t.Errorf("Load(missing file) = %v", err)
	}
	_, err := masterkey.Load(&config.Config{MasterKeyFile: cur, MasterKeyNewFile: bad})
	if !errors.Is(err, crypto.ErrInvalidMasterKey) || !strings.Contains(err.Error(), config.EnvMasterKeyNewFile) {
		t.Errorf("Load(bad new file) = %v", err)
	}
	_, err = masterkey.Load(&config.Config{MasterKeyFile: cur, MasterKeyNewFile: same})
	if !errors.Is(err, masterkey.ErrSameKey) || strings.Contains(err.Error(), masterkeytest.Text("current")) {
		t.Errorf("Load(same key twice) = %v", err)
	}

	kr, err := masterkey.Load(&config.Config{MasterKeyFile: cur})
	if err != nil || kr.NewID() != "" {
		t.Fatalf("Load(current) = %v, %v", kr, err)
	}
	kr, err = masterkey.Load(&config.Config{MasterKeyFile: cur, MasterKeyNewFile: next})
	if err != nil {
		t.Fatalf("Load(current, new) = %v", err)
	}
	if kr.CurrentID() != curID || kr.NewID() != nextID {
		t.Errorf("Load IDs = %s, %s", kr.CurrentID(), kr.NewID())
	}

	// Close destroys the keys: sealing fails, the IDs remain.
	db := openDB(t, storetest.SQLite(t))
	tid := newTenant(t, db, "transfer.entity-a.example.com")
	kr.Close()
	if kr.CurrentID() != curID {
		t.Error("Close dropped the key ID")
	}
	if _, err := vault(db, kr).Seal(context.Background(), tid, crypto.PurposeDEK, []byte("x")); !errors.Is(err, crypto.ErrKeyUnavailable) {
		t.Errorf("Seal after Close = %v", err)
	}
}
