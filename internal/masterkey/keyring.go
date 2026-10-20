package masterkey

import (
	"errors"
	"fmt"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
)

// DocLink is the operator documentation every refusal points to.
const DocLink = "docs/operations/master-key.md"

var (
	// ErrNoCurrentKey is returned when no current master key is provided.
	ErrNoCurrentKey = errors.New("masterkey: the current master key is required")
	// ErrSameKey is returned when the new master key is the current one.
	ErrSameKey = errors.New("masterkey: the new master key must differ from the current one")
)

// Keyring holds the master keys of the running process: the current key and,
// during a rotation, the new key. It is safe for concurrent use, except
// Close, which must be called once no other method can run.
type Keyring struct {
	current *crypto.MasterKey
	next    *crypto.MasterKey
}

// New returns a keyring made of current and, when not nil, next. The keyring
// takes ownership of the keys: Close destroys them. On error the keys are
// left untouched and still belong to the caller.
func New(current, next *crypto.MasterKey) (*Keyring, error) {
	if current.ID() == "" {
		return nil, ErrNoCurrentKey
	}
	if next != nil && next.ID() == current.ID() {
		return nil, fmt.Errorf("%w (both are %s)", ErrSameKey, current.ID())
	}
	return &Keyring{current: current, next: next}, nil
}

// Load reads the master key files named by cfg.MasterKeyFile and, when set,
// cfg.MasterKeyNewFile, and returns the keyring. Errors name the variable
// and the file, never the key content.
func Load(cfg *config.Config) (*Keyring, error) {
	if cfg.MasterKeyFile == "" {
		return nil, fmt.Errorf("%w: %s is not set", ErrNoCurrentKey, config.EnvMasterKeyFile)
	}
	current, err := crypto.LoadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return nil, fmt.Errorf("masterkey: %s: %w", config.EnvMasterKeyFile, err)
	}
	var next *crypto.MasterKey
	if cfg.MasterKeyNewFile != "" {
		if next, err = crypto.LoadMasterKey(cfg.MasterKeyNewFile); err != nil {
			current.Destroy()
			return nil, fmt.Errorf("masterkey: %s: %w", config.EnvMasterKeyNewFile, err)
		}
	}
	kr, err := New(current, next)
	if err != nil {
		current.Destroy()
		next.Destroy()
		return nil, err
	}
	return kr, nil
}

// CurrentID returns the ID of the current master key (TT_MASTER_KEY_FILE).
func (k *Keyring) CurrentID() string { return k.current.ID() }

// NewID returns the ID of the new master key (TT_MASTER_KEY_NEW_FILE), or ""
// when no new key is configured.
func (k *Keyring) NewID() string { return k.next.ID() }

// WrapID returns the ID of the master key new wrapped keys are wrapped with:
// the new key when present, the current key otherwise.
func (k *Keyring) WrapID() string { return k.wrapKey().ID() }

// wrapKey returns the master key new wrapped keys are wrapped with.
func (k *Keyring) wrapKey() *crypto.MasterKey {
	if k.next != nil {
		return k.next
	}
	return k.current
}

// key returns the master key with the given ID, if the keyring holds it.
func (k *Keyring) key(keyID string) (*crypto.MasterKey, bool) {
	switch {
	case keyID == k.current.ID(): // never "": New refuses a key without ID
		return k.current, true
	case k.next != nil && keyID == k.next.ID():
		return k.next, true
	}
	return nil, false
}

// has reports whether the keyring holds the master key with the given ID.
func (k *Keyring) has(keyID string) bool {
	_, ok := k.key(keyID)
	return ok
}

// describe names the configured keys for error messages.
func (k *Keyring) describe() string {
	s := config.EnvMasterKeyFile + " is " + k.CurrentID()
	if k.next != nil {
		s += " and " + config.EnvMasterKeyNewFile + " is " + k.NewID()
	} else {
		s += " and " + config.EnvMasterKeyNewFile + " is not set"
	}
	return s
}

// Close destroys the keys of the keyring. The keyring must not be used
// afterwards; the IDs remain available.
func (k *Keyring) Close() {
	k.current.Destroy()
	k.next.Destroy()
}
