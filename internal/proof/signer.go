package proof

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
)

// reasonProofSigning is the reason of the system transactions of the
// signer.
const reasonProofSigning = "proof signing key management"

// CLIActor is the system actor of the key operations of the command line
// (transteira proof retire-key), as the other commands record theirs.
var CLIActor = Actor{Kind: store.ActorSystem, Name: "cli"}

// systemActor is the actor of the creation of a key on first use.
var systemActor = Actor{Kind: store.ActorSystem, Name: "proof"}

// createAttempts bounds the retries of [Signer.Prepare] when another
// process creates or retires the active key at the same time.
const createAttempts = 3

// Vault seals and opens the private signing keys, as system secrets of
// purpose crypto.PurposeProofSigning. *masterkey.Vault implements it.
type Vault interface {
	// WrapSystem seals plaintext for purpose p as a new system secret,
	// without storing it.
	WrapSystem(p crypto.Purpose, plaintext []byte) (store.SystemSecret, error)
	// OpenSystem unwraps the system secret secretID of purpose p.
	OpenSystem(ctx context.Context, p crypto.Purpose, secretID string) ([]byte, error)
}

// SystemAuditor records audit events inside a system transaction.
// *audit.Writer implements it.
type SystemAuditor interface {
	RecordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error
}

// Actor identifies who acts on a signing key, for the audit log.
type Actor struct {
	// Kind is the actor kind (store.ActorSystem, store.ActorAdmin).
	Kind store.AuditActorKind
	// Name is the system actor name or the administrator's username.
	Name string
	// IP is the client IP, the zero Addr for a local command.
	IP netip.Addr
}

// PublicKey is a public signing key of the instance (OpenAPI ProofKey).
type PublicKey struct {
	// KeyID is the key identifier ("psk_" + ULID).
	KeyID string
	// PublicKey is the raw Ed25519 public key.
	PublicKey ed25519.PublicKey
	// CreatedAt is the creation time.
	CreatedAt time.Time
	// RetiredAt is the retirement time, zero while the key is active.
	RetiredAt time.Time
}

// cachedKey is the opened private key of the active signing key.
type cachedKey struct {
	id   string
	priv ed25519.PrivateKey
}

// Signer manages the signing keys of the instance: it reads the active key
// in the system scope, creates it on first use, keeps its opened private
// key in memory and retires it. It is safe for concurrent use; one Signer
// serves the whole process.
type Signer struct {
	db     *store.DB
	vault  Vault
	audit  SystemAuditor
	clock  func() time.Time
	logger *slog.Logger
	rand   io.Reader
	// scrub purges the deleted secret from the database files (a test seam).
	scrub func(context.Context) error

	mu     sync.Mutex
	cached *cachedKey
}

// NewSigner returns a signer over db, sealing the private keys with vault
// and recording the key events with rec. A nil clock is time.Now and a nil
// logger discards.
func NewSigner(db *store.DB, vault Vault, rec SystemAuditor, clock func() time.Time, logger *slog.Logger) *Signer {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Signer{db: db, vault: vault, audit: rec, clock: clock, logger: logger, rand: rand.Reader, scrub: db.ScrubDeleted}
}

// Sealer signs the statements of one write with the key that was active
// when it was prepared. It holds its own copy of the private key and is
// meant to live for one transaction; it is safe for concurrent use.
type Sealer struct {
	db    *store.DB
	keyID string
	priv  ed25519.PrivateKey
	// listLinks replaces the read of the recipient links when set (a test seam).
	listLinks func(ctx context.Context, tx *store.ScopedTx, trfID string) ([]store.RecipientLink, error)
}

// KeyID returns the identifier of the key the sealer signs with.
func (s *Sealer) KeyID() string { return s.keyID }

// Prepare returns a sealer signing with the active key, creating the key
// when none is active (Ed25519, private seed sealed by the master key,
// audited as proof_key.created). It reads the active key at each call, so
// that a key retired by another process (the command line) is never used
// again; the opened private key is cached by key ID.
//
// It opens system transactions: the caller calls it before opening the
// tenant transaction the sealer writes in, never inside it.
func (s *Signer) Prepare(ctx context.Context) (*Sealer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for range createAttempts {
		k, err := s.db.ProofKeys().Active(ctx)
		if errors.Is(err, store.ErrNotFound) {
			k, err = s.create(ctx)
			if errors.Is(err, store.ErrConflict) {
				continue // created (or rotated) by another process: read it
			}
		}
		if err != nil {
			return nil, fmt.Errorf("proof: active signing key: %w", err)
		}
		priv, err := s.open(ctx, k)
		if errors.Is(err, store.ErrNotFound) {
			continue // retired since it was read: its secret is gone
		}
		if err != nil {
			return nil, err
		}
		return &Sealer{db: s.db, keyID: k.ID, priv: bytes.Clone(priv)}, nil
	}
	return nil, fmt.Errorf("proof: active signing key: %w", store.ErrConflict)
}

// create generates, seals and stores a new active key, audits it and
// caches it. It returns store.ErrConflict when another process created an
// active key first. The caller holds s.mu.
func (s *Signer) create(ctx context.Context) (store.ProofKey, error) {
	pub, priv, err := ed25519.GenerateKey(s.rand)
	if err != nil {
		return store.ProofKey{}, fmt.Errorf("proof: generate signing key: %w", err)
	}
	seed := priv.Seed()
	secret, err := s.vault.WrapSystem(crypto.PurposeProofSigning, seed)
	clear(seed)
	if err != nil {
		clear(priv)
		return store.ProofKey{}, fmt.Errorf("proof: seal signing key: %w", err)
	}
	k := store.ProofKey{ID: id.New(id.ProofKey), PublicKey: pub, CreatedAt: s.clock()}
	sys, err := s.db.System(reasonProofSigning)
	if err == nil {
		err = sys.Tx(ctx, func(tx *store.SystemTx) error {
			if err := s.db.ProofKeys().CreateTx(ctx, tx, k, secret); err != nil {
				return err
			}
			return s.audit.RecordTx(ctx, tx, keyEvent(systemActor, audit.ActionProofKeyCreated, k.ID))
		})
	}
	if err != nil {
		clear(priv)
		return store.ProofKey{}, err
	}
	s.logger.InfoContext(ctx, "proof signing key created", slog.String("key", k.ID))
	k.PrivateKeySecretID = secret.ID
	s.replace(&cachedKey{id: k.ID, priv: priv})
	return k, nil
}

// open returns the private key of the active key k, from the cache or
// unwrapped from its system secret (and then cached). The caller holds
// s.mu.
func (s *Signer) open(ctx context.Context, k store.ProofKey) (ed25519.PrivateKey, error) {
	if s.cached != nil && s.cached.id == k.ID {
		return s.cached.priv, nil
	}
	if k.PrivateKeySecretID == "" {
		return nil, store.ErrNotFound
	}
	seed, err := s.vault.OpenSystem(ctx, crypto.PurposeProofSigning, k.PrivateKeySecretID)
	if err != nil {
		return nil, fmt.Errorf("proof: open signing key: %w", err)
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, ErrKeyMismatch
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if pub, ok := priv.Public().(ed25519.PublicKey); !ok || !pub.Equal(ed25519.PublicKey(k.PublicKey)) {
		clear(priv)
		return nil, ErrKeyMismatch
	}
	s.replace(&cachedKey{id: k.ID, priv: priv})
	return priv, nil
}

// replace sets the cached key, zeroing the one it replaces (sealers hold
// their own copy). The caller holds s.mu.
func (s *Signer) replace(c *cachedKey) {
	if s.cached != nil {
		clear(s.cached.priv)
	}
	s.cached = c
}

// Retire retires the active key and destroys its private part, audited as
// proof_key.retired by actor, then purges the destroyed secret from the
// database files. Its public key stays published. The next [Signer.Prepare]
// creates a new key. It returns the retired key, or ErrNoActiveKey.
func (s *Signer) Retire(ctx context.Context, actor Actor) (store.ProofKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var k store.ProofKey
	sys, err := s.db.System(reasonProofSigning)
	if err == nil {
		err = sys.Tx(ctx, func(tx *store.SystemTx) error {
			var err error
			if k, err = s.db.ProofKeys().RetireActiveTx(ctx, tx, s.clock()); err != nil {
				return err
			}
			return s.audit.RecordTx(ctx, tx, keyEvent(actor, audit.ActionProofKeyRetired, k.ID))
		})
	}
	s.replace(nil)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.ProofKey{}, ErrNoActiveKey
	case err != nil:
		return store.ProofKey{}, fmt.Errorf("proof: retire signing key: %w", err)
	}
	// The secret row is deleted; scrubbing removes its bytes from the
	// database files. The retirement holds even if scrubbing fails.
	if err := s.scrub(ctx); err != nil {
		s.logger.WarnContext(ctx, "scrub after proof key retirement failed", slog.String("error", err.Error()))
	}
	s.logger.InfoContext(ctx, "proof signing key retired", slog.String("key", k.ID))
	return k, nil
}

// Keys returns every signing key, active and retired, most recent first:
// the public keys that verify the proofs (OpenAPI listProofKeys).
func (s *Signer) Keys(ctx context.Context) ([]PublicKey, error) {
	keys, err := s.db.ProofKeys().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("proof: list signing keys: %w", err)
	}
	out := make([]PublicKey, len(keys))
	for i, k := range keys {
		out[i] = PublicKey{
			KeyID: k.ID, PublicKey: ed25519.PublicKey(bytes.Clone(k.PublicKey)), CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt,
		}
	}
	return out, nil
}

// keyEvent returns the system audit event of action on key kid by actor.
func keyEvent(actor Actor, action audit.Action, kid string) audit.Event {
	return audit.Event{
		ActorKind: actor.Kind, Actor: actor.Name, IP: actor.IP,
		Action: action, ObjectKind: audit.ObjectProofKey, ObjectID: kid,
	}
}
