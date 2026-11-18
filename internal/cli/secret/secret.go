package secret

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tte2"
)

// API paths (api/openapi.yaml).
const (
	// createPath is createExpressSecret.
	createPath = "/api/v1/express-secrets"
	// linkPath, followed by the token, is getSecretLink; with "/reveal"
	// appended, revealSecret.
	linkPath = "/api/v1/secret-links/"
)

// statusAttempts bounds the attempts of the status call, which consumes
// nothing: connection errors and 5xx answers are tried again, a 429 never
// (its delay is reported).
const statusAttempts = 3

// Request policies. No API token is sent to the secret links, and the
// creation and the reveal are sent once: a creation is never retried with
// the same key (e2e-format.md 3.3.1) and a reveal is one-time.
var (
	statusPolicy = client.Policy{Anonymous: true, MaxAttempts: 1}
	revealPolicy = client.Policy{Anonymous: true, MaxAttempts: 1}
)

// sealSecret is tte2.SealSecret, replaced by the tests.
var sealSecret = tte2.SealSecret

// CreateOptions describes an express secret to create.
type CreateOptions struct {
	// Text is the text of the secret; it must pass [CheckText]. It is
	// sealed on this machine and never sent nor logged.
	Text string
	// Duration is "1h", "1d" or "7d"; empty means DefaultDuration.
	Duration string
	// Anonymous never sends the API token of the client, even when one is
	// configured. Without a token the creation is anonymous anyway.
	Anonymous bool
}

// Created is a new express secret.
type Created struct {
	// ID is the identifier of the secret ("sec_..."), which the admins of
	// the entity see; it gives no access to the text.
	ID string
	// Link is https://<host>/s/<token>#k=<key>, the secret itself: print
	// it to a private place only, never log it.
	Link string
	// ExpiresAt is when the secret is destroyed if nobody reads it.
	ExpiresAt time.Time
	// Anonymous reports that no API token was sent.
	Anonymous bool
}

// Revealed is a secret read once.
type Revealed struct {
	// Text is the plaintext: never log it.
	Text string
	// Express reports an express secret, written by a third party the
	// entity did not verify (threat T-397).
	Express bool
	// Anonymous reports an express secret created without credential (as
	// opposed to one created with an API token of the entity).
	Anonymous bool
	// FileLost reports that the reveal returned a file although the status
	// announced none: this client cannot download it, and it is lost.
	FileLost bool
}

// expressCreate is the ExpressSecretCreate body: exactly these members.
type expressCreate struct {
	EncryptedText string `json:"encryptedText"`
	Verifier      string `json:"verifier"`
	KeyVerifier   string `json:"keyVerifier"`
	ExpiresIn     string `json:"expiresIn"`
}

// secretCreated is the SecretCreated answer.
type secretCreated struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	State     string     `json:"state"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

// secretStatus is the SecretStatus answer. The passphrase and the file are
// kept raw: their mere presence makes the secret unsupported.
type secretStatus struct {
	State      string          `json:"state"`
	Passphrase json.RawMessage `json:"passphrase"`
	File       json.RawMessage `json:"file"`
	Express    bool            `json:"express"`
	Anonymous  bool            `json:"anonymous"`
}

// revealBody is the SecretReveal body.
type revealBody struct {
	KeyProof string `json:"keyProof"`
	Proof    string `json:"proof"`
}

// secretRevealed is the SecretRevealed answer.
type secretRevealed struct {
	EncryptedText     string `json:"encryptedText"`
	EncryptedMetadata string `json:"encryptedMetadata"`
	FileGrant         string `json:"fileGrant"`
}

// material is what a secret key K gives, without passphrase: the root key
// K', the key proof and the proof (e2e-format.md 3.3.2 and 3.3.4).
type material struct {
	root, keyProof, proof []byte
}

// derive returns the material of K, which must be tte2.KeySize bytes (it
// comes from crypto/rand or tte2.DecodeKey).
func derive(key []byte) material {
	// Cannot fail: a 32-byte key and no passphrase.
	root, _ := tte2.DeriveSecretKey(key, "", tte2.PassphraseDescriptor{})
	// Cannot fail: 32-byte keys.
	keyProof, _ := tte2.SecretKeyProof(key)
	proof, _ := tte2.SecretProof(root)
	return material{root: root, keyProof: keyProof, proof: proof}
}

// clear wipes the material.
func (m material) clear() {
	clear(m.root)
	clear(m.keyProof)
	clear(m.proof)
}

// Create seals o.Text with a new key and creates an express secret on the
// server of c (createExpressSecret), then composes its link on the base URL
// of c. The text and the key never leave this function, except the key in
// the returned link. The request is sent once, with the API token of c
// unless o.Anonymous is set or c has none. Errors wrap the sentinels of
// this package, [ErrInvalidText] for a text that fails [CheckText].
func Create(ctx context.Context, c *client.Client, o CreateOptions) (*Created, error) {
	duration := cmp.Or(o.Duration, DefaultDuration)
	if !ValidDuration(duration) {
		return nil, fmt.Errorf("invalid duration %q: use %s", duration, DurationList)
	}
	if err := CheckText(o.Text); err != nil {
		return nil, err
	}
	key := make([]byte, tte2.KeySize)
	_, _ = rand.Read(key) // never fails since Go 1.24
	defer clear(key)
	m := derive(key)
	defer m.clear()
	sealed, err := sealSecret(m.root, o.Text)
	if err != nil {
		return nil, fmt.Errorf("sealing the text: %w", err)
	}
	// Open the sealed text again before a verifier certifies it
	// (e2e-format.md 3.3.4).
	if opened, err := tte2.OpenSecret(m.root, sealed); err != nil || opened != o.Text {
		return nil, errors.New("the sealed text does not open again: nothing was sent")
	}
	body := expressCreate{
		EncryptedText: sealed,
		Verifier:      tte2.EncodeProof(tte2.SecretVerifier(m.proof)),
		KeyVerifier:   tte2.EncodeProof(tte2.SecretVerifier(m.keyProof)),
		ExpiresIn:     duration,
	}
	anonymous := o.Anonymous || c.Config().Token == ""
	var out secretCreated
	policy := client.Policy{Anonymous: anonymous, MaxAttempts: 1}
	if _, err := c.JSON(ctx, http.MethodPost, createPath, body, &out, nil, policy); err != nil {
		return nil, createError(err, !anonymous)
	}
	if !id.Valid(id.Secret, out.ID) || !id.SecretTokenValid(out.Token) || out.State != "active" || out.ExpiresAt == nil {
		return nil, fmt.Errorf("%w: not an active express secret", ErrInvalidAnswer)
	}
	encoded, _ := tte2.EncodeKey(key) // cannot fail: a 32-byte key
	return &Created{
		ID:        out.ID,
		Link:      c.BaseURL() + id.SecretPath + out.Token + id.SecretKeyFragment + encoded,
		ExpiresAt: *out.ExpiresAt,
		Anonymous: anonymous,
	}, nil
}

// Read reads the secret of l once from the server of c, which must be the
// origin of the link: the status first (consumes nothing; a passphrase or a
// file is refused there with [ErrUnsupported]), then the reveal with the
// two proofs, sent once, then the decryption of the text with the key of
// the link. No API token is sent. Errors wrap the sentinels of this
// package; after a successful reveal only [ErrIntegrity] can occur, and
// the secret is then consumed.
func Read(ctx context.Context, c *client.Client, l Link) (*Revealed, error) {
	key, err := tte2.DecodeKey(l.Key)
	if err != nil || !id.SecretTokenValid(l.Token) {
		return nil, ErrInvalidLink
	}
	defer clear(key)
	if l.Origin != c.BaseURL() {
		return nil, fmt.Errorf("the link is for %s, not for the server %s", client.Redact(l.Origin), c.BaseURL())
	}
	m := derive(key)
	defer m.clear()
	base := linkPath + l.Token
	st, err := status(ctx, c, base)
	if err != nil {
		return nil, err
	}
	switch {
	case present(st.Passphrase):
		return nil, fmt.Errorf("%w: this secret is protected by a passphrase: open the link in a browser (nothing was consumed)", ErrUnsupported)
	case present(st.File):
		return nil, fmt.Errorf("%w: this secret carries a file: open the link in a browser (nothing was consumed)", ErrUnsupported)
	case st.State != "active":
		return nil, fmt.Errorf("%w: unknown state of the secret (nothing was consumed)", ErrInvalidAnswer)
	}
	var rv secretRevealed
	body := revealBody{KeyProof: tte2.EncodeProof(m.keyProof), Proof: tte2.EncodeProof(m.proof)}
	if _, err := c.JSON(ctx, http.MethodPost, base+"/reveal", body, &rv, nil, revealPolicy); err != nil {
		return nil, linkError(err)
	}
	text, err := tte2.OpenSecret(m.root, rv.EncryptedText)
	if err != nil {
		return nil, fmt.Errorf("%w (%w); the secret is consumed: ask its sender for a new one", ErrIntegrity, err)
	}
	return &Revealed{
		Text: text, Express: st.Express, Anonymous: st.Express && st.Anonymous,
		FileLost: rv.EncryptedMetadata != "" || rv.FileGrant != "",
	}, nil
}

// status asks the status of the secret at base (getSecretLink).
func status(ctx context.Context, c *client.Client, base string) (*secretStatus, error) {
	for attempt := 1; ; attempt++ {
		var st secretStatus
		_, err := c.JSON(ctx, http.MethodGet, base, nil, &st, nil, statusPolicy)
		if err == nil {
			return &st, nil
		}
		if p := problemOf(err); attempt >= statusAttempts || !client.IsRetryable(err) ||
			(p != nil && p.Status == http.StatusTooManyRequests) {
			return nil, linkError(err)
		}
		if err := c.Pause(ctx, attempt, err, statusPolicy); err != nil {
			return nil, err
		}
	}
}

// present reports whether a raw JSON member is present and not null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}
