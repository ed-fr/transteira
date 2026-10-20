package crypto

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing parameters (threat model decision P3). They apply to the
// transfer passwords and, later, to the admin passwords.
//
// One hash or verification with these parameters allocates Argon2Memory KiB
// (64 MiB) for about the duration of the computation. Callers exposed to
// unauthenticated requests must therefore rate limit before hashing and bound
// the number of concurrent computations (threat T-125), for example with a
// PasswordHasher: N concurrent computations need N x 64 MiB.
const (
	// Argon2Memory is the argon2id memory cost, in KiB (64 MiB).
	Argon2Memory uint32 = 64 * 1024
	// Argon2Time is the argon2id number of passes.
	Argon2Time uint32 = 3
	// Argon2Threads is the argon2id degree of parallelism.
	Argon2Threads uint8 = 1
	// Argon2SaltSize is the size in bytes of the random salt of a new hash.
	Argon2SaltSize = 16
	// Argon2KeySize is the size in bytes of the hash of a new password.
	Argon2KeySize = 32

	// MaxPasswordSize is the largest password, in bytes, that HashPassword
	// and VerifyPassword accept (the API allows 1,024 characters, at most
	// 4 bytes each in UTF-8). It bounds the cost of hashing a crafted input.
	MaxPasswordSize = 4096

	// Bounds accepted by VerifyPassword, so that a crafted stored hash cannot
	// make a verification arbitrarily expensive.

	// MaxArgon2Memory is the largest memory cost accepted, in KiB (256 MiB).
	MaxArgon2Memory uint32 = 256 * 1024
	// MaxArgon2Time is the largest number of passes accepted.
	MaxArgon2Time uint32 = 10
	// MaxArgon2Threads is the largest degree of parallelism accepted.
	MaxArgon2Threads uint8 = 4
	// MinArgon2SaltSize is the smallest decoded salt accepted, in bytes.
	MinArgon2SaltSize = 8
	// MaxArgon2SaltSize is the largest decoded salt accepted, in bytes.
	MaxArgon2SaltSize = 64
	// MinArgon2KeySize is the smallest decoded hash accepted, in bytes.
	MinArgon2KeySize = 16
	// MaxArgon2KeySize is the largest decoded hash accepted, in bytes.
	MaxArgon2KeySize = 64

	// argon2Version is the only argon2 version accepted (0x13).
	argon2Version = argon2.Version
	// maxEncodedHashLen bounds the length of an encoded hash, checked before
	// any parsing. The longest valid encoding is about 190 bytes.
	maxEncodedHashLen = 256
	// argon2Prefix is the algorithm segment of the PHC string.
	argon2Prefix = "argon2id"
)

var (
	// ErrMalformedHash is returned by VerifyPassword when the encoded hash is
	// not a strictly well-formed argon2id v=19 PHC string, or when its
	// parameters are outside the accepted bounds.
	ErrMalformedHash = errors.New("crypto: malformed password hash")
	// ErrPasswordTooLong is returned when a password exceeds MaxPasswordSize.
	ErrPasswordTooLong = errors.New("crypto: password too long")
)

// argon2Params holds the parameters of one argon2id hash.
type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
	saltLen int
	keyLen  int
}

// hashParams are the parameters of new hashes and the reference of
// NeedsRehash. Tests lower them to stay fast; production never changes them.
var hashParams = argon2Params{
	memory:  Argon2Memory,
	time:    Argon2Time,
	threads: Argon2Threads,
	saltLen: Argon2SaltSize,
	keyLen:  Argon2KeySize,
}

// idKey computes argon2id. Tests replace it to check the parameters that
// reach it without paying the memory cost.
var idKey = argon2.IDKey // gitleaks:allow

// b64 is the PHC base64 variant: standard alphabet, no padding, strict.
var b64 = base64.RawStdEncoding.Strict()

// HashPassword hashes password with argon2id and the current parameters and
// returns a PHC string:
//
//	$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
//
// where salt (16 random bytes) and hash (32 bytes) are base64 encoded with
// the standard alphabet and no padding. It allocates Argon2Memory KiB: see
// the package constants about bounding concurrency.
func HashPassword(password []byte) (string, error) {
	if len(password) > MaxPasswordSize {
		return "", ErrPasswordTooLong
	}
	p := hashParams
	salt := make([]byte, p.saltLen)
	if err := randomBytes(salt); err != nil {
		return "", err
	}
	key := idKey(password, salt, p.time, p.memory, p.threads, uint32(p.keyLen)) //nolint:gosec // keyLen is a small constant
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2Prefix, argon2Version, p.memory, p.time, p.threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded argon2id hash.
// The comparison is constant time. It returns ErrMalformedHash, and false,
// when encoded is not a well-formed argon2id v=19 PHC string or when its
// parameters exceed the accepted bounds (memory MaxArgon2Memory, passes
// MaxArgon2Time, parallelism MaxArgon2Threads, salt and hash sizes), so that
// a crafted hash can never cost more than these bounds. A password longer than
// MaxPasswordSize does not match and returns ErrPasswordTooLong without being
// hashed.
func VerifyPassword(encoded string, password []byte) (bool, error) {
	p, salt, want, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	if len(password) > MaxPasswordSize {
		return false, ErrPasswordTooLong
	}
	got := idKey(password, salt, p.time, p.memory, p.threads, uint32(len(want))) //nolint:gosec // len(want) <= MaxArgon2KeySize
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether encoded was not produced with the current
// parameters (memory, passes, parallelism, salt and hash sizes), including
// when it is malformed. The caller should then hash the password again after
// a successful verification.
func NeedsRehash(encoded string) bool {
	p, _, _, err := parseHash(encoded)
	return err != nil || p != hashParams
}

// parseHash strictly parses an argon2id v=19 PHC string and checks its bounds.
func parseHash(encoded string) (argon2Params, []byte, []byte, error) {
	var p argon2Params
	if len(encoded) > maxEncodedHashLen {
		return p, nil, nil, ErrMalformedHash
	}
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != argon2Prefix ||
		parts[2] != fmt.Sprintf("v=%d", argon2Version) {
		return p, nil, nil, ErrMalformedHash
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return p, nil, nil, ErrMalformedHash
	}
	m, okM := parseParam(params[0], "m=", uint64(MaxArgon2Memory))
	t, okT := parseParam(params[1], "t=", uint64(MaxArgon2Time))
	th, okP := parseParam(params[2], "p=", uint64(MaxArgon2Threads))
	// RFC 9106: at least one pass, one lane and 8 KiB per lane.
	if !okM || !okT || !okP || t < 1 || th < 1 || m < 8*th {
		return p, nil, nil, ErrMalformedHash
	}
	salt, okS := decodeBounded(parts[4], MinArgon2SaltSize, MaxArgon2SaltSize)
	key, okK := decodeBounded(parts[5], MinArgon2KeySize, MaxArgon2KeySize)
	if !okS || !okK {
		return p, nil, nil, ErrMalformedHash
	}
	// The conversions cannot overflow: parseParam enforced the bounds.
	p = argon2Params{
		memory:  uint32(m), //nolint:gosec // m <= MaxArgon2Memory
		time:    uint32(t), //nolint:gosec // t <= MaxArgon2Time
		threads: uint8(th), //nolint:gosec // th <= MaxArgon2Threads
		saltLen: len(salt),
		keyLen:  len(key),
	}
	return p, salt, key, nil
}

// parseParam parses "<name><decimal>" where decimal has no sign and no leading
// zero, and is at most limit.
func parseParam(s, name string, limit uint64) (uint64, bool) {
	digits, ok := strings.CutPrefix(s, name)
	if !ok || digits == "" || len(digits) > 10 || (digits[0] == '0' && len(digits) > 1) {
		return 0, false
	}
	var v uint64
	for i := range len(digits) {
		c := digits[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, v <= limit
}

// decodeBounded decodes strict unpadded base64 whose decoded size is within
// [minLen, maxLen], checking the size before allocating.
func decodeBounded(s string, minLen, maxLen int) ([]byte, bool) {
	n := b64.DecodedLen(len(s))
	if n < minLen || n > maxLen {
		return nil, false
	}
	// The decoder silently skips CR and LF, even in strict mode: only the
	// alphabet itself is accepted.
	for i := range len(s) {
		if !isB64Char(s[i]) {
			return nil, false
		}
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// isB64Char reports whether c belongs to the standard base64 alphabet.
func isB64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// PasswordHasher bounds the number of concurrent argon2id computations, and
// therefore the memory they use (threat T-125): at most maxConcurrent x
// 64 MiB with the current parameters, and maxConcurrent x MaxArgon2Memory
// for verifications of stored hashes with other parameters. It is safe for
// concurrent use.
type PasswordHasher struct {
	slots chan struct{}
}

// NewPasswordHasher returns a PasswordHasher running at most maxConcurrent
// computations at once; a value below 1 is treated as 1.
func NewPasswordHasher(maxConcurrent int) *PasswordHasher {
	return &PasswordHasher{slots: make(chan struct{}, max(maxConcurrent, 1))}
}

// acquire waits for a free slot or for ctx to be done.
func (h *PasswordHasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("crypto: wait for a password hashing slot: %w", ctx.Err())
	}
}

// release frees a slot.
func (h *PasswordHasher) release() { <-h.slots }

// HashPassword is HashPassword, run once a slot is free. It returns the
// context error if ctx is done first.
func (h *PasswordHasher) HashPassword(ctx context.Context, password []byte) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return HashPassword(password)
}

// VerifyPassword is VerifyPassword, run once a slot is free. A malformed
// hash is rejected without waiting. It returns the context error if ctx is
// done first.
func (h *PasswordHasher) VerifyPassword(ctx context.Context, encoded string, password []byte) (bool, error) {
	if _, _, _, err := parseHash(encoded); err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	return VerifyPassword(encoded, password)
}

// NeedsRehash is NeedsRehash; it does not hash and never waits.
func (*PasswordHasher) NeedsRehash(encoded string) bool {
	return NeedsRehash(encoded)
}
