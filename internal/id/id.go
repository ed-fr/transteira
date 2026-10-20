// Package id generates and validates the identifiers used by TransTeira.
//
// Two families of identifiers exist, matching the patterns of the OpenAPI
// specification (api/openapi.yaml):
//
//   - Entity identifiers ("ten_", "trf_", "fil_", ...) are a short prefix, an
//     underscore and a 26-character ULID: a 48-bit millisecond timestamp
//     followed by 80 bits from a cryptographic random source, encoded in
//     uppercase Crockford base32. They are sortable by creation time and
//     unique, but they are not secrets: they always travel together with an
//     authenticated, tenant-scoped context.
//   - Public tokens ("dl_", "upl_", "inv_", "vch_", ...) are bearer secrets
//     that grant access by themselves (download links, invitation links,
//     upload sessions). They carry at least 128 bits of crypto/rand entropy,
//     encoded in base62, and contain no timestamp (see NewToken).
package id

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Prefix is the short type marker placed before the underscore of an entity
// identifier, for example "trf" in "trf_01JABC...".
type Prefix string

// Entity identifier prefixes, as declared by the OpenAPI specification.
const (
	// Tenant identifies an entity (tenant).
	Tenant Prefix = "ten"
	// Transfer identifies a transfer.
	Transfer Prefix = "trf"
	// File identifies a file inside a transfer.
	File Prefix = "fil"
	// Invitation identifies an invitation record in the administration API.
	// It is distinct from the public invitation token ("inv_" + base62).
	Invitation Prefix = "inv"
	// Blocklist identifies a blocklist entry.
	Blocklist Prefix = "blk"
	// APIToken identifies an API token record (not the secret itself).
	APIToken Prefix = "tok"
	// Admin identifies an administrator account.
	Admin Prefix = "adm"
	// Rotation identifies a master key rotation run.
	Rotation Prefix = "rot"
	// Audit identifies an audit log entry.
	Audit Prefix = "aud"
	// Request identifies an HTTP request (Problem Details "instance").
	Request Prefix = "req"
)

// ulidLen is the length of the encoded ULID part of an entity identifier.
const ulidLen = 26

// maxTimestamp is the largest millisecond timestamp a ULID can hold (48 bits).
const maxTimestamp = 1<<48 - 1

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// invalidChar marks a byte outside the Crockford alphabet in decodeTable.
const invalidChar = 0xFF

// decodeTable maps an ASCII byte to its Crockford value, or invalidChar when
// the byte is not part of the uppercase alphabet.
var decodeTable = func() [256]byte {
	var t [256]byte
	for i := range t {
		t[i] = invalidChar
	}
	for i := range len(crockford) {
		t[crockford[i]] = byte(i)
	}
	return t
}()

// Errors returned by this package.
var (
	// ErrInvalid reports a malformed identifier.
	ErrInvalid = errors.New("id: invalid identifier")
	// ErrTimestamp reports a clock value that a ULID cannot represent.
	ErrTimestamp = errors.New("id: timestamp out of ULID range")
	// ErrEntropy reports a token request with too little or too much entropy.
	ErrEntropy = errors.New("id: invalid token entropy")
	// ErrPrefix reports an empty or malformed prefix.
	ErrPrefix = errors.New("id: invalid prefix")
)

// cryptoReader is the default random source. It is a variable only so that
// tests can exercise the unrecoverable failure path of New.
var cryptoReader io.Reader = rand.Reader

// Generator creates entity identifiers from an injectable clock and random
// source. Use NewGenerator to build one. A Generator is safe for concurrent
// use if its clock and random reader are (the defaults are).
type Generator struct {
	clock func() time.Time
	rand  io.Reader
}

// NewGenerator returns a Generator using clock and rand. A nil clock defaults
// to time.Now and a nil rand defaults to crypto/rand.Reader.
func NewGenerator(clock func() time.Time, rand io.Reader) *Generator {
	if clock == nil {
		clock = time.Now
	}
	if rand == nil {
		rand = cryptoReader
	}
	return &Generator{clock: clock, rand: rand}
}

// New returns a new identifier "<p>_<ULID>". It fails if p is not a valid
// prefix, if the clock is before the Unix epoch or beyond the 48-bit
// millisecond range, or if the random source cannot supply 10 bytes.
func (g *Generator) New(p Prefix) (string, error) {
	if !validPrefix(string(p)) {
		return "", ErrPrefix
	}
	ms := g.clock().UnixMilli()
	if ms < 0 || ms > maxTimestamp {
		return "", ErrTimestamp
	}
	var entropy [10]byte
	if _, err := io.ReadFull(g.rand, entropy[:]); err != nil {
		return "", fmt.Errorf("id: read random: %w", err)
	}
	return string(p) + "_" + encode(uint64(ms), entropy), nil
}

// New returns a new identifier "<p>_<ULID>" using the current time and
// crypto/rand. It panics if crypto/rand fails, which is unrecoverable: the
// process cannot safely generate any secret. With the system clock and one of
// the Prefix constants, no other error can occur.
func New(p Prefix) string {
	s, err := NewGenerator(nil, nil).New(p)
	if err != nil {
		panic(err)
	}
	return s
}

// encode returns the 26-character Crockford base32 form of the 128-bit value
// made of the 48-bit timestamp ms followed by the 80-bit entropy.
func encode(ms uint64, entropy [10]byte) string {
	var out [ulidLen]byte
	// 48-bit timestamp in 10 characters (50 bits, top 2 bits zero).
	for i := range 10 {
		out[i] = crockford[(ms>>(45-5*uint(i)))&31]
	}
	// 80-bit entropy split as hi (top 16 bits) and lo (low 64 bits),
	// encoded in 16 characters of 5 bits each.
	hi := uint64(entropy[0])<<8 | uint64(entropy[1])
	var lo uint64
	for _, b := range entropy[2:] {
		lo = lo<<8 | uint64(b)
	}
	for j := range 16 {
		shift := uint(75 - 5*j)
		var v uint64
		switch {
		case shift >= 64:
			v = hi >> (shift - 64)
		case shift > 59: // the 5-bit group straddles hi and lo
			v = lo>>shift | hi<<(64-shift)
		default:
			v = lo >> shift
		}
		out[10+j] = crockford[v&31]
	}
	return string(out[:])
}

// Valid reports whether s is a well-formed identifier with prefix p: exactly
// "<p>_" followed by 26 uppercase Crockford base32 characters whose first
// character is at most '7' (the value must fit in 128 bits).
func Valid(p Prefix, s string) bool {
	_, err := Parse(p, s)
	return err == nil
}

// Parse validates s like Valid and returns the creation time embedded in the
// identifier, in UTC with millisecond precision.
func Parse(p Prefix, s string) (time.Time, error) {
	if !validPrefix(string(p)) {
		return time.Time{}, ErrPrefix
	}
	head := string(p) + "_"
	if len(s) != len(head)+ulidLen || !strings.HasPrefix(s, head) {
		return time.Time{}, ErrInvalid
	}
	u := s[len(head):]
	if u[0] > '7' {
		return time.Time{}, ErrInvalid
	}
	var ms uint64
	for i := range ulidLen {
		v := decodeTable[u[i]]
		if v == invalidChar {
			return time.Time{}, ErrInvalid
		}
		if i < 10 {
			ms = ms<<5 | uint64(v)
		}
	}
	return time.UnixMilli(int64(ms)).UTC(), nil
}

// validPrefix reports whether p is a non-empty string of at most 16 lowercase
// ASCII letters, the shape of every prefix used by TransTeira.
func validPrefix(p string) bool {
	if p == "" || len(p) > 16 {
		return false
	}
	for i := range len(p) {
		if p[i] < 'a' || p[i] > 'z' {
			return false
		}
	}
	return true
}
