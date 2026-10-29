// Package vcode holds the primitives of the 6-digit verification codes sent
// by mail (CLAUDE.md section 7): their drawing without bias, their input
// check and the rules every purpose shares (validity, rate limit window and
// budgets). The deposit codes (internal/deposit) and the recipient codes
// (internal/download) both use it, so that the two never drift apart.
package vcode

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Rules of spec 7, shared by every purpose.
const (
	// TTL is the validity of a verification code.
	TTL = 15 * time.Minute
	// Digits is the number of digits of a verification code.
	Digits = 6
	// MaxPerAddress bounds the codes sent to one address per Window, within
	// one purpose (a recipient code counts per address and link).
	MaxPerAddress = 5
	// MaxPerIP bounds the codes requested from one client IP per Window,
	// all purposes combined.
	MaxPerIP = 20
	// Window is the sliding window of the code rate limits.
	Window = time.Hour
	// QueueFullRetryAfter is the Retry-After hint when the mail queue is
	// full.
	QueueFullRetryAfter = 30 * time.Second
)

// Code drawing bounds.
const (
	// Space is the number of distinct codes, 10^Digits.
	Space = 1_000_000
	// RejectAtOrAbove is the largest multiple of Space not above 2^32: a
	// 32-bit random value at or above it is drawn again.
	RejectAtOrAbove = (1 << 32) - (1<<32)%Space
)

// New draws a verification code from r uniformly among the 10^6 values: a
// 32-bit random value is rejected when it falls in the incomplete last
// block, so that the reduction modulo 10^6 has no bias. r is normally
// crypto/rand.Reader.
func New(r io.Reader) (string, error) {
	var b [4]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("read random: %w", err)
		}
		if v := binary.BigEndian.Uint32(b[:]); v < RejectAtOrAbove {
			return fmt.Sprintf("%0*d", Digits, v%Space), nil
		}
	}
}

// Valid reports whether code is exactly Digits ASCII digits.
func Valid(code string) bool {
	if len(code) != Digits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}
