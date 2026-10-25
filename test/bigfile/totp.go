package bigfile

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the RFC 6238 default used by TransTeira's TOTP
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTPPeriod is the TOTP time step (RFC 6238 default, as TransTeira).
const TOTPPeriod = 30 * time.Second

// TOTPStep returns the time step of t.
func TOTPStep(t time.Time) int64 { return t.Unix() / int64(TOTPPeriod/time.Second) }

// TOTPCode returns the 6-digit RFC 6238 code (HMAC-SHA1) of the base32
// secret at step, the algorithm of test/e2e/support/totp.ts. Padding,
// spaces and case of the secret are ignored.
func TOTPCode(secret string, step int64) (string, error) {
	clean := strings.ToUpper(strings.TrimRight(strings.Join(strings.Fields(secret), ""), "="))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("totp secret: %w", err)
	}
	if step < 0 {
		return "", fmt.Errorf("totp step %d is negative", step)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	h := mac.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}
