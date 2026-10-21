package download

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Download grant cookie (OpenAPI security scheme downloadGrant): the
// browser proof that a transfer password was entered. See the package
// documentation.
const (
	// GrantCookieName is the name of the cookie. The __Host- prefix
	// requires Secure, Path=/ and no Domain attribute; the HTTP layer also
	// sets HttpOnly and SameSite=Strict.
	GrantCookieName = "__Host-tt_dl"
	// GrantTTL is the lifetime of a grant entry, and the Max-Age of the
	// cookie (3600 seconds).
	GrantTTL = time.Hour
	// GrantMaxEntries bounds the transfers one browser keeps unlocked.
	GrantMaxEntries = 10
	// MaxGrantCookieLen bounds the raw cookie value the service parses; a
	// longer value is ignored altogether. Ten entries take 552 bytes, so a
	// value the service produces always fits.
	MaxGrantCookieLen = 1024
	// GrantCookiePrefix starts the cookie value.
	GrantCookiePrefix = "dg_"
	// grantSep separates the entries of the cookie value.
	grantSep = "."
	// grantExpiryLen is the size of the expiry that starts an entry: Unix
	// seconds, big-endian.
	grantExpiryLen = 8
	// grantRawLen is the size of a decoded entry: the expiry then the MAC.
	grantRawLen = grantExpiryLen + crypto.MACSize
	// grantEntryLen is the length of one encoded entry (unpadded base64url
	// of grantRawLen bytes).
	grantEntryLen = 54
)

// grantEncoding encodes the entries; its alphabet never contains grantSep.
// It is strict, so that one entry has a single encoding.
var grantEncoding = base64.RawURLEncoding.Strict()

// parseGrants decodes the raw value of the grant cookie into at most
// GrantMaxEntries distinct entries of grantRawLen bytes. It is defensive:
// a value longer than MaxGrantCookieLen or without GrantCookiePrefix is
// ignored, and so is every entry that is not exactly one entry in unpadded
// base64url. It never fails. The entries are neither dated nor verified
// here.
func parseGrants(raw string) [][]byte {
	body, ok := strings.CutPrefix(raw, GrantCookiePrefix)
	if !ok || len(raw) > MaxGrantCookieLen {
		return nil
	}
	var entries [][]byte
	for part := range strings.SplitSeq(body, grantSep) {
		if len(entries) == GrantMaxEntries {
			break
		}
		if len(part) != grantEntryLen {
			continue
		}
		e, err := grantEncoding.DecodeString(part)
		if err != nil || len(e) != grantRawLen || slices.ContainsFunc(entries, func(o []byte) bool { return bytes.Equal(o, e) }) {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// live reports whether the entry e is still valid at now: its expiry is
// after now, and not further than GrantTTL ahead (an entry is never issued
// for longer).
func live(e []byte, now time.Time) bool {
	v := binary.BigEndian.Uint64(e[:grantExpiryLen])
	if v > math.MaxInt64 {
		return false
	}
	exp := time.Unix(int64(v), 0)
	return exp.After(now) && !exp.After(now.Add(GrantTTL))
}

// grantParts returns the MAC input of an entry for the transfer trfID of
// tenant tid expiring at expiry (8 bytes): the cookie holds no clear data,
// and an entry is worthless for another tenant, another transfer or
// another expiry.
func grantParts(tid tenant.ID, trfID string, expiry []byte) [][]byte {
	return [][]byte{[]byte(tid), []byte(trfID), expiry}
}

// ownGrant reports whether e is a live entry of the transfer trfID of
// tenant tid. The MAC comparison runs in constant time (Keys.VerifyMAC).
func (s *Service) ownGrant(e []byte, now time.Time, tid tenant.ID, trfID string) (bool, error) {
	if !live(e, now) {
		return false, nil
	}
	ok, err := s.keys.VerifyMAC(crypto.MACPurposeDownloadGrant, e[grantExpiryLen:],
		grantParts(tid, trfID, e[:grantExpiryLen])...)
	if err != nil {
		return false, fmt.Errorf("download: verify grant cookie: %w", err)
	}
	return ok, nil
}

// granted reports whether the grant cookie raw holds a live entry of the
// transfer trfID of tenant tid.
func (s *Service) granted(raw string, tid tenant.ID, trfID string, now time.Time) (bool, error) {
	for _, e := range parseGrants(raw) {
		if ok, err := s.ownGrant(e, now, tid, trfID); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// grant returns the new value of the grant cookie raw: a new entry of the
// transfer trfID of tenant tid expiring GrantTTL after now, then the other
// live entries in their order, without the earlier entries of this
// transfer, capped at GrantMaxEntries.
func (s *Service) grant(raw string, tid tenant.ID, trfID string, now time.Time) (string, error) {
	expiry := binary.BigEndian.AppendUint64(nil, uint64(now.Add(GrantTTL).Unix())) //nolint:gosec // G115: a time after 1970 is positive
	mac, err := s.keys.MAC(crypto.MACPurposeDownloadGrant, grantParts(tid, trfID, expiry)...)
	if err != nil {
		return "", fmt.Errorf("download: compute grant cookie: %w", err)
	}
	out := []string{grantEncoding.EncodeToString(append(expiry, mac...))}
	for _, e := range parseGrants(raw) {
		if len(out) == GrantMaxEntries {
			break
		}
		if !live(e, now) {
			continue
		}
		own, err := s.ownGrant(e, now, tid, trfID)
		if err != nil {
			return "", err
		}
		if !own {
			out = append(out, grantEncoding.EncodeToString(e))
		}
	}
	return GrantCookiePrefix + strings.Join(out, grantSep), nil
}
