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
// documentation. The recipient verification cookie (verify.go) has the same
// layout, under its own name, prefix and MAC purpose.
const (
	// GrantCookieName is the name of the cookie. The __Host- prefix
	// requires Secure, Path=/ and no Domain attribute; the HTTP layer also
	// sets HttpOnly and SameSite=Strict.
	GrantCookieName = "__Host-tt_dl"
	// GrantTTL is the lifetime of a grant entry, and the Max-Age of the
	// cookie (3600 seconds).
	GrantTTL = time.Hour
	// GrantMaxEntries bounds the transfers (or recipient links) one browser
	// keeps unlocked.
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

// entryCookie describes a stateless cookie of MAC-signed entries: the
// download grant cookie and the recipient verification cookie. Each entry
// is an expiry (Unix seconds, big-endian) then the MAC, under purpose, of
// the tenant ID, a subject ID (a transfer or a recipient link) and that
// expiry; the cookie holds no clear data. Both cookies share GrantTTL,
// GrantMaxEntries and MaxGrantCookieLen.
type entryCookie struct {
	// prefix starts the cookie value.
	prefix string
	// purpose keys the MACs of the entries.
	purpose crypto.MACPurpose
	// what names the cookie in the errors.
	what string
}

// grantSpec is the download grant cookie (GrantCookieName).
var grantSpec = entryCookie{prefix: GrantCookiePrefix, purpose: crypto.MACPurposeDownloadGrant, what: "grant cookie"}

// parse decodes the raw value of the cookie into at most GrantMaxEntries
// distinct entries of grantRawLen bytes. It is defensive: a value longer
// than MaxGrantCookieLen or without the prefix is ignored, and so is every
// entry that is not exactly one entry in unpadded base64url. It never
// fails. The entries are neither dated nor verified here.
func (c entryCookie) parse(raw string) [][]byte {
	body, ok := strings.CutPrefix(raw, c.prefix)
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

// parseGrants decodes the raw value of the grant cookie (see
// [entryCookie.parse]).
func parseGrants(raw string) [][]byte { return grantSpec.parse(raw) }

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

// grantParts returns the MAC input of an entry for the subject (a transfer
// or a recipient link ID) of tenant tid expiring at expiry (8 bytes): an
// entry is worthless for another tenant, another subject or another
// expiry.
func grantParts(tid tenant.ID, subject string, expiry []byte) [][]byte {
	return [][]byte{[]byte(tid), []byte(subject), expiry}
}

// own reports whether e is a live entry of the cookie c for the subject of
// tenant tid. The MAC comparison runs in constant time (Keys.VerifyMAC).
func (s *Service) own(c entryCookie, e []byte, now time.Time, tid tenant.ID, subject string) (bool, error) {
	if !live(e, now) {
		return false, nil
	}
	ok, err := s.keys.VerifyMAC(c.purpose, e[grantExpiryLen:], grantParts(tid, subject, e[:grantExpiryLen])...)
	if err != nil {
		return false, fmt.Errorf("download: verify %s: %w", c.what, err)
	}
	return ok, nil
}

// holds reports whether the raw value of the cookie c holds a live entry of
// the subject of tenant tid.
func (s *Service) holds(c entryCookie, raw string, tid tenant.ID, subject string, now time.Time) (bool, error) {
	for _, e := range c.parse(raw) {
		if ok, err := s.own(c, e, now, tid, subject); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// add returns the new value of the cookie c whose raw value is raw: a new
// entry of the subject of tenant tid expiring GrantTTL after now, then the
// other live entries in their order, without the earlier entries of this
// subject, capped at GrantMaxEntries.
func (s *Service) add(c entryCookie, raw string, tid tenant.ID, subject string, now time.Time) (string, error) {
	expiry := binary.BigEndian.AppendUint64(nil, uint64(now.Add(GrantTTL).Unix())) //nolint:gosec // G115: a time after 1970 is positive
	mac, err := s.keys.MAC(c.purpose, grantParts(tid, subject, expiry)...)
	if err != nil {
		return "", fmt.Errorf("download: compute %s: %w", c.what, err)
	}
	out := []string{grantEncoding.EncodeToString(append(expiry, mac...))}
	for _, e := range c.parse(raw) {
		if len(out) == GrantMaxEntries {
			break
		}
		if !live(e, now) {
			continue
		}
		own, err := s.own(c, e, now, tid, subject)
		if err != nil {
			return "", err
		}
		if !own {
			out = append(out, grantEncoding.EncodeToString(e))
		}
	}
	return c.prefix + strings.Join(out, grantSep), nil
}

// granted reports whether the grant cookie raw holds a live entry of the
// subject (a transfer, or a recipient link) of tenant tid.
func (s *Service) granted(raw string, tid tenant.ID, subject string, now time.Time) (bool, error) {
	return s.holds(grantSpec, raw, tid, subject, now)
}

// grant returns the new value of the grant cookie raw with a new entry of
// the subject of tenant tid (see [Service.add]).
func (s *Service) grant(raw string, tid tenant.ID, subject string, now time.Time) (string, error) {
	return s.add(grantSpec, raw, tid, subject, now)
}
