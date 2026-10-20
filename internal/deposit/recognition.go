package deposit

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Browser recognition cookie (spec 7: "un cookie technique peut faciliter
// la reconnaissance, mais la base fait foi"). See the package documentation.
const (
	// RecognitionCookie is the name of the cookie. The __Host- prefix
	// requires Secure, Path=/ and no Domain attribute.
	RecognitionCookie = "__Host-tt_known"
	// RecognitionMaxEntries bounds the addresses one browser remembers.
	RecognitionMaxEntries = 5
	// RecognitionMaxAge is the lifetime of the cookie, renewed on each use
	// (31536000 seconds).
	RecognitionMaxAge = RecognitionMaxAgeDays * 24 * time.Hour
	// RecognitionMaxAgeDays is how long an entry is accepted after its issue
	// day, whatever the cookie lifetime the browser applies.
	RecognitionMaxAgeDays = 365
	// recognitionSep separates the entries of the cookie value.
	recognitionSep = "."
	// recognitionDayLen is the size of the issue day that starts an entry.
	recognitionDayLen = 4
	// recognitionRawLen is the size of a decoded entry: the issue day then
	// the MAC.
	recognitionRawLen = recognitionDayLen + crypto.MACSize
	// recognitionEntryLen is the length of one encoded entry (unpadded
	// base64url of recognitionRawLen bytes).
	recognitionEntryLen = 48
	// maxRecognitionInput bounds the raw cookie value the service parses; a
	// longer value is ignored altogether. Five entries take 244 bytes.
	maxRecognitionInput = 1024
	// secondsPerDay converts Unix seconds to issue days.
	secondsPerDay = 24 * 60 * 60
)

// recognitionEncoding encodes the entries; its alphabet never contains
// recognitionSep.
var recognitionEncoding = base64.RawURLEncoding

// parseRecognition decodes the raw value of the recognition cookie into at
// most RecognitionMaxEntries distinct entries of recognitionRawLen bytes.
// It is defensive: a value longer than maxRecognitionInput is ignored, and
// so is every entry that is not exactly one entry in unpadded base64url. It
// never fails. The entries are neither dated nor verified here.
func parseRecognition(raw string) [][]byte {
	if raw == "" || len(raw) > maxRecognitionInput {
		return nil
	}
	var entries [][]byte
	for part := range strings.SplitSeq(raw, recognitionSep) {
		if len(entries) == RecognitionMaxEntries {
			break
		}
		if len(part) != recognitionEntryLen {
			continue
		}
		e, err := recognitionEncoding.DecodeString(part)
		if err != nil || len(e) != recognitionRawLen || slices.ContainsFunc(entries, func(o []byte) bool { return bytes.Equal(o, e) }) {
			continue
		}
		entries = append(entries, e)
	}
	return entries
}

// dayOf returns the issue day of t: whole days since the Unix epoch, 0
// before it.
func dayOf(t time.Time) uint32 {
	d := max(t.Unix()/secondsPerDay, 0)
	return uint32(min(d, 1<<32-1))
}

// fresh reports whether the entry e, issued on its leading day, is still
// accepted on day today: not issued in the future, at most
// RecognitionMaxAgeDays ago.
func fresh(e []byte, today uint32) bool {
	day := binary.BigEndian.Uint32(e[:recognitionDayLen])
	return day <= today && today-day <= RecognitionMaxAgeDays
}

// recognitionParts returns the MAC input of an entry of the address email in
// tenant tid issued on day: the cookie never contains the address, and an
// entry is worthless in another tenant, for another address, after the salt
// of the address is replaced or with another day.
func recognitionParts(tid tenant.ID, email string, salt [store.RecognitionSaltSize]byte, day []byte) [][]byte {
	return [][]byte{[]byte(tid), []byte(email), salt[:], day}
}

// ownEntry reports whether e is a fresh entry of the address (email, salt)
// in tenant tid. The MAC comparison runs in constant time
// (Keys.VerifyMAC).
func (s *Service) ownEntry(e []byte, today uint32, tid tenant.ID, email string, salt [store.RecognitionSaltSize]byte) (bool, error) {
	if !fresh(e, today) {
		return false, nil
	}
	ok, err := s.keys.VerifyMAC(crypto.MACPurposeRecognition, e[recognitionDayLen:],
		recognitionParts(tid, email, salt, e[:recognitionDayLen])...)
	if err != nil {
		return false, fmt.Errorf("deposit: verify recognition cookie: %w", err)
	}
	return ok, nil
}

// recognizes reports whether one of entries is a fresh entry of the address
// email (with its recognition salt) in tenant tid.
func (s *Service) recognizes(entries [][]byte, tid tenant.ID, email string, salt [store.RecognitionSaltSize]byte) (bool, error) {
	today := dayOf(s.now())
	for _, e := range entries {
		if ok, err := s.ownEntry(e, today, tid, email, salt); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

// remember returns the new value of the recognition cookie: a new entry of
// the address email (with its recognition salt) in tenant tid, issued
// today, then the other fresh entries in their order, without the earlier
// entries of this address, capped at RecognitionMaxEntries.
func (s *Service) remember(entries [][]byte, tid tenant.ID, email string, salt [store.RecognitionSaltSize]byte) (string, error) {
	today := dayOf(s.now())
	day := binary.BigEndian.AppendUint32(nil, today)
	mac, err := s.keys.MAC(crypto.MACPurposeRecognition, recognitionParts(tid, email, salt, day)...)
	if err != nil {
		return "", fmt.Errorf("deposit: compute recognition cookie: %w", err)
	}
	out := []string{recognitionEncoding.EncodeToString(append(day, mac...))}
	for _, e := range entries {
		if len(out) == RecognitionMaxEntries {
			break
		}
		if !fresh(e, today) {
			continue
		}
		own, err := s.ownEntry(e, today, tid, email, salt)
		if err != nil {
			return "", err
		}
		if !own {
			out = append(out, recognitionEncoding.EncodeToString(e))
		}
	}
	return strings.Join(out, recognitionSep), nil
}
