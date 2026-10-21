package download

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// FuzzParseGrants checks that any cookie value parses without panic into at
// most GrantMaxEntries entries of the right length, and that serializing
// the entries again parses back to the same entries.
func FuzzParseGrants(f *testing.F) {
	entry := grantEncoding.EncodeToString(bytes.Repeat([]byte{7}, grantRawLen))
	for _, seed := range []string{
		"", "dg_", GrantCookiePrefix + entry, GrantCookiePrefix + entry + "." + entry,
		GrantCookiePrefix + strings.Repeat(entry+".", 12), "dg_*.**", entry,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		entries := parseGrants(raw)
		if len(entries) > GrantMaxEntries {
			t.Fatalf("%d entries", len(entries))
		}
		parts := make([]string, 0, len(entries))
		for _, e := range entries {
			if len(e) != grantRawLen {
				t.Fatalf("entry of %d bytes", len(e))
			}
			parts = append(parts, grantEncoding.EncodeToString(e))
		}
		if len(entries) == 0 {
			return
		}
		again := parseGrants(GrantCookiePrefix + strings.Join(parts, grantSep))
		if !slices.EqualFunc(again, entries, bytes.Equal) {
			t.Fatalf("round trip %x, want %x", again, entries)
		}
	})
}

// FuzzDecodeServed checks that any state decodes without panic and that a
// state that decodes is canonical: marshaling it gives the same bytes.
func FuzzDecodeServed(f *testing.F) {
	f1, f2 := "fil_01JA0000000000000000000000", "fil_01JB0000000000000000000000"
	f.Add(served{f1: {{0, 5}, {7, 1 << 40}}, f2: nil}.marshal())
	f.Add(served{}.marshal())
	f.Add([]byte{stateVersion, 0x80, 0x00})
	f.Add(binary.AppendUvarint([]byte{stateVersion}, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := decodeServed(b)
		if err != nil {
			return
		}
		if got := st.marshal(); !bytes.Equal(got, b) {
			t.Fatalf("marshal %x, want %x", got, b)
		}
	})
}

// FuzzCheckPassword checks that checkPassword accepts exactly the
// non-empty, valid UTF-8 inputs of at most MaxPasswordRunes characters and
// MaxPasswordBytes bytes, and that ErrPasswordRequired is returned for the
// empty input only.
func FuzzCheckPassword(f *testing.F) {
	for _, seed := range []string{
		"", "x", password, "\xff", "café", strings.Repeat("a", MaxPasswordRunes),
		strings.Repeat("a", MaxPasswordRunes+1), strings.Repeat("\U0001F600", MaxPasswordRunes),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, pw string) {
		err := checkPassword(pw)
		valid := pw != "" && utf8.ValidString(pw) && len(pw) <= MaxPasswordBytes && utf8.RuneCountInString(pw) <= MaxPasswordRunes
		switch {
		case valid && err != nil:
			t.Fatalf("valid input refused: %v", err)
		case !valid && !errors.Is(err, ErrInvalid):
			t.Fatalf("invalid input: error %v", err)
		case errors.Is(err, ErrPasswordRequired) != (pw == ""):
			t.Fatalf("input %q: error %v", pw, err)
		}
	})
}

func TestEmptyFileCredit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{{}, random(10)}})
		fid := p.files[0].ID
		// Without Delivered (HEAD, 416, failed write), nothing is credited.
		f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, "", fid)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Content.Close(ctx)
		if ev.state(p) != nil {
			t.Fatal("empty file credited without a delivered GET")
		}
		ev.fetch(p, "", fid, 0, -1, true)
		if st := ev.state(p); st == nil || !st.fileDone(p.files[0]) {
			t.Fatalf("empty file not credited: %v", st)
		}
	})
}
