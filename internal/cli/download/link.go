package download

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tte2"
)

// MaxLinkBytes is the longest link ParseLink accepts.
const MaxLinkBytes = 2048

// keyFragmentPrefix starts the fragment of an end-to-end encrypted link.
const keyFragmentPrefix = "k="

// ErrInvalidLink is returned by ParseLink for anything that is not a
// download link. Its message never quotes the link, which may carry a key.
var ErrInvalidLink = errors.New("not a TransTeira download link")

// errInvalidKeyInLink wraps ErrInvalidLink for a malformed "#k=" key.
var errInvalidKeyInLink = fmt.Errorf("%w: the end-to-end key of the link is invalid", ErrInvalidLink)

// Link is a parsed download link.
type Link struct {
	// Origin is "https://host[:port]" (normalized, default port dropped), or
	// "" for a bare token: the caller then supplies the server address.
	Origin string
	// Token is the download token, "dl_" followed by 22 to 43 base62
	// characters.
	Token string
	// Key is the raw value of the "#k=" fragment (43 base64url characters,
	// checked by tte2.DecodeKey), or "". It is a secret: never print it.
	Key string
	// FromFragment reports whether Key came from the link itself (the
	// caller warns that a key on the command line is visible to other
	// processes).
	FromFragment bool
}

// String returns the link without its key, for messages.
func (l Link) String() string {
	return client.Redact(l.Origin + id.DownloadPath + l.Token)
}

// ParseLink parses a download link: either a bare token ("dl_..."), or an
// https URL whose path is "/d/<token>" or "/d/<token>/reply", without user
// information or query, with an optional "#k=<key>" fragment and no other
// fragment. Surrounding spaces are ignored; anything else is refused with
// ErrInvalidLink (the error never repeats the link or the key).
func ParseLink(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxLinkBytes || strings.ContainsFunc(raw, invalidLinkRune) {
		return Link{}, ErrInvalidLink
	}
	if id.DownloadTokenValid(raw) {
		return Link{Token: raw}, nil
	}
	base, frag, hasFrag := strings.Cut(raw, "#")
	var l Link
	if hasFrag {
		key, err := parseKeyFragment(frag)
		if err != nil {
			return Link{}, err
		}
		l.Key, l.FromFragment = key, true
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.RawPath != "" {
		return Link{}, ErrInvalidLink
	}
	origin, err := client.NormalizeURL(u.Scheme + "://" + u.Host)
	if err != nil {
		return Link{}, ErrInvalidLink
	}
	rest, ok := strings.CutPrefix(u.Path, id.DownloadPath)
	if !ok {
		return Link{}, ErrInvalidLink
	}
	token := strings.TrimSuffix(rest, "/reply")
	if !id.DownloadTokenValid(token) {
		return Link{}, ErrInvalidLink
	}
	l.Origin, l.Token = origin, token
	return l, nil
}

// parseKeyFragment checks the fragment of a link ("k=" and a key) and
// returns the key.
func parseKeyFragment(frag string) (string, error) {
	key, ok := strings.CutPrefix(frag, keyFragmentPrefix)
	if !ok {
		return "", ErrInvalidLink
	}
	if _, err := tte2.DecodeKey(key); err != nil {
		return "", errInvalidKeyInLink
	}
	return key, nil
}

// invalidLinkRune reports a character that never appears in a link:
// spaces, controls and every hidden character.
func invalidLinkRune(r rune) bool {
	return r <= ' ' || r == 0x7f || r > 0x7e
}

// keyFromInput returns the key typed by the user: the key alone, or a full
// link whose fragment holds it.
func keyFromInput(s string) (string, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		key, err := parseKeyFragment(s[i+1:])
		if err != nil {
			return "", errWrongKeyFormat
		}
		return key, nil
	}
	return s, nil
}
