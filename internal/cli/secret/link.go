package secret

import (
	"errors"
	"net/url"
	"strings"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tte2"
)

// MaxLinkBytes is the longest link ParseLink accepts.
const MaxLinkBytes = 2048

// keyFragmentPrefix starts the fragment of a secret link.
const keyFragmentPrefix = "k="

// ErrInvalidLink is returned by ParseLink for anything that is not a full
// secret link. Its message never quotes the link, which carries the key.
var ErrInvalidLink = errors.New("not a TransTeira secret link (https://host/s/tts_...#k=...)")

// Link is a parsed secret link.
type Link struct {
	// Origin is "https://host[:port]" (normalized, default port dropped):
	// the server to ask.
	Origin string
	// Token is the secret token, "tts_" followed by 43 base62 characters.
	// With the origin alone it lets one ask the status, not read the
	// secret; still, never print it in full.
	Token string
	// Key is the "#k=" fragment, 43 base64url characters checked by
	// tte2.DecodeKey. It is the secret: never print it.
	Key string
}

// String returns the link without its key and with its token shortened,
// for messages.
func (l Link) String() string {
	return client.Redact(l.Origin + id.SecretPath + l.Token)
}

// ParseLink parses a secret link: an https URL whose path is exactly
// "/s/<token>", without user information nor query, with the fragment
// "k=<key>" and nothing else. Surrounding spaces are ignored. A bare token
// is refused: the key is needed to read a secret. Every refusal is
// ErrInvalidLink, whose message never repeats the link nor the key.
func ParseLink(raw string) (Link, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxLinkBytes || strings.ContainsFunc(raw, invalidLinkRune) {
		return Link{}, ErrInvalidLink
	}
	base, frag, ok := strings.Cut(raw, "#")
	if !ok {
		return Link{}, ErrInvalidLink
	}
	key, ok := strings.CutPrefix(frag, keyFragmentPrefix)
	if !ok {
		return Link{}, ErrInvalidLink
	}
	if _, err := tte2.DecodeKey(key); err != nil {
		return Link{}, ErrInvalidLink
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
	token, ok := strings.CutPrefix(u.Path, id.SecretPath)
	if !ok || !id.SecretTokenValid(token) {
		return Link{}, ErrInvalidLink
	}
	return Link{Origin: origin, Token: token, Key: key}, nil
}

// invalidLinkRune reports a character that never appears in a link:
// spaces, controls and every non-ASCII or hidden character.
func invalidLinkRune(r rune) bool {
	return r <= ' ' || r == 0x7f || r > 0x7e
}
