package secret

import (
	"errors"
	"strings"
	"testing"
)

const (
	linkToken = "tts_Xp4kQ7mZr2Lw9TfB3nHc8VyJd5Gs1KqA6eWu0RtNb7M" // gitleaks:allow (example token of the specification)
	linkKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestParseLink(t *testing.T) {
	for _, tc := range []struct{ raw, origin string }{
		{"https://transfer.entity-a.example.com/s/" + linkToken + "#k=" + linkKey, "https://transfer.entity-a.example.com"},
		{"  https://Transfer.Entity-A.example.com:443/s/" + linkToken + "#k=" + linkKey + "\n", "https://transfer.entity-a.example.com"},
		{"https://transfer.entity-a.example.com:8443/s/" + linkToken + "#k=" + linkKey, "https://transfer.entity-a.example.com:8443"},
	} {
		l, err := ParseLink(tc.raw)
		if err != nil || l.Origin != tc.origin || l.Token != linkToken || l.Key != linkKey {
			t.Errorf("%q: %+v %v", tc.raw, l, err)
		}
		if s := l.String(); strings.Contains(s, linkKey) || strings.Contains(s, linkToken) || !strings.Contains(s, "/s/tts_Xp4k") {
			t.Errorf("String %q", s)
		}
	}
	base := "https://transfer.entity-a.example.com/s/" + linkToken
	for _, raw := range []string{
		"",
		linkToken,
		linkToken + "#k=" + linkKey,
		base,
		base + "#",
		base + "#key=" + linkKey,
		base + "#k=" + linkKey[:42],
		base + "#k=" + linkKey + "&x",
		"http://transfer.entity-a.example.com/s/" + linkToken + "#k=" + linkKey,
		"https://user@transfer.entity-a.example.com/s/" + linkToken + "#k=" + linkKey,
		base + "?x=1#k=" + linkKey,
		base + "?#k=" + linkKey,
		"https://transfer.entity-a.example.com/s/tts%5FXp4kQ7mZr2Lw9TfB3nHc8VyJd5Gs1KqA6eWu0RtNb7M#k=" + linkKey,
		"https://transfer.entity-a.example.com/d/" + linkToken + "#k=" + linkKey,
		"https://transfer.entity-a.example.com/s/" + linkToken + "/x#k=" + linkKey,
		"https://transfer.entity-a.example.com/s/tts_short#k=" + linkKey,
		"https://transfer.entity-a.example.com:/s/" + linkToken + "#k=" + linkKey,
		"https:///s/" + linkToken + "#k=" + linkKey,
		"https://[::1/s/" + linkToken + "#k=" + linkKey,
		"https:transfer/s/" + linkToken + "#k=" + linkKey,
		"https://transfer.entity-a.example.com/s/ " + linkToken + "#k=" + linkKey,
		"https://transfer.entity-a.example.com/s/" + linkToken + "\u200b#k=" + linkKey,
		"https://transfer.entity-a.example.com/s/" + linkToken + "#k=" + linkKey + strings.Repeat("A", MaxLinkBytes),
	} {
		l, err := ParseLink(raw)
		if !errors.Is(err, ErrInvalidLink) {
			t.Errorf("%q accepted: %+v", raw, l)
		}
		if err != nil && strings.Contains(err.Error(), linkKey) {
			t.Errorf("key in the error of %q", raw)
		}
	}
}
