package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func FuzzCheckIssuer(f *testing.F) {
	for _, s := range []string{
		"https://idp.example.com", "https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/v2.0",
		"https://login.microsoftonline.com/%7Btenantid%7D/v2.0", "http://x", "https://u@h/", "https://h/?q#f",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, issuer string) {
		err := CheckIssuer(issuer)
		if err != nil && !errors.Is(err, ErrIssuerInvalid) && !errors.Is(err, ErrIssuerNotAllowed) {
			t.Fatalf("unexpected error %v", err)
		}
		if err == nil {
			u, perr := url.Parse(issuer)
			if perr != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				len(issuer) < MinIssuerLength || len(issuer) > MaxIssuerLength {
				t.Fatalf("accepted %q", issuer)
			}
			if entraHosts[issuerHost(u)] {
				for seg := range strings.SplitSeq(u.Path, "/") {
					if entraMultiTenant[strings.ToLower(seg)] {
						t.Fatalf("multi-tenant issuer accepted: %q", issuer)
					}
				}
			}
		}
		if IsEntraTenantIssuer(issuer) && err != nil {
			t.Fatalf("Entra tenant issuer refused by CheckIssuer: %q", issuer)
		}
	})
}

func FuzzParseDocument(f *testing.F) {
	f.Add(`{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/a",` +
		`"token_endpoint":"https://idp.example.com/t","jwks_uri":"https://idp.example.com/k"}`)
	f.Add(`{"issuer":"https://idp.example.com","authorization_endpoint":"http://x"}`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, body string) {
		d, err := ParseDocument("https://idp.example.com", []byte(body))
		if err != nil {
			if err.Reason != ReasonIssuerError || err.Category == "" || d != nil {
				t.Fatalf("bad failure %+v", err)
			}
			return
		}
		if d.Issuer != "https://idp.example.com" || !checkEndpoint(d.AuthorizationEndpoint) ||
			!checkEndpoint(d.TokenEndpoint) || !checkEndpoint(d.JWKSURI) {
			t.Fatalf("invalid document accepted: %+v", d)
		}
	})
}

func FuzzParseCookie(f *testing.F) {
	f.Add("of_abc.AAAA")
	f.Add("of_" + random() + "." + random())
	f.Add("")
	f.Add("of_.x")
	f.Fuzz(func(t *testing.T, value string) {
		id, m, ok := ParseCookie(value)
		if !ok {
			return
		}
		if !strings.HasPrefix(id, flowIDPrefix) || len(m) != 32 || len(value) > maxCookieLength {
			t.Fatalf("ParseCookie(%q) = %q, %d bytes", value, id, len(m))
		}
	})
}

func FuzzConsume(f *testing.F) {
	flows := NewFlows(NewClient(Options{}), testKeys(f))
	f.Add("of_abc.AAAA", "state", "https://idp.example.com")
	f.Fuzz(func(t *testing.T, cookie, state, iss string) {
		if flows.Bound(cookie, state) {
			t.Fatalf("Bound(%q, %q) of a forged cookie", cookie, state)
		}
		if _, err := flows.Consume(cookie, state, iss); ReasonOf(err) != ReasonStateInvalid {
			t.Fatalf("Consume of a forged cookie = %v", err)
		}
	})
}

func FuzzParseKeySet(f *testing.F) {
	f.Add(`{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`)
	f.Add(`{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)
	f.Add(`{"keys":[]}`)
	f.Fuzz(func(t *testing.T, body string) {
		keys, ok := ParseKeySet([]byte(body))
		if !ok {
			return
		}
		if len(keys) > maxKeys {
			t.Fatalf("%d keys", len(keys))
		}
		for i := range keys {
			if !keys[i].IsPublic() || !usable(&keys[i]) {
				t.Fatalf("unusable key kept: %+v", keys[i])
			}
		}
	})
}

// FuzzVerifyIDToken fuzzes the ID token path: JWS parsing, signature,
// claims parsing and checks, against a static key set.
func FuzzVerifyIDToken(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0)
	c := NewClient(Options{Now: func() time.Time { return now }})
	ks := newKeySet(c, "https://127.0.0.1:1/jwks")
	ks.keys = []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k"}}
	ks.loaded, ks.loadedAt = true, now
	prov := &provider{doc: &Document{Issuer: "https://idp.example.com"}, keys: ks, fetchedAt: now}
	p := Pending{Issuer: "https://idp.example.com", ClientID: "c", nonce: "n", verifier: "v"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k"}}, nil)
	if err != nil {
		f.Fatal(err)
	}
	sign := func(claims map[string]any) string {
		b, _ := json.Marshal(claims)
		jws, _ := signer.Sign(b)
		s, _ := jws.CompactSerialize()
		return s
	}
	base := map[string]any{
		"iss": "https://idp.example.com", "sub": "s", "aud": "c", "nonce": "n",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "email": "a@b.example.com", "email_verified": true,
	}
	f.Add(sign(base))
	f.Add(sign(map[string]any{"iss": "https://idp.example.com", "aud": []string{"c", "d"}}))
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, raw string) {
		id, err := c.verify(context.Background(), prov, p, raw)
		if err != nil {
			if r := ReasonOf(err); r != ReasonTokenInvalid && r != ReasonIssuerError {
				t.Fatalf("reason %q", r)
			}
			return
		}
		if id.Subject == "" || len(id.Subject) > maxSubjectLength || id.Issuer != p.Issuer || id.ClientID != p.ClientID {
			t.Fatalf("invalid identity %+v", id)
		}
	})
}
