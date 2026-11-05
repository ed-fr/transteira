package oidc

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckIssuer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want error
	}{
		{"https://idp.example.com", nil},
		{"https://idp.example.com/realms/a/", nil},
		{"https://login.microsoftonline.com/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/v2.0", nil},
		{"https://sts.windows.net/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/", nil},
		{"https://idp.example.com:8443/x", nil},
		{"https://idp.example.com/common", nil}, // not an Entra host
		{"https://login.microsoftonline.com/common/v2.0", ErrIssuerNotAllowed},
		{"https://login.microsoftonline.com/organizations/v2.0", ErrIssuerNotAllowed},
		{"https://LOGIN.microsoftonline.com./Consumers/v2.0", ErrIssuerNotAllowed},
		{"https://login.microsoftonline.us/common/v2.0", ErrIssuerNotAllowed},
		{"https://login.partner.microsoftonline.cn/common/v2.0", ErrIssuerNotAllowed},
		{"https://sts.windows.net/common/", ErrIssuerNotAllowed},
		{"https://login.microsoftonline.com/{tenantid}/v2.0", ErrIssuerNotAllowed},
		{"https://login.microsoftonline.com/%7Btenantid%7D/v2.0", ErrIssuerNotAllowed},
		{"https://idp.example.com/{tenant}", ErrIssuerNotAllowed},
		{"http://idp.example.com", ErrIssuerInvalid},
		{"HTTPS://idp.example.com", ErrIssuerInvalid},
		{"https://", ErrIssuerInvalid},
		{"https:/", ErrIssuerInvalid},
		{"https://:443/abcdef", ErrIssuerInvalid},
		{"https://user:pw@idp.example.com", ErrIssuerInvalid},
		{"https://idp.example.com/?a=b", ErrIssuerInvalid},
		{"https://idp.example.com/#f", ErrIssuerInvalid},
		{"https://idp.example.com/ x", ErrIssuerInvalid},
		{"https://idp.example.com/\x7f", ErrIssuerInvalid},
		{"https://[::1/x", ErrIssuerInvalid},
		{"https:opaque/x", ErrIssuerInvalid},
		{"https://idp.example.com/" + strings.Repeat("a", 500), ErrIssuerInvalid},
	} {
		if err := CheckIssuer(tc.in); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("CheckIssuer(%q) = %v, want %v", tc.in, err, tc.want)
		}
	}
}

func TestIsEntraTenantIssuer(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"https://login.microsoftonline.com/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/v2.0": true,
		"https://sts.windows.net/0B0C1D2E-3F40-5A6B-7C8D-9E0F1A2B3C4D/":               true,
		"https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0":              false,
		"https://login.microsoftonline.com/common/v2.0":                               false,
		"https://idp.example.com/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/v2.0":           false,
		"http://login.microsoftonline.com/0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d/v2.0":  false,
	} {
		if got := IsEntraTenantIssuer(in); got != want {
			t.Errorf("IsEntraTenantIssuer(%q) = %v", in, got)
		}
	}
}

func TestIsGUID(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4d": true,
		"0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4":  false,
		"0b0c1d2e+3f40-5a6b-7c8d-9e0f1a2b3c4d": false,
		"0b0c1d2e-3f40-5a6b-7c8d-9e0f1a2b3c4g": false,
	} {
		if got := isGUID(in); got != want {
			t.Errorf("isGUID(%q) = %v", in, got)
		}
	}
}

func TestCheckEndpoint(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"https://idp.example.com/token":         true,
		"https://idp.example.com/authorize?p=1": true,
		"":                                      false,
		"https://idp.example.com/" + strings.Repeat("a", 2048): false,
		"https://idp.example.com/a#b":                          false,
		"https://idp.example.com/a b":                          false,
		"https://idp.example.com/\x01":                         false,
		"https://[::1/x":                                       false,
		"http://idp.example.com/token":                         false,
		"https:///token":                                       false,
		"https://u:p@idp.example.com/token":                    false,
		"/token":                                               false,
	} {
		if got := checkEndpoint(in); got != want {
			t.Errorf("checkEndpoint(%q) = %v", in, got)
		}
	}
}
