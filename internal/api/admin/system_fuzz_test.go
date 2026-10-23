package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/api/problem"
)

// FuzzDecodeSystemSettingsUpdate checks that decodeSystemSettingsUpdate
// never panics, that it either decodes or answers validation-failed, and
// that what it decodes is a JSON object holding only the known members,
// with a threshold never null and an address present exactly when the
// member is (nil for null).
func FuzzDecodeSystemSettingsUpdate(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"diskAlertThreshold":0.9}`, `{"alertEmail":null}`, `{"alertEmail":"it@example.com"}`,
		`{"diskAlertThreshold":null}`, `{"unknown":1}`, `[1]`, `null`, `{`, `{"diskAlertThreshold":"x"}`,
		`{"a/b~c":1}`, `{"diskAlertThreshold":1e999,"alertEmail":5}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		patch, err := decodeSystemSettingsUpdate(raw)
		if err != nil {
			var p *problem.Problem
			if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) == 0 {
				t.Fatalf("decodeSystemSettingsUpdate(%q) error %v is not validation-failed", raw, err)
			}
			return
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			t.Fatalf("decodeSystemSettingsUpdate(%q) accepted a non-object", raw)
		}
		for name := range members {
			if name != memberDiskAlertThreshold && name != memberAlertEmail {
				t.Fatalf("decodeSystemSettingsUpdate(%q) accepted the unknown member %q", raw, name)
			}
		}
		if _, ok := members[memberDiskAlertThreshold]; ok != (patch.Threshold != nil) {
			t.Fatalf("decodeSystemSettingsUpdate(%q): threshold presence %v, decoded %v", raw, ok, patch.Threshold)
		}
		v, ok := members[memberAlertEmail]
		if ok != patch.Email.Set {
			t.Fatalf("decodeSystemSettingsUpdate(%q): address presence %v, set %v", raw, ok, patch.Email.Set)
		}
		if ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) != (patch.Email.Value == nil) {
			t.Fatalf("decodeSystemSettingsUpdate(%q): null address decoded %v", raw, patch.Email.Value)
		}
	})
}

// FuzzDecodeMaintenanceUpdate checks that decodeMaintenanceUpdate never
// panics, that it either decodes or answers validation-failed, and that
// what it decodes is a JSON object holding a boolean enabled and only the
// known members.
func FuzzDecodeMaintenanceUpdate(f *testing.F) {
	for _, s := range []string{
		`{"enabled":true}`, `{"enabled":false,"message":null}`, `{"enabled":true,"message":{"en":"x"}}`,
		`{}`, `null`, `{"enabled":null}`, `{"enabled":"true"}`, `{"mesage":1}`, `{"enabled":true,"message":[1]}`, `{`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		enabled, _, err := decodeMaintenanceUpdate(raw)
		if err != nil {
			var p *problem.Problem
			if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) == 0 {
				t.Fatalf("decodeMaintenanceUpdate(%q) error %v is not validation-failed", raw, err)
			}
			return
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil {
			t.Fatalf("decodeMaintenanceUpdate(%q) accepted a non-object", raw)
		}
		for name := range members {
			if name != memberEnabled && name != memberMessage {
				t.Fatalf("decodeMaintenanceUpdate(%q) accepted the unknown member %q", raw, name)
			}
		}
		var want *bool
		if json.Unmarshal(members[memberEnabled], &want) != nil || want == nil || *want != enabled {
			t.Fatalf("decodeMaintenanceUpdate(%q) decoded enabled %v", raw, enabled)
		}
	})
}

// FuzzDecodeTotpCode checks that decodeTotpCode never panics, that it
// either decodes or answers validation-failed, and that what it decodes is
// a JSON object holding only the known members.
func FuzzDecodeTotpCode(f *testing.F) {
	for _, s := range []string{
		`{"code":"204816"}`, `{"recoveryCode":"rc-1"}`, `{}`, `null`, `{"code":null}`, `{"code":1}`, `{"cdoe":"1"}`, `{`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		code, recovery, err := decodeTotpCode(raw)
		if err != nil {
			var p *problem.Problem
			if !errors.As(err, &p) || p.Code != problem.CodeValidationFailed || len(p.Errors) == 0 {
				t.Fatalf("decodeTotpCode(%q) error %v is not validation-failed", raw, err)
			}
			return
		}
		var b struct {
			Code         string `json:"code"`
			RecoveryCode string `json:"recoveryCode"`
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil || members == nil || json.Unmarshal(raw, &b) != nil {
			t.Fatalf("decodeTotpCode(%q) accepted a non-object", raw)
		}
		for name := range members {
			if name != memberCode && name != memberRecoveryCode {
				t.Fatalf("decodeTotpCode(%q) accepted the unknown member %q", raw, name)
			}
		}
		if code != b.Code || recovery != b.RecoveryCode {
			t.Fatalf("decodeTotpCode(%q) = %q, %q", raw, code, recovery)
		}
	})
}
