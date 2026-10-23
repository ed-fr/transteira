package apitoken

import (
	"context"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestAdminSenders creates and updates the allowed senders of a token, on
// both engines: normalized, kept, replaced and cleared, and audited as a
// count only, never as addresses.
func TestAdminSenders(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		ev := newEnv(t, e)
		svc := ev.svc
		created, err := svc.Create(ctx, ev.delegA, ev.a.ID, CreateInput{
			Name: "ERP", AllowedCIDRs: []string{"192.0.2.0/24"},
			AllowedSenders: []string{" Reporting@Entity-A.Example.com ", "ERP.Entity-A.example.com.", "bücher.example"},
		}, adminIP)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"reporting@entity-a.example.com", "erp.entity-a.example.com", "xn--bcher-kva.example"}
		if !reflect.DeepEqual(created.Token.AllowedSenders, want) {
			t.Fatalf("Create.AllowedSenders = %q, want %q", created.Token.AllowedSenders, want)
		}
		ev.clock.Advance(time.Second)
		plain, err := svc.Create(ctx, ev.delegA, ev.a.ID, CreateInput{Name: "plain", AllowedCIDRs: []string{"192.0.2.0/24"}}, adminIP)
		if err != nil || plain.Token.AllowedSenders == nil || len(plain.Token.AllowedSenders) != 0 {
			t.Fatalf("Create(no senders).AllowedSenders = %#v, %v", plain.Token.AllowedSenders, err)
		}
		ev.clock.Advance(time.Second)
		upd, err := svc.Update(ctx, ev.delegA, ev.a.ID, created.Token.ID, UpdateInput{Name: strPtr("ERP 2")}, adminIP)
		if err != nil || !reflect.DeepEqual(upd.AllowedSenders, want) {
			t.Errorf("Update(name).AllowedSenders = %q, %v", upd.AllowedSenders, err)
		}
		ev.clock.Advance(time.Second)
		upd, err = svc.Update(ctx, ev.delegA, ev.a.ID, created.Token.ID, UpdateInput{AllowedSenders: []string{"ops@entity-a.example.com"}}, adminIP)
		if err != nil || !reflect.DeepEqual(upd.AllowedSenders, []string{"ops@entity-a.example.com"}) {
			t.Errorf("Update(senders).AllowedSenders = %q, %v", upd.AllowedSenders, err)
		}
		ev.clock.Advance(time.Second)
		upd, err = svc.Update(ctx, ev.delegA, ev.a.ID, created.Token.ID, UpdateInput{AllowedSenders: []string{}}, adminIP)
		if err != nil || upd.AllowedSenders == nil || len(upd.AllowedSenders) != 0 {
			t.Errorf("Update(clear).AllowedSenders = %#v, %v", upd.AllowedSenders, err)
		}

		rows := ev.auditRows(t, ev.a.ID)
		if len(rows) != 5 {
			t.Fatalf("audit rows = %d, want 5", len(rows))
		}
		for _, r := range rows {
			if strings.Contains(string(r.Details), "@") || strings.Contains(string(r.Details), "entity-a") {
				t.Errorf("audit details leak a sender: %s", r.Details)
			}
		}
		if d := rows[0].details; d["senderCount"] != float64(3) {
			t.Errorf("created details = %v", d)
		}
		if d := rows[1].details; d["senderCount"] != float64(0) {
			t.Errorf("created (no senders) details = %v", d)
		}
		if d := rows[2].details; d["senderCount"] != nil {
			t.Errorf("updated (name) details = %v", d)
		}
		if d := rows[3].details; d["senderCount"] != float64(1) || !reflect.DeepEqual(d["fields"], []any{"allowedSenders"}) {
			t.Errorf("updated (senders) details = %v", d)
		}
		if d := rows[4].details; d["senderCount"] != float64(0) || !reflect.DeepEqual(d["fields"], []any{"allowedSenders"}) {
			t.Errorf("updated (clear) details = %v", d)
		}
	})
}

func TestAdminSendersValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ok := []string{"192.0.2.0/24"}
	created, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "x", AllowedCIDRs: ok}, adminIP)
	if err != nil {
		t.Fatal(err)
	}
	many := make([]string, MaxSenders+1)
	for i := range many {
		many[i] = "u" + strconv.Itoa(i) + "@entity-a.example.com"
	}
	cases := map[string]struct {
		in    []string
		field string
	}{
		"too many":       {many, FieldAllowedSenders},
		"empty":          {[]string{""}, FieldAllowedSenders + "/0"},
		"blank":          {[]string{"a.example.com", "   "}, FieldAllowedSenders + "/1"},
		"too long":       {[]string{strings.Repeat("a", 250) + ".com"}, FieldAllowedSenders + "/0"},
		"display name":   {[]string{"Alice <alice@entity-a.example.com>"}, FieldAllowedSenders + "/0"},
		"quoted local":   {[]string{`"a b"@entity-a.example.com`}, FieldAllowedSenders + "/0"},
		"two at signs":   {[]string{"a@b@entity-a.example.com"}, FieldAllowedSenders + "/0"},
		"no domain":      {[]string{"alice@"}, FieldAllowedSenders + "/0"},
		"single label":   {[]string{"localhost"}, FieldAllowedSenders + "/0"},
		"port":           {[]string{"entity-a.example.com:25"}, FieldAllowedSenders + "/0"},
		"inner space":    {[]string{"entity a.example.com"}, FieldAllowedSenders + "/0"},
		"ip literal":     {[]string{"192.0.2.1"}, FieldAllowedSenders + "/0"},
		"dup address":    {[]string{"Ops@entity-a.example.com", "ops@ENTITY-A.example.com"}, FieldAllowedSenders + "/1"},
		"dup domain":     {[]string{"entity-a.example.com", "x@y.example", "Entity-A.example.com."}, FieldAllowedSenders + "/2"},
		"control in one": {[]string{"a\x07@entity-a.example.com"}, FieldAllowedSenders + "/0"},
	}
	for what, c := range cases {
		_, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "n", AllowedCIDRs: ok, AllowedSenders: c.in}, adminIP)
		wantInvalid(t, "Create(senders "+what+")", err, c.field)
		_, err = ev.svc.Update(ctx, ev.super, ev.a.ID, created.Token.ID, UpdateInput{AllowedSenders: c.in}, adminIP)
		wantInvalid(t, "Update(senders "+what+")", err, c.field)
	}
	full := make([]string, MaxSenders)
	copy(full, many)
	if _, err := ev.svc.Create(ctx, ev.super, ev.a.ID, CreateInput{Name: "n", AllowedCIDRs: ok, AllowedSenders: full}, adminIP); err != nil {
		t.Errorf("Create(%d senders) = %v", MaxSenders, err)
	}
}

// FuzzCheckCIDRs checks that checkCIDRs never panics and that what it
// accepts is 1 to MaxCIDRs masked, distinct ranges.
func FuzzCheckCIDRs(f *testing.F) {
	for _, s := range []string{"192.0.2.0/24", "2001:db8::1", "::ffff:198.51.100.0/120", "0.0.0.0/0,::/0", "192.0.2.1/24", "fe80::1%eth0", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, list string) {
		raw := strings.Split(list, ",")
		got, err := checkCIDRs(raw)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "apitoken: invalid "+FieldAllowedCIDRs) {
				t.Fatalf("checkCIDRs error %q names another field", err)
			}
			return
		}
		if len(got) == 0 || len(got) > MaxCIDRs || len(got) != len(raw) {
			t.Fatalf("checkCIDRs(%q) = %d ranges", raw, len(got))
		}
		seen := map[netip.Prefix]bool{}
		for _, p := range got {
			if !p.IsValid() || p != p.Masked() || seen[p] || p.Addr().Zone() != "" || p.Addr().Is4In6() {
				t.Fatalf("checkCIDRs(%q) returned %v", raw, got)
			}
			seen[p] = true
		}
	})
}

// FuzzCheckSenders checks that checkSenders never panics and that what it
// accepts is at most MaxSenders distinct entries, each a fixed point of the
// normalization, without whitespace or control character.
func FuzzCheckSenders(f *testing.F) {
	for _, s := range []string{
		"reporting@entity-a.example.com", "ERP.example.com.", "bücher.example", "a@b@c", "Alice <a@b.example>",
		"a.example.com,A.example.com", "", "x@xn--bcher-kva.example,xn--bcher-kva.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, list string) {
		raw := strings.Split(list, ",")
		got, err := checkSenders(raw)
		if err != nil {
			if !strings.HasPrefix(err.Error(), "apitoken: invalid "+FieldAllowedSenders) {
				t.Fatalf("checkSenders error %q names another field", err)
			}
			return
		}
		if got == nil || len(got) > MaxSenders || len(got) != len(raw) {
			t.Fatalf("checkSenders(%q) = %q", raw, got)
		}
		seen := map[string]bool{}
		for _, v := range got {
			again, ok := normalizeSender(v)
			if !ok || again != v || seen[v] || v != strings.ToLower(v) ||
				strings.ContainsAny(v, " \t\r\n\x00") || len(v) > MaxSenderLen {
				t.Fatalf("checkSenders(%q) returned %q", raw, got)
			}
			seen[v] = true
		}
	})
}
