package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ed-fr/transteira/internal/events"
)

// verifySignature checks header the way the OpenAPI WebhookEvent
// documentation tells a receiver to: parse t and v1, recompute the
// HMAC-SHA256 of "<t>.<raw body>" with the secret, compare in constant time
// and reject a t older than 5 minutes.
func verifySignature(header string, secret, body []byte, now time.Time) error {
	var ts, sig string
	for part := range strings.SplitSeq(header, ",") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("no timestamp")
	}
	if now.Sub(time.Unix(sec, 0)) > 5*time.Minute {
		return errors.New("stale")
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "." + string(body)))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return errors.New("bad signature")
	}
	return nil
}

func TestSign(t *testing.T) {
	secret := []byte(strings.Repeat("0f", 32))
	now := time.Unix(1_790_000_000, 0)
	body := []byte(`{"id":"evt_1"}`)
	h := Sign(secret, now, body)
	if !strings.HasPrefix(h, "t=1790000000,v1=") || len(h) != len("t=1790000000,v1=")+64 {
		t.Fatalf("header %q", h)
	}
	if err := verifySignature(h, secret, body, now.Add(time.Minute)); err != nil {
		t.Error(err)
	}
	if verifySignature(h, []byte("other"), body, now) == nil || verifySignature(h, secret, []byte("{}"), now) == nil ||
		verifySignature(h, secret, body, now.Add(6*time.Minute)) == nil ||
		verifySignature("v1=zz", secret, body, now) == nil || verifySignature("t=1790000000,v1=zz", secret, body, now) == nil {
		t.Error("verifier accepts a bad signature")
	}
}

// schema is the part of an OpenAPI schema the payload test reads.
type schema struct {
	Required   []string          `yaml:"required"`
	Properties map[string]schema `yaml:"properties"`
	Enum       []string          `yaml:"enum"`
	Ref        string            `yaml:"$ref"`
}

// loadSchemas reads the components of api/openapi.yaml.
func loadSchemas(t *testing.T) map[string]schema {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]schema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

// checkObject checks that obj holds the required members of s and no
// member s does not declare.
func checkObject(t *testing.T, what string, obj map[string]any, s schema) {
	t.Helper()
	for _, r := range s.Required {
		if _, ok := obj[r]; !ok {
			t.Errorf("%s: missing %q", what, r)
		}
	}
	for k := range obj {
		if _, ok := s.Properties[k]; !ok {
			t.Errorf("%s: unknown member %q", what, k)
		}
	}
}

// checkWebhookEvent validates a generic payload against WebhookEvent.
func checkWebhookEvent(t *testing.T, schemas map[string]schema, body []byte) map[string]any {
	t.Helper()
	ev := schemas["WebhookEvent"]
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	checkObject(t, "WebhookEvent", obj, ev)
	if typ, _ := obj["type"].(string); !slices.Contains(schemas["WebhookEventType"].Enum, typ) {
		t.Errorf("type %q not in WebhookEventType", typ)
	}
	if sev, _ := obj["severity"].(string); !slices.Contains(ev.Properties["severity"].Enum, sev) {
		t.Errorf("severity %q", sev)
	}
	if id, _ := obj["id"].(string); !strings.HasPrefix(id, "evt_") {
		t.Errorf("id %q", id)
	}
	if at, _ := obj["occurredAt"].(string); !strings.HasSuffix(at, "Z") {
		t.Errorf("occurredAt %q", at)
	} else if _, err := time.Parse(time.RFC3339, at); err != nil {
		t.Errorf("occurredAt %q: %v", at, err)
	}
	counts, ok := obj["counts"].(map[string]any)
	if !ok {
		t.Errorf("counts %v", obj["counts"])
	}
	for k, v := range counts {
		if _, ok := v.(float64); !ok {
			t.Errorf("count %s = %v", k, v)
		}
	}
	if tenant, ok := obj["tenant"]; ok {
		m, _ := tenant.(map[string]any)
		checkObject(t, "tenant", m, ev.Properties["tenant"])
	}
	if a, ok := obj["adminUrl"]; ok {
		u, err := url.Parse(a.(string))
		if err != nil || !u.IsAbs() {
			t.Errorf("adminUrl %v", a)
		}
	}
	if a, ok := obj["addresses"]; ok {
		m, _ := a.(map[string]any)
		checkObject(t, "addresses", m, ev.Properties["addresses"])
		if len(m) == 0 {
			t.Error("empty addresses")
		}
	}
	return obj
}

func TestGenericPayloadMatchesSchema(t *testing.T) {
	schemas := loadSchemas(t)
	c := testClient(t, nil, nil)
	types := append(append(events.TenantTypes(), events.SystemTypes()...), events.WebhookTest)
	if len(types) != len(schemas["WebhookEventType"].Enum) {
		t.Fatalf("%d types, the specification lists %d", len(types), len(schemas["WebhookEventType"].Enum))
	}
	addrs := &events.Addresses{
		Sender: "alice@entity-a.example.com", Recipients: []string{"bob@example.org"}, Reporter: "carol@example.net",
	}
	for _, typ := range types {
		for _, include := range []bool{false, true} {
			ev := events.Event{
				ID: "evt_01JABCU7W8X9Y0Z1A2B3C4D5E6", Type: typ, Severity: events.SeverityWarning,
				OccurredAt: time.Date(2026, 10, 27, 11, 0, 0, 0, time.FixedZone("CET", 3600)),
				Counts:     map[string]float64{"usedRatio": 0.85, "nan": math.NaN(), "inf": math.Inf(1)},
				AdminPath:  events.AdminPathSystem, Addresses: addrs,
			}
			tg := Target{ID: "whk_1", Kind: KindGeneric, IncludeAddresses: include}
			tenantEvent := events.IsTenant(typ) || typ == events.WebhookTest
			if tenantEvent {
				ev.TenantID, tg.TenantID, tg.TenantName = "ten_a", "ten_a", "Entity A"
			}
			body, _, ok := c.format(tg, ev, time.Now())
			if !ok {
				t.Fatal("format")
			}
			obj := checkWebhookEvent(t, schemas, body)
			if obj["occurredAt"] != "2026-10-27T10:00:00Z" || obj["adminUrl"] != "https://admin.transfer.example.com/admin/system" {
				t.Errorf("%s: %s", typ, body)
			}
			if c := obj["counts"].(map[string]any); len(c) != 1 {
				t.Errorf("%s: non-finite counts kept: %v", typ, c)
			}
			_, hasTenant := obj["tenant"]
			_, hasAddresses := obj["addresses"]
			if hasTenant != tenantEvent || hasAddresses != (include && tenantEvent) {
				t.Errorf("%s include=%v: %s", typ, include, body)
			}
			if !hasAddresses && strings.Contains(string(body), "@") {
				t.Errorf("%s: address leaked: %s", typ, body)
			}
		}
	}
}

func TestMessageMinimisation(t *testing.T) {
	c := testClient(t, nil, func(o *ClientOptions) { o.AdminURL = "" })
	ev := testEvent()
	// No admin URL configured: no link.
	if m := c.newMessage(Target{TenantID: "ten_a"}, ev); m.adminURL != "" {
		t.Errorf("admin URL %q", m.adminURL)
	}
	c = testClient(t, nil, nil)
	// A relative or empty path gives no link.
	ev.AdminPath = "admin/x"
	if m := c.newMessage(Target{TenantID: "ten_a"}, ev); m.adminURL != "" {
		t.Errorf("admin URL %q", m.adminURL)
	}
	// An event of another tenant never carries the tenant nor addresses.
	ev = testEvent()
	if m := c.newMessage(Target{TenantID: "ten_b", TenantName: "Entity B", IncludeAddresses: true}, ev); m.tenant != nil || m.addresses != nil {
		t.Errorf("foreign event %+v", m)
	}
	// Empty addresses are left out.
	ev.Addresses = &events.Addresses{}
	if m := c.newMessage(Target{TenantID: "ten_a", IncludeAddresses: true}, ev); m.addresses != nil {
		t.Errorf("empty addresses %+v", m.addresses)
	}
	if _, _, ok := c.format(Target{Kind: "pager"}, ev, time.Now()); ok {
		t.Error("unknown kind formatted")
	}
}

func TestTeamsAndSlack(t *testing.T) {
	c := testClient(t, nil, nil)
	ev := testEvent()
	ev.Counts = map[string]float64{}
	for i := range 9 {
		ev.Counts["c"+strconv.Itoa(i)] = float64(i) + 0.5
	}
	ev.Addresses = &events.Addresses{
		Sender: "alice@entity-a.example.com", Recipients: []string{"bob@example.org", "dave@example.org"},
		Reporter: "carol@example.net",
	}
	tg := Target{
		ID: "whk_1", TenantID: "ten_a", TenantName: "Entity [A](x) *bold* <!channel>\x00\u202e",
		Kind: KindTeams,
	}
	for _, include := range []bool{false, true} {
		tg.IncludeAddresses = include
		for _, kind := range []Kind{KindTeams, KindSlack} {
			tg.Kind = kind
			body, h, ok := c.format(tg, ev, time.Now())
			if !ok || h.Get(HeaderSignature) != "" || h.Get(HeaderEvent) != "" {
				t.Fatalf("%s headers %v", kind, h)
			}
			s := string(body)
			if !json.Valid(body) {
				t.Fatalf("%s: invalid JSON", kind)
			}
			for _, bad := range []string{"](", "<!", "*bold*", `\u0000`, "\u202e"} {
				if strings.Contains(s, bad) {
					t.Errorf("%s: %q in %s", kind, bad, s)
				}
			}
			if strings.Contains(s, "@") != include {
				t.Errorf("%s include=%v: %s", kind, include, s)
			}
			if !strings.Contains(s, "Virus detected") || !strings.Contains(s, "https://admin.transfer.example.com/admin/tenants/ten_a/audit") {
				t.Errorf("%s: %s", kind, s)
			}
		}
	}
	// Slack: more than 10 facts are split into sections.
	tg.Kind = KindSlack
	body, _, _ := c.format(tg, ev, time.Now())
	var slack struct {
		Text   string
		Blocks []struct {
			Type   string
			Fields []any
		}
	}
	if err := json.Unmarshal(body, &slack); err != nil {
		t.Fatal(err)
	}
	if len(slack.Blocks) != 4 || slack.Blocks[1].Type != "section" || len(slack.Blocks[1].Fields) != 10 ||
		slack.Blocks[3].Type != "actions" || !strings.Contains(slack.Text, "(critical) - Entity A") {
		t.Errorf("slack %s", body)
	}

	// System event without admin URL, unknown type: fallback title, no
	// tenant, no action.
	c2 := testClient(t, nil, func(o *ClientOptions) { o.AdminURL = "" })
	sys := events.Event{ID: "evt_2", Type: "custom.type", Severity: events.SeverityInfo, OccurredAt: time.Now()}
	for _, kind := range []Kind{KindTeams, KindSlack} {
		body, _, _ := c2.format(Target{Kind: kind}, sys, time.Now())
		s := string(body)
		if !strings.Contains(s, "TransTeira: custom.type") || strings.Contains(s, "Tenant") ||
			strings.Contains(s, "actions") || strings.Contains(s, "Open the administration") {
			t.Errorf("%s: %s", kind, s)
		}
	}
}

func TestTeamsColor(t *testing.T) {
	for s, want := range map[events.Severity]string{
		events.SeverityCritical: "Attention", events.SeverityWarning: "Warning", events.SeverityInfo: "Accent", "": "Accent",
	} {
		if got := teamsColor(s); got != want {
			t.Errorf("teamsColor(%q) = %q", s, got)
		}
	}
}

func TestSafeText(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"Entity A", 100, "Entity A"},
		{"  a\r\n\tb  ", 100, "a b"},
		{"[x](y) *z* <u> `c`", 100, "x y z u c"},
		{"a&b|c#d~e_f\\g", 100, "a b c d e f g"},
		{"bad\xffutf8", 100, "bad\uFFFDutf8"},
		{"rtl\u202eoverride", 100, "rtl override"},
		{"\u00e9\u00e9\u00e9\u00e9\u00e9", 4, "\u00e9\u00e9\u00e9\u2026"},
		{"\u00e9\u00e9\u00e9\u00e9", 4, "\u00e9\u00e9\u00e9\u00e9"},
	} {
		if got := safeText(c.in, c.n); got != c.want {
			t.Errorf("safeText(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
