package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/version"
)

// Headers of the generic deliveries (OpenAPI WebhookEvent).
const (
	// HeaderEvent carries the event type.
	HeaderEvent = "X-TransTeira-Event"
	// HeaderDelivery carries the event ID, identical across the attempts.
	HeaderDelivery = "X-TransTeira-Delivery"
	// HeaderSignature carries "t=<unix seconds>,v1=<hex HMAC-SHA256 of
	// "<t>.<raw body>">".
	HeaderSignature = "X-TransTeira-Signature"
)

// Limits of the formatted messages.
const (
	// maxNameRunes bounds the tenant name in the Teams and Slack messages.
	maxNameRunes = 100
	// maxFieldRunes bounds any other text value of a Teams or Slack
	// message (the recipients list).
	maxFieldRunes = 1000
	// slackFieldsPerSection is the Slack limit of fields in a section.
	slackFieldsPerSection = 10
	// adminLinkText is the label of the link to the administration.
	adminLinkText = "Open the administration"
)

// titles are the English titles of the event types in the Teams and Slack
// messages.
var titles = map[events.Type]string{
	events.VirusDetected:              "Virus detected",
	events.AbuseThresholdExceeded:     "Abuse threshold exceeded",
	events.AbuseUnusualActivity:       "Unusual activity",
	events.AbuseReported:              "Abuse reported",
	events.QuotaWarning:               "Storage quota at 80 %",
	events.QuotaReached:               "Storage quota reached",
	events.DiskAlertRaised:            "Disk space alert",
	events.DiskAlertCleared:           "Disk space back to normal",
	events.AntivirusAlertRaised:       "Antivirus unavailable",
	events.AntivirusAlertCleared:      "Antivirus available again",
	events.MaintenanceEnabled:         "Maintenance mode enabled",
	events.MaintenanceDisabled:        "Maintenance mode disabled",
	events.MasterKeyRotationCompleted: "Master key rotation completed",
	events.MasterKeyRotationFailed:    "Master key rotation failed",
	events.WebhookTest:                "Test event",
}

// genericEvent is the OpenAPI WebhookEvent document.
type genericEvent struct {
	ID         string             `json:"id"`
	Type       events.Type        `json:"type"`
	Severity   events.Severity    `json:"severity"`
	OccurredAt string             `json:"occurredAt"`
	Tenant     *tenantRef         `json:"tenant,omitempty"`
	Counts     map[string]float64 `json:"counts"`
	AdminURL   string             `json:"adminUrl,omitempty"`
	Addresses  *addressesDoc      `json:"addresses,omitempty"`
}

// tenantRef is the tenant member of a WebhookEvent.
type tenantRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// addressesDoc is the addresses member of a WebhookEvent.
type addressesDoc struct {
	Sender     string   `json:"sender,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
	Reporter   string   `json:"reporter,omitempty"`
}

// message is the minimized content of an event for t, shared by the three
// formats (decision P31): never a file name, a link to a transfer, a
// token or a password; addresses only when the tenant allows them.
type message struct {
	ev        events.Event
	tenant    *tenantRef
	counts    map[string]float64
	adminURL  string
	addresses *addressesDoc
}

// newMessage minimizes ev for t. The tenant appears only for an event of
// the tenant of t; the addresses only when t.IncludeAddresses is set on a
// tenant webhook; non-finite counters are dropped.
func (c *Client) newMessage(t Target, ev events.Event) message {
	m := message{ev: ev, counts: make(map[string]float64, len(ev.Counts))}
	for k, v := range ev.Counts {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			m.counts[k] = v
		}
	}
	ownTenant := ev.TenantID != "" && ev.TenantID == t.TenantID
	if ownTenant {
		m.tenant = &tenantRef{ID: ev.TenantID, Name: t.TenantName}
	}
	if c.adminURL != "" && strings.HasPrefix(ev.AdminPath, "/") {
		m.adminURL = c.adminURL + ev.AdminPath
	}
	if a := ev.Addresses; ownTenant && t.IncludeAddresses && a != nil &&
		(a.Sender != "" || len(a.Recipients) > 0 || a.Reporter != "") {
		m.addresses = &addressesDoc{Sender: a.Sender, Recipients: slices.Clone(a.Recipients), Reporter: a.Reporter}
	}
	return m
}

// format returns the body and headers of the request delivering ev to t
// at now; ok is false for an unknown kind.
func (c *Client) format(t Target, ev events.Event, now time.Time) (body []byte, header http.Header, ok bool) {
	m := c.newMessage(t, ev)
	header = http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("User-Agent", "TransTeira/"+version.Get().Version)
	switch t.Kind {
	case KindGeneric:
		body = marshal(m.generic())
		header.Set(HeaderEvent, string(ev.Type))
		header.Set(HeaderDelivery, ev.ID)
		if len(t.Secret) > 0 {
			header.Set(HeaderSignature, Sign(t.Secret, now, body))
		}
	case KindTeams:
		body = marshal(m.teams())
	case KindSlack:
		body = marshal(m.slack())
	default:
		return nil, nil, false
	}
	return body, header, true
}

// marshal encodes v, built only from strings, finite numbers, maps and
// slices: the encoding cannot fail.
func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Sign returns the X-TransTeira-Signature value of body signed at now with
// secret: "t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<body>">". The
// secret is used as given (the ASCII text shown to the admin).
func Sign(secret []byte, now time.Time, body []byte) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// generic returns the WebhookEvent document.
func (m message) generic() genericEvent {
	return genericEvent{
		ID: m.ev.ID, Type: m.ev.Type, Severity: m.ev.Severity,
		OccurredAt: m.ev.OccurredAt.UTC().Format(time.RFC3339),
		Tenant:     m.tenant, Counts: m.counts, AdminURL: m.adminURL, Addresses: m.addresses,
	}
}

// fact is a name and value of a Teams or Slack message.
type fact struct{ name, value string }

// title returns the title of the message.
func (m message) title() string {
	title, ok := titles[m.ev.Type]
	if !ok {
		title = string(m.ev.Type)
	}
	return "TransTeira: " + safeText(title, maxNameRunes)
}

// facts returns the facts of the message: event, severity, tenant, time,
// counters in key order, then the addresses when allowed.
func (m message) facts() []fact {
	out := []fact{
		{"Event", safeText(string(m.ev.Type), maxNameRunes)},
		{"Severity", safeText(string(m.ev.Severity), maxNameRunes)},
	}
	if m.tenant != nil {
		out = append(out, fact{"Tenant", safeText(m.tenant.Name, maxNameRunes)})
	}
	out = append(out, fact{"Occurred at", m.ev.OccurredAt.UTC().Format(time.RFC3339)})
	keys := make([]string, 0, len(m.counts))
	for k := range m.counts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out = append(out, fact{safeText(k, maxNameRunes), strconv.FormatFloat(m.counts[k], 'f', -1, 64)})
	}
	if a := m.addresses; a != nil {
		if a.Sender != "" {
			out = append(out, fact{"Sender", safeText(a.Sender, maxFieldRunes)})
		}
		if len(a.Recipients) > 0 {
			out = append(out, fact{"Recipients", safeText(strings.Join(a.Recipients, ", "), maxFieldRunes)})
		}
		if a.Reporter != "" {
			out = append(out, fact{"Reporter", safeText(a.Reporter, maxFieldRunes)})
		}
	}
	return out
}

// teamsColor maps a severity to an Adaptive Card text color.
func teamsColor(s events.Severity) string {
	switch s {
	case events.SeverityCritical:
		return "Attention"
	case events.SeverityWarning:
		return "Warning"
	default:
		return "Accent"
	}
}

// teams returns a Microsoft Teams message carrying an Adaptive Card (the
// format of the Teams workflows and incoming webhooks).
func (m message) teams() map[string]any {
	facts := make([]map[string]string, 0, 8)
	for _, f := range m.facts() {
		facts = append(facts, map[string]string{"title": f.name, "value": f.value})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body": []any{
			map[string]any{
				"type": "TextBlock", "text": m.title(), "weight": "Bolder", "size": "Medium",
				"color": teamsColor(m.ev.Severity), "wrap": true,
			},
			map[string]any{"type": "FactSet", "facts": facts},
		},
	}
	if m.adminURL != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": adminLinkText, "url": m.adminURL}}
	}
	return map[string]any{
		"type":    "message",
		"summary": m.title(),
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content":     card,
		}},
	}
}

// slack returns a Slack message: a fallback text (stripped of the
// characters Slack escapes) and blocks made of plain text only, so that no
// value is interpreted as markup.
func (m message) slack() map[string]any {
	blocks := []any{map[string]any{
		"type": "header", "text": map[string]any{"type": "plain_text", "text": m.title()},
	}}
	facts := m.facts()
	for i := 0; i < len(facts); i += slackFieldsPerSection {
		fields := []any{}
		for _, f := range facts[i:min(i+slackFieldsPerSection, len(facts))] {
			fields = append(fields, map[string]any{"type": "plain_text", "text": f.name + ": " + f.value})
		}
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	if m.adminURL != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{map[string]any{
			"type": "button", "text": map[string]any{"type": "plain_text", "text": adminLinkText}, "url": m.adminURL,
		}}})
	}
	text := m.title() + " (" + safeText(string(m.ev.Severity), maxNameRunes) + ")"
	if m.tenant != nil {
		text += " - " + safeText(m.tenant.Name, maxNameRunes)
	}
	return map[string]any{"text": text, "blocks": blocks}
}

// markupRunes are the characters that Teams and Slack may interpret as
// markup (links, emphasis, mentions); they are replaced by a space in the
// values of the messages.
const markupRunes = "<>[]()*_~`#|&\\"

// safeText returns s without control characters nor markup characters,
// with its runs of spaces collapsed, cut to at most n runes (an ellipsis marks a
// cut). Invalid UTF-8 is replaced.
func safeText(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || strings.ContainsRune(markupRunes, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "\u2026"
	}
	return s
}
