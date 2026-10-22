package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// customMark marks the subject and the text of the customized templates.
const customMark = "[Custom A]"

// customSource returns the default source of template name in lang with
// customMark added to the subject and the text.
func customSource(t *testing.T, name, lang string) *mail.TemplateSource {
	t.Helper()
	src, err := mail.DefaultSource(name, lang)
	if err != nil {
		t.Fatal(err)
	}
	src.Subject = customMark + " " + src.Subject
	src.Text = customMark + "\n" + src.Text
	return &src
}

// mapLookup serves the customized templates of tenant "ten_a" in every
// language, records the calls and fails with err when set.
type mapLookup struct {
	t     *testing.T
	err   error
	calls []string
}

func (l *mapLookup) lookup(_ context.Context, tenantID, name, lang string) (*mail.TemplateSource, error) {
	l.calls = append(l.calls, tenantID+"/"+name+"/"+lang)
	if l.err != nil {
		return nil, l.err
	}
	if tenantID != "ten_a" {
		return nil, nil
	}
	return customSource(l.t, name, lang), nil
}

// mailKinds builds every kind of mail of the notifier for tenant tn.
func mailKinds(n *Notifier, tn *tenant.Tenant) map[string]func() ([]mail.Job, error) {
	ctx := context.Background()
	tr := testTransfer()
	one := func(j mail.Job, err error) ([]mail.Job, error) { return []mail.Job{j}, err }
	return map[string]func() ([]mail.Job, error){
		mail.TemplateTransferNotification: func() ([]mail.Job, error) { return n.RecipientJobs(ctx, tn, tr, testLink) },
		mail.TemplateTransferConfirmation: func() ([]mail.Job, error) { return one(n.SenderConfirmation(ctx, tn, tr, testLink)) },
		mail.TemplateFileProblems:         func() ([]mail.Job, error) { return one(n.FileProblems(ctx, tn, tr)) },
		mail.TemplateFileNotScanned:       func() ([]mail.Job, error) { return one(n.FileNotScanned(ctx, tn, tr)) },
		mail.TemplateFirstDownload: func() ([]mail.Job, error) {
			return one(n.FirstDownload(ctx, tn, tr, testNow, time.Time{}))
		},
		mail.TemplateQuotaWarning: func() ([]mail.Job, error) {
			return n.QuotaAlert(ctx, tn, testQuotaData(), QuotaWarning, []Contact{{Email: "admin@entity-a.example.com"}})
		},
		mail.TemplateQuotaReached: func() ([]mail.Job, error) {
			return n.QuotaAlert(ctx, tn, testQuotaData(), QuotaReached, []Contact{{Email: "admin@entity-a.example.com"}})
		},
	}
}

// TestCustomizedTemplates checks that every mail of a tenant uses its
// customized template, and that another tenant keeps the default.
func TestCustomizedTemplates(t *testing.T) {
	l := &mapLookup{t: t}
	e := newEnv(t)
	e.n = New(e.vault, e.smtp, nil, Options{Now: func() time.Time { return testNow }, Overrides: l.lookup})
	tenantB := &tenant.Tenant{ID: "ten_b", Name: "Entity B", DefaultLanguage: "en"}
	for _, tc := range []struct {
		tn     *tenant.Tenant
		custom bool
	}{{e.t, true}, {tenantB, false}} {
		for name, build := range mailKinds(e.n, tc.tn) {
			l.calls = nil
			jobs, err := build()
			if err != nil {
				t.Fatalf("%s/%s: %v", tc.tn.ID, name, err)
			}
			for _, j := range jobs {
				got := strings.HasPrefix(j.Message.Subject, customMark) && strings.HasPrefix(j.Message.Text, customMark)
				if got != tc.custom || j.Template != name {
					t.Errorf("%s/%s: customized %v, want %v (subject %q)", tc.tn.ID, name, got, tc.custom, j.Message.Subject)
				}
			}
			want := fmt.Sprintf("%s/%s/%s", tc.tn.ID, name, tc.tn.DefaultLanguage)
			if len(l.calls) != 1 || l.calls[0] != want {
				t.Errorf("%s/%s: lookups %v, want [%s]", tc.tn.ID, name, l.calls, want)
			}
		}
	}
}

// TestCustomizedTemplateLookupFailure checks that a lookup failure does not
// stop a mail: the default template is used and a warning names the tenant
// and the template.
func TestCustomizedTemplateLookupFailure(t *testing.T) {
	l := &mapLookup{t: t, err: errors.New("database down")}
	var logs bytes.Buffer
	e := newEnv(t)
	e.n = New(e.vault, e.smtp, nil, Options{
		Now: func() time.Time { return testNow }, Overrides: l.lookup,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	for name, build := range mailKinds(e.n, e.t) {
		logs.Reset()
		jobs, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, j := range jobs {
			if strings.Contains(j.Message.Subject, customMark) {
				t.Errorf("%s: customized subject %q despite the lookup failure", name, j.Message.Subject)
			}
		}
		out := logs.String()
		for _, s := range []string{"level=WARN", "tenant=ten_a", "template=" + name, "language=fr", "database down"} {
			if !strings.Contains(out, s) {
				t.Errorf("%s: log lacks %q: %s", name, s, out)
			}
		}
		if strings.Contains(out, "@") {
			t.Errorf("%s: log holds an address: %s", name, out)
		}
	}
}

// fakeTemplates is a TemplateStore over a map keyed by tenant/key/lang.
type fakeTemplates struct {
	rows map[string]store.EmailTemplate
	err  error
}

func (f fakeTemplates) Get(_ context.Context, tid tenant.ID, key, lang string) (store.EmailTemplate, error) {
	if f.err != nil {
		return store.EmailTemplate{}, f.err
	}
	r, ok := f.rows[tid.String()+"/"+key+"/"+lang]
	if !ok {
		return store.EmailTemplate{}, fmt.Errorf("get: %w", store.ErrNotFound)
	}
	return r, nil
}

func TestStoreOverrides(t *testing.T) {
	const tidA, tidB = "ten_01HZY3K5V7W9XBCDFGHJKMNPQR", "ten_01HZY3K5V7W9XBCDFGHJKMNPQS"
	ctx := context.Background()
	src := fakeTemplates{rows: map[string]store.EmailTemplate{
		tidA + "/transfer-notification/en": {Subject: "S", BodyHTML: "<p>H</p>", BodyText: "T"},
	}}
	lookup := StoreOverrides(src)
	got, err := lookup(ctx, tidA, mail.TemplateTransferNotification, "en")
	if err != nil || got == nil || *got != (mail.TemplateSource{Subject: "S", HTML: "<p>H</p>", Text: "T"}) {
		t.Errorf("customized: %+v, %v", got, err)
	}
	for _, c := range [][3]string{
		{tidB, mail.TemplateTransferNotification, "en"}, // other tenant
		{tidA, mail.TemplateTransferNotification, "fr"}, // other language
		{tidA, mail.TemplateFileProblems, "en"},         // other template
	} {
		if got, err := lookup(ctx, c[0], c[1], c[2]); got != nil || err != nil {
			t.Errorf("%v: %+v, %v, want the default", c, got, err)
		}
	}
	if _, err := lookup(ctx, "not a tenant id", mail.TemplateTransferNotification, "en"); err == nil {
		t.Error("invalid tenant ID accepted")
	}
	boom := errors.New("boom")
	if _, err := StoreOverrides(fakeTemplates{err: boom})(ctx, tidA, mail.TemplateFirstDownload, "en"); !errors.Is(err, boom) {
		t.Errorf("store failure: %v", err)
	}
}

func TestTolerantOverrides(t *testing.T) {
	ctx := context.Background()
	if got, err := TolerantOverrides(nil, nil)(ctx, "ten_a", mail.TemplateFirstDownload, "en"); got != nil || err != nil {
		t.Errorf("nil lookup: %+v, %v", got, err)
	}
	if got, err := NoOverrides(ctx, "ten_a", mail.TemplateFirstDownload, "en"); got != nil || err != nil {
		t.Errorf("NoOverrides: %+v, %v", got, err)
	}
	// A nil logger discards the warning.
	failing := func(context.Context, string, string, string) (*mail.TemplateSource, error) {
		return nil, errors.New("boom")
	}
	if got, err := TolerantOverrides(failing, nil)(ctx, "ten_a", mail.TemplateFirstDownload, "en"); got != nil || err != nil {
		t.Errorf("failing lookup: %+v, %v", got, err)
	}
	want := &mail.TemplateSource{Subject: "S"}
	ok := func(context.Context, string, string, string) (*mail.TemplateSource, error) { return want, nil }
	if got, err := TolerantOverrides(ok, nil)(ctx, "ten_a", mail.TemplateFirstDownload, "en"); got != want || err != nil {
		t.Errorf("lookup: %+v, %v", got, err)
	}
}
