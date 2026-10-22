package tenantadmin

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestCheckMailDNS(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	_, err := ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, nil)
	wantErr(t, "no settings", err, ErrNotFound)
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, relay(), clientIP)
	mustNoErr(t, "settings", err)

	const d = "entity-a.example.com"
	r := ev.resolver
	r.txt[d] = []string{"google-site-verification=x", "v=spf1 include:spf.example.net -all"}
	r.txt["_dmarc."+d] = []string{"v=DMARC1; p=reject; rua=mailto:d@example.com"}
	r.txt["s1._domainkey."+d] = []string{"v=DKIM1; k=rsa; p=MIGf"}
	r.txtErr["s2._domainkey."+d] = errBoom

	c, err := ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, []string{"s1", "s2", "s3"})
	mustNoErr(t, "check", err)
	if c.Domain != d || c.SPF.Status != DNSOK || c.SPF.Record != "v=spf1 include:spf.example.net -all" ||
		c.DMARC.Status != DNSOK || c.DKIM.Status != DNSOK || len(c.DKIM.Selectors) != 3 ||
		!c.DKIM.Selectors[0].Found || c.DKIM.Selectors[1].Found {
		t.Fatalf("check: %+v", c)
	}

	// Warnings, missing records and lookup errors.
	r.txt[d] = []string{"v=spf1 +all"}
	r.txt["_dmarc."+d] = []string{"v=DMARC1;p=none"}
	c, err = ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, []string{"s3"})
	mustNoErr(t, "check", err)
	if c.SPF.Status != DNSWarning || c.DMARC.Status != DNSWarning || c.DKIM.Status != DNSMissing {
		t.Fatalf("warnings: %+v", c)
	}
	r.txt[d] = []string{"v=spf1 -all", "V=SPF1 ~all"}
	delete(r.txt, "_dmarc."+d)
	c, err = ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, []string{"s2"})
	mustNoErr(t, "check", err)
	if c.SPF.Status != DNSWarning || !strings.Contains(c.SPF.Message, "Several") ||
		c.DMARC.Status != DNSMissing || c.DKIM.Status != DNSError {
		t.Fatalf("several/missing: %+v", c)
	}
	r.txtErr[d] = errBoom
	r.txt["_dmarc."+d] = []string{"v=DMARC1x", "unrelated"}
	c, err = ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, nil)
	mustNoErr(t, "check", err)
	if c.SPF.Status != DNSError || c.DMARC.Status != DNSMissing || c.DKIM.Status != DNSWarning || c.DKIM.Selectors == nil {
		t.Fatalf("errors: %+v", c)
	}

	_, err = ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, []string{"a", "b", "c", "d", "e", "f"})
	wantInvalid(t, "too many", err, FieldDKIMSelector)
	for _, bad := range []string{"", "-a", "a..b", "a b", strings.Repeat("a", 64), "a_b"} {
		_, err = ev.svc.CheckMailDNS(ctx, ev.adminA, ev.a.ID, []string{bad})
		wantInvalid(t, "selector "+bad, err, FieldDKIMSelector)
	}
	_, err = ev.svc.CheckMailDNS(ctx, ev.adminB, ev.a.ID, nil)
	wantErr(t, "other tenant", err, ErrNotFound)
}

func TestCleanRecord(t *testing.T) {
	got := cleanRecord("v=spf1" + string(rune(0)) + " a" + string(rune(0x202e)) + strings.Repeat("x", 600) + string([]byte{0xff}))
	if strings.ContainsRune(got, 0) || strings.ContainsRune(got, rune(0x202e)) || len([]rune(got)) != maxRecordLen {
		t.Fatalf("cleanRecord: %q", got)
	}
}
