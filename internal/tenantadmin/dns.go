package tenantadmin

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/tenant"
)

// DNS check statuses (OpenAPI DnsRecordCheck.status).
const (
	DNSOK      = "ok"
	DNSWarning = "warning"
	DNSMissing = "missing"
	DNSError   = "error"
)

// Bounds of the mail DNS check.
const (
	// MaxDKIMSelectors bounds the DKIM selectors probed by one check.
	MaxDKIMSelectors = 5
	// maxSelectorLen bounds a DKIM selector.
	maxSelectorLen = 63
	// maxRecordLen bounds a DNS record returned by the check, in
	// characters.
	maxRecordLen = 512
)

// selectorPattern is the syntax of a DKIM selector: DNS labels of letters,
// digits and inner hyphens, separated by dots.
var selectorPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// DNSRecordCheck is the check of one DNS record (OpenAPI DnsRecordCheck).
type DNSRecordCheck struct {
	Status string
	// Record is the record found, sanitized and truncated.
	Record string
	// Message explains a warning or an error, in English.
	Message string
}

// DKIMSelectorCheck tells whether a DKIM selector has a key record.
type DKIMSelectorCheck struct {
	Selector string
	Found    bool
}

// DKIMCheck is the check of the DKIM selectors.
type DKIMCheck struct {
	Status    string
	Selectors []DKIMSelectorCheck
}

// MailDNSCheck is the indicative mail DNS check of a sender domain
// (OpenAPI MailDnsCheck).
type MailDNSCheck struct {
	Domain string
	SPF    DNSRecordCheck
	DKIM   DKIMCheck
	DMARC  DNSRecordCheck
}

// CheckMailDNS checks the SPF, DKIM and DMARC records of the domain of the
// sender address of tenant tid (spec 12.1). DKIM selectors cannot be
// discovered: up to MaxDKIMSelectors are probed. Each lookup is bounded by
// a short timeout; the result is informational only. It returns
// ErrNotFound when the tenant has no SMTP settings.
func (s *Service) CheckMailDNS(ctx context.Context, p adminauth.Principal, tid tenant.ID, selectors []string) (MailDNSCheck, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return MailDNSCheck{}, err
	}
	if len(selectors) > MaxDKIMSelectors {
		return MailDNSCheck{}, invalid(FieldDKIMSelector, "at most %d selectors", MaxDKIMSelectors)
	}
	for _, sel := range selectors {
		if len(sel) > maxSelectorLen || !selectorPattern.MatchString(sel) {
			return MailDNSCheck{}, invalid(FieldDKIMSelector, "must be DNS labels of at most %d characters", maxSelectorLen)
		}
	}
	c, err := s.smtpConfig(ctx, tid)
	if err != nil {
		return MailDNSCheck{}, err
	}
	domain := c.FromAddress[strings.LastIndexByte(c.FromAddress, '@')+1:]
	return MailDNSCheck{
		Domain: domain,
		SPF:    s.checkSPF(ctx, domain),
		DKIM:   s.checkDKIM(ctx, domain, selectors),
		DMARC:  s.checkDMARC(ctx, "_dmarc."+domain),
	}, nil
}

// lookupTXT returns the TXT records of name with the DNS timeout, and
// whether the name exists. An error other than a missing name is returned.
func (s *Service) lookupTXT(ctx context.Context, name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.dnsTimeout)
	defer cancel()
	recs, err := s.resolver.LookupTXT(ctx, name)
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		return nil, nil
	}
	return recs, err
}

// tagged returns the records starting with the version tag (followed by a
// space, a semicolon or the end), compared case-insensitively.
func tagged(recs []string, tag string) []string {
	var out []string
	for _, r := range recs {
		r = strings.TrimSpace(r)
		if len(r) >= len(tag) && strings.EqualFold(r[:len(tag)], tag) &&
			(len(r) == len(tag) || r[len(tag)] == ' ' || r[len(tag)] == ';') {
			out = append(out, r)
		}
	}
	return out
}

// recordCheck evaluates the records carrying tag: missing, error, several
// records, or the verdict of judge on the only one.
func (s *Service) recordCheck(ctx context.Context, name, tag, what string, judge func(rec string) (string, string)) DNSRecordCheck {
	recs, err := s.lookupTXT(ctx, name)
	if err != nil {
		return DNSRecordCheck{Status: DNSError, Message: "DNS lookup failed."}
	}
	found := tagged(recs, tag)
	switch len(found) {
	case 0:
		return DNSRecordCheck{Status: DNSMissing, Message: "No " + what + " record."}
	case 1:
		status, msg := judge(found[0])
		return DNSRecordCheck{Status: status, Record: cleanRecord(found[0]), Message: msg}
	}
	return DNSRecordCheck{
		Status: DNSWarning, Record: cleanRecord(found[0]),
		Message: "Several " + what + " records: receivers treat this as an error.",
	}
}

// checkSPF checks the SPF record of domain.
func (s *Service) checkSPF(ctx context.Context, domain string) DNSRecordCheck {
	return s.recordCheck(ctx, domain, "v=spf1", "SPF", func(rec string) (string, string) {
		for _, term := range strings.Fields(strings.ToLower(rec)) {
			if term == "+all" || term == "all" {
				return DNSWarning, "The record allows any sender (+all)."
			}
		}
		return DNSOK, ""
	})
}

// checkDMARC checks the DMARC record at name.
func (s *Service) checkDMARC(ctx context.Context, name string) DNSRecordCheck {
	return s.recordCheck(ctx, name, "v=DMARC1", "DMARC", func(rec string) (string, string) {
		for _, tag := range strings.Split(rec, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(tag), "=")
			if strings.EqualFold(strings.TrimSpace(k), "p") && strings.EqualFold(strings.TrimSpace(v), "none") {
				return DNSWarning, "Policy is p=none."
			}
		}
		return DNSOK, ""
	})
}

// checkDKIM probes the DKIM selectors of domain.
func (s *Service) checkDKIM(ctx context.Context, domain string, selectors []string) DKIMCheck {
	out := DKIMCheck{Status: DNSWarning, Selectors: []DKIMSelectorCheck{}}
	if len(selectors) == 0 {
		return out
	}
	found, failed := 0, 0
	for _, sel := range selectors {
		recs, err := s.lookupTXT(ctx, sel+"._domainkey."+domain)
		ok := false
		for _, r := range recs {
			if strings.Contains(strings.ToLower(r), "p=") {
				ok = true
			}
		}
		if err != nil {
			failed++
		}
		if ok {
			found++
		}
		out.Selectors = append(out.Selectors, DKIMSelectorCheck{Selector: sel, Found: ok})
	}
	switch {
	case found > 0:
		out.Status = DNSOK
	case failed == len(selectors):
		out.Status = DNSError
	default:
		out.Status = DNSMissing
	}
	return out
}

// cleanRecord removes the control characters of a DNS record and truncates
// it: DNS data is untrusted.
func cleanRecord(rec string) string {
	rec = strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(rec, "?"))
	if r := []rune(rec); len(r) > maxRecordLen {
		rec = string(r[:maxRecordLen])
	}
	return rec
}
