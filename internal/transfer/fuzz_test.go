package transfer

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/filename"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// FuzzValidate checks the invariants of the validation of a creation
// request: no panic, accepted names pass the file name policy, the total is
// never negative, recipients are normalized and unique, the message holds
// no hidden character and the fingerprint is deterministic. With an API
// token, an accepted sender address is a normalized plain address.
func FuzzValidate(f *testing.F) {
	f.Add("plans.pdf", "b.txt", int64(1), int64(2), "Dave@Customer.example.net,erin@customer.example.net",
		"Hello", 7, "pw", true, "fr", "")
	f.Add("../x", "CON", int64(-1), int64(9223372036854775807), "a@b.example.com,A@B.example.com",
		"x", 2, "", true, "de", "ABC")
	f.Add("a  .txt", "", int64(0), int64(0), "", "", 30, "", false, "", strings.Repeat("F", 64))
	f.Fuzz(func(t *testing.T, name1, name2 string, size1, size2 int64, rcpts, msg string,
		days int, pw string, withPw bool, lang, sum string,
	) {
		s := New(nil, nil, nil, nil, Options{MaxRecipients: store.MaxTransferRecipients})
		req := CreateRequest{
			Recipients: strings.Split(rcpts, ","), Message: msg, ExpiryDays: days, Language: lang,
			Files: []FileDeclaration{
				{Name: name1, Size: size1, ExpectedSHA256: sum},
				{Name: name2, Size: size2, MediaType: lang},
			},
		}
		if withPw {
			req.Password = &pw
		}
		tokReq := req
		tokReq.SenderEmail = strings.Split(rcpts, ",")[0]
		tok := Sender{Depositor: store.Depositor{Kind: store.DepositorInternal, APITokenID: id.New(id.APIToken)}}
		if tp, err := s.validate(tokReq, tok, ""); err == nil {
			if norm, err := store.NormalizeEmail(tp.sender); err != nil || norm != tp.sender || strings.ContainsAny(tp.sender, "<> ") {
				t.Fatalf("token sender %q is not a normalized plain address", tp.sender)
			}
		}
		p, err := s.validate(req, Sender{Depositor: store.Depositor{Kind: store.DepositorInternal}}, "")
		if err != nil {
			var verr *ValidationError
			if !errors.As(err, &verr) || len(verr.Fields) == 0 || !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate error %v is not a validation error", err)
			}
			return
		}
		if p.total < 0 {
			t.Fatalf("negative total %d", p.total)
		}
		for _, file := range p.files {
			if got, err := filename.Validate(file.Name); err != nil || got != file.Name {
				t.Fatalf("accepted name %q fails filename.Validate: %v", file.Name, err)
			}
		}
		seen := map[string]bool{}
		for _, r := range p.recipients {
			if norm, err := store.NormalizeEmail(r); err != nil || norm != r {
				t.Fatalf("recipient %q is not normalized", r)
			}
			if seen[r] {
				t.Fatalf("duplicate recipient %q", r)
			}
			seen[r] = true
		}
		if strings.ContainsFunc(p.message, textsafe.IsHidden) {
			t.Fatalf("message %q keeps a hidden character", p.message)
		}
		again, err := s.validate(req, Sender{Depositor: store.Depositor{Kind: store.DepositorInternal}}, "")
		if err != nil || fingerprint(p, req) != fingerprint(again, req) {
			t.Fatal("fingerprint is not deterministic")
		}
	})
}

// FuzzPolicies checks the invariants of the tenant policies applied to a
// creation request: no panic, every refused field names an existing
// recipient or a known option, the refused domains are sorted and unique,
// and a request satisfying the level keeps at most the cap and the forced
// deletion.
func FuzzPolicies(f *testing.F) {
	f.Add("carol@entity-a.example.com,dave@customer.example.net", "customer.example.net", "", 7, 3, 5, true, true)
	f.Add("x@Sub.Customer.Example.NET", "", "entity-a.example.com", 1, 0, 0, false, false)
	f.Add("a@b", "b", "b", 30, 1001, 1, true, false)
	f.Fuzz(func(t *testing.T, rcpts, denied, allowed string, days, maxDl, maxCap int, pw, internalOnly bool) {
		recipients := strings.Split(rcpts, ",")
		set := store.RecipientRuleSet{Denied: strings.Split(denied, ","), Allowed: strings.Split(allowed, ",")}
		if allowed == "" {
			set.Allowed = nil
		}
		fields, domains := refusedRecipients(recipients, set)
		if len(domains) > len(fields) || !slices.IsSorted(domains) || len(slices.Compact(slices.Clone(domains))) != len(domains) {
			t.Fatalf("domains %v for fields %v", domains, fields)
		}
		for _, fe := range fields {
			i, err := strconv.Atoi(strings.TrimPrefix(fe.Pointer, FieldRecipients+"/"))
			if err != nil || i < 0 || i >= len(recipients) || fe.Code != CodeDomainDenied {
				t.Fatalf("field %+v", fe)
			}
		}
		level := &store.ConfidentialityLevel{Key: "k", Rules: store.ConfidentialityRules{
			ExpiryDaysMask: store.ExpiryMaskAll &^ store.ExpiryMask30Days, RequirePassword: pw,
			InternalRecipientsOnly: internalOnly, ForceDeleteAfterFirstDownload: pw,
		}}
		if maxCap > 0 {
			level.Rules.MaxDownloadsCap = &maxCap
		}
		req := CreateRequest{ExpiryDays: days}
		if maxDl > 0 {
			req.MaxDownloads = &maxDl
		}
		broken := checkLevelRules(level, req, recipients, netpolicy.Rules{Domains: set.Allowed})
		if len(broken) > 0 {
			return
		}
		p := applyLevel(level, req)
		if maxCap > 0 && (p.maxDownloads == nil || *p.maxDownloads > maxCap) {
			t.Fatalf("limit %v above the cap %d", p.maxDownloads, maxCap)
		}
		if pw && !p.deleteAfterFirstDownload {
			t.Fatal("forced deletion lost")
		}
	})
}
