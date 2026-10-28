package transfer

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// policy is the outcome of the tenant policies applied to a validated
// creation request (spec 8.3 and 8.4).
type policy struct {
	// level is the confidentiality level of the transfer, nil when the
	// tenant has none (never the case once migrated: every tenant is seeded
	// with levels and keeps at least one).
	level *store.ConfidentialityLevel
	// maxDownloads is the download limit to store: the requested one, or
	// the cap of the level when the sender gave none.
	maxDownloads *int
	// deleteAfterFirstDownload is the requested option, forced by the
	// level when it says so.
	deleteAfterFirstDownload bool
}

// pickLevel returns the level key of levels, or the default level when key
// is "". An unknown key is a *ValidationError on FieldConfidentialityLevel
// (CodeNotAllowed). A tenant without any level gets nil: the transfer is
// created without level.
func pickLevel(levels []store.ConfidentialityLevel, key string) (*store.ConfidentialityLevel, error) {
	for i := range levels {
		if (key == "" && levels[i].IsDefault) || (key != "" && levels[i].Key == key) {
			return &levels[i], nil
		}
	}
	if key == "" {
		return nil, nil
	}
	return nil, &ValidationError{Fields: []FieldError{{Pointer: FieldConfidentialityLevel, Code: CodeNotAllowed}}}
}

// checkLevelRules returns the rules of level that the request breaks, in
// the order of the confidentiality-rule-violated examples of the
// specification: password, recipient verification, validity (with the
// allowed ones), each recipient outside the internal domains of rules, and
// a download limit above the cap. recipients are the normalized recipients
// of the plan (the inviter for an external sender).
func checkLevelRules(level *store.ConfidentialityLevel, req CreateRequest, recipients []string, rules netpolicy.Rules) []FieldError {
	if level == nil {
		return nil
	}
	r := level.Rules
	var out []FieldError
	if r.RequirePassword && req.Password == nil {
		out = append(out, FieldError{Pointer: FieldPassword, Code: CodeRequired})
	}
	if r.RequireRecipientVerification && !req.RecipientVerification {
		out = append(out, FieldError{Pointer: FieldRecipientVerification, Code: CodeRequired})
	}
	if !r.AllowsExpiry(req.ExpiryDays) {
		out = append(out, FieldError{Pointer: FieldExpiryDays, Code: CodeNotAllowed, Allowed: r.AllowedExpiryDays()})
	}
	if r.InternalRecipientsOnly {
		for i, rcpt := range recipients {
			if !netpolicy.DomainInternal(rules, rcpt) {
				out = append(out, FieldError{Pointer: FieldRecipients + "/" + strconv.Itoa(i), Code: CodeInternalOnly})
			}
		}
	}
	// Without a limit, the cap of the level is applied (see applyLevel):
	// only an explicit limit above it is refused.
	if req.MaxDownloads != nil && !r.AllowsMaxDownloads(req.MaxDownloads) {
		out = append(out, FieldError{Pointer: FieldMaxDownloads, Code: CodeMaxExceeded})
	}
	return out
}

// applyLevel returns the download limit and the deletion option of a
// request that satisfies level: the cap of the level when the sender gave
// no limit, and the deletion after the first download when the level
// forces it.
func applyLevel(level *store.ConfidentialityLevel, req CreateRequest) policy {
	p := policy{level: level, maxDownloads: req.MaxDownloads, deleteAfterFirstDownload: req.DeleteAfterFirstDownload}
	if level == nil {
		return p
	}
	if p.maxDownloads == nil && level.Rules.MaxDownloadsCap != nil {
		c := *level.Rules.MaxDownloadsCap
		p.maxDownloads = &c
	}
	p.deleteAfterFirstDownload = p.deleteAfterFirstDownload || level.Rules.ForceDeleteAfterFirstDownload
	return p
}

// refusedRecipients applies the recipient domain rules set to recipients
// and returns one CodeDomainDenied field per refused recipient, with the
// distinct refused domains, sorted.
func refusedRecipients(recipients []string, set store.RecipientRuleSet) ([]FieldError, []string) {
	var (
		fields  []FieldError
		domains []string
	)
	for i, rcpt := range recipients {
		domain := rcpt[strings.LastIndexByte(rcpt, '@')+1:]
		if netpolicy.RecipientDomainAllowed(domain, set.Allowed, set.Denied) {
			continue
		}
		fields = append(fields, FieldError{Pointer: FieldRecipients + "/" + strconv.Itoa(i), Code: CodeDomainDenied})
		if d, err := netpolicy.NormalizeDomain(domain); err == nil {
			domain = d
		}
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	return fields, slices.Compact(domains)
}

// applyPolicies applies the confidentiality level and the recipient domain
// rules of tenant t to the validated request req of sender (normalized
// address email), whose plan holds the final recipients (the inviter for an
// external sender: the checks still run, generically, for every kind of
// sender). Steps, in order:
//
//  1. the level: the default one when req names none, an unknown key is a
//     *ValidationError (400);
//  2. its rules: every broken rule at once, as a *RuleError matching
//     ErrConfidentialityRule (422);
//  3. the recipient domain rules: every refused recipient at once, as a
//     *RuleError matching ErrRecipientDomainRefused (403), recorded as
//     transfer.recipient_refused with the refused domains only (no
//     address), never in the security log: it is a policy refusal, not a
//     sign of attack.
//
// The levels and the rules are read just before the creation transaction,
// not inside it: the checks then run before the password is hashed and
// without holding the tenant lock. A level replaced in between is seen as
// if the request had arrived just before the change; the transfer keeps
// the snapshot that was checked.
func (s *Service) applyPolicies(ctx context.Context, t *tenant.Tenant, sender Sender, email string, req CreateRequest, recipients []string) (policy, error) {
	levels, err := s.repo.confidentialityLevels(ctx, t.ID)
	if err != nil {
		return policy{}, fmt.Errorf("transfer: read confidentiality levels: %w", err)
	}
	level, err := pickLevel(levels, req.ConfidentialityLevel)
	if err != nil {
		return policy{}, err
	}
	var rules netpolicy.Rules
	if level != nil && level.Rules.InternalRecipientsOnly {
		nr, err := s.repo.networkRules(ctx, t.ID)
		if err != nil {
			return policy{}, fmt.Errorf("transfer: read network rules: %w", err)
		}
		rules = netpolicy.Rules{Domains: nr.Domains}
	}
	if broken := checkLevelRules(level, req, recipients, rules); len(broken) > 0 {
		return policy{}, &RuleError{Kind: ErrConfidentialityRule, Fields: broken}
	}
	if sender.Kind == store.DepositorExternal {
		// An invited external depositor has no free choice of recipient: the
		// only one is the inviting internal user. Applying the domain rules
		// would block every invitation under an allow list that leaves out
		// the internal domains, so they only bind free recipients.
		return applyLevel(level, req), nil
	}
	set, err := s.repo.recipientRules(ctx, t.ID)
	if err != nil {
		return policy{}, fmt.Errorf("transfer: read recipient rules: %w", err)
	}
	if fields, domains := refusedRecipients(recipients, set); len(fields) > 0 {
		kind, actor := actorOf(sender, email)
		s.write(ctx, t, audit.Event{
			ActorKind: kind, Actor: actor, IP: sender.ClientIP, Action: audit.ActionTransferRecipientRefused,
			ObjectKind: audit.ObjectTenant, ObjectID: t.ID.String(),
			Details: map[string]any{"domains": domains, "origin": origin(sender)},
		})
		return policy{}, &RuleError{Kind: ErrRecipientDomainRefused, Fields: fields}
	}
	return applyLevel(level, req), nil
}

// snapshot writes the level of p, its labels and its rules into rec,
// with the download limit and the deletion option p settled on. The copies
// share nothing with the level read from the store.
func (p policy) snapshot(rec *store.Transfer) {
	rec.MaxDownloads, rec.DeleteAfterFirstDownload = p.maxDownloads, p.deleteAfterFirstDownload
	if p.level == nil {
		return
	}
	rules := p.level.Rules
	if c := rules.MaxDownloadsCap; c != nil {
		v := *c
		rules.MaxDownloadsCap = &v
	}
	labels := maps.Clone(p.level.Labels)
	rec.ConfidentialityLevel, rec.ConfidentialityLabel, rec.Rules = p.level.Key, labels, &rules
}
