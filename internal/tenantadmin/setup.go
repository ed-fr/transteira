package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textproposals"
)

// ActionTenantSetupCompleted records the end of the setup of a tenant
// (details: forced, and the keys of the required items still missing when
// forced).
const ActionTenantSetupCompleted audit.Action = "tenant.setup_completed"

// Keys of the setup checklist (OpenAPI TenantSetupItemKey), in display
// order.
const (
	SetupBrandingLogo     = "branding_logo"
	SetupBrandingColors   = "branding_colors"
	SetupSMTP             = "smtp"
	SetupInternalNetworks = "internal_networks"
	SetupInternalDomains  = "internal_domains"
	SetupLegalNotice      = "legal_notice"
	SetupPrivacyPolicy    = "privacy_policy"
	SetupMailTemplates    = "mail_templates"
)

// ErrSetupComplete reports the completion of the setup of a tenant already
// active (409 setup-already-complete): there is no way back to the setup
// state.
var ErrSetupComplete = errors.New("tenantadmin: tenant setup already complete")

// ErrSetupIncomplete reports a completion refused because required items of
// the checklist are not done (409 setup-incomplete). The error is an
// *[IncompleteError] listing them.
var ErrSetupIncomplete = errors.New("tenantadmin: tenant setup incomplete")

// IncompleteError reports the required items of the setup checklist that
// are not done. It matches [ErrSetupIncomplete].
type IncompleteError struct {
	// Missing are the keys of the items, in checklist order.
	Missing []string
}

// Error implements error.
func (e *IncompleteError) Error() string {
	return "tenantadmin: tenant setup incomplete: " + strings.Join(e.Missing, ", ")
}

// Is makes errors.Is(err, ErrSetupIncomplete) true.
func (e *IncompleteError) Is(target error) bool { return target == ErrSetupIncomplete }

// SetupItem is an item of the setup checklist (OpenAPI TenantSetupItem).
type SetupItem struct {
	// Key is one of the Setup* keys.
	Key string
	// Required tells that the setup cannot be completed, unless forced,
	// while the item is not done.
	Required bool
	// Done is computed from the real configuration of the tenant.
	Done bool
}

// Setup is the setup state of a tenant with its checklist (OpenAPI
// TenantSetup).
type Setup struct {
	State tenant.SetupState
	Items []SetupItem
	// CanComplete tells that every required item is done.
	CanComplete bool
}

// missing returns the keys of the required items not done.
func (s Setup) missing() []string {
	var out []string
	for _, it := range s.Items {
		if it.Required && !it.Done {
			out = append(out, it.Key)
		}
	}
	return out
}

// GetSetup returns the setup state and checklist of tenant tid, computed
// from its real configuration (T-262), whatever its state: an active tenant
// keeps its checklist, for information. The super admin and the delegated
// admins of the tenant may read it; another tenant answers ErrNotFound, as
// an unknown one (T-263).
func (s *Service) GetSetup(ctx context.Context, p adminauth.Principal, tid tenant.ID) (Setup, error) {
	t, err := s.readable(ctx, p, tid)
	if err != nil {
		return Setup{}, err
	}
	return s.checklist(ctx, t)
}

// CompleteSetup moves tenant tid from the setup state to the active state:
// its public operations are open from then on (the resolution cache is
// invalidated at once). The super admin and the delegated admins of the
// tenant may complete it; another tenant answers ErrNotFound, as an unknown
// one. Unless force is set, every required item of the checklist must be
// done, else an *[IncompleteError]; force is reserved to the super admin
// (ErrForbidden for a delegated admin). The items are computed by the
// server just before the change, and the SMTP item is checked again by the
// statement that changes the state ([store.Tenants.CompleteSetup]) with the
// network rules and the presence of the legal documents: a change racing the
// completion makes it fail, and the checklist is computed again to report
// the items missing. Only the absence of "to complete" markers in the legal
// documents is checked here alone, just before the statement. mailTemplatesReviewed records
// the review of the mail templates (optional item). A tenant already active
// answers ErrSetupComplete. The completion is audited as
// tenant.setup_completed with details forced (and, when forced, the keys of
// the required items still missing). For a tenant created through the
// provisioning API, the tenant.setup_completed system event is also
// published and the super admins notified (Options.Events,
// Options.Notifier; P50). It returns the checklist of the active tenant.
func (s *Service) CompleteSetup(ctx context.Context, p adminauth.Principal, tid tenant.ID, force, mailTemplatesReviewed bool,
	ip netip.Addr,
) (Setup, error) {
	t, err := s.writable(ctx, p, tid)
	if err != nil {
		return Setup{}, err
	}
	if force && superAdmin(p) != nil {
		return Setup{}, ErrForbidden
	}
	if t.SetupState == tenant.SetupStateActive {
		return Setup{}, ErrSetupComplete
	}
	before, err := s.checklist(ctx, t)
	if err != nil {
		return Setup{}, err
	}
	missing := before.missing()
	if !force && len(missing) > 0 {
		return Setup{}, &IncompleteError{Missing: missing}
	}
	var reviewedAt time.Time
	if mailTemplatesReviewed {
		reviewedAt = s.now()
	}
	done, err := s.repo.completeSetup(ctx, tid, force, reviewedAt)
	switch {
	case errors.Is(err, store.ErrSetupComplete):
		return Setup{}, ErrSetupComplete
	case errors.Is(err, store.ErrNotFound):
		return Setup{}, ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return Setup{}, s.recomputeMissing(ctx, tid)
	case err != nil:
		return Setup{}, fmt.Errorf("tenantadmin: complete tenant setup: %w", err)
	}
	s.invalidate(done.ID, done.FQDN)
	details := map[string]any{"forced": force}
	if force && len(missing) > 0 {
		details["missing"] = missing
	}
	s.record(ctx, p, ip, done.ID, ActionTenantSetupCompleted, details)
	s.setupCompleted(ctx, done, force && len(missing) > 0, ip)
	return s.checklist(ctx, done)
}

// recomputeMissing returns the error of a completion whose guards failed:
// the *IncompleteError of the checklist computed again. When the new
// checklist is complete (the configuration changed and was completed again
// meanwhile, typically the SMTP settings tested anew), the SMTP item is
// reported: the caller may simply retry.
func (s *Service) recomputeMissing(ctx context.Context, tid tenant.ID) error {
	t, err := s.activeTenant(ctx, tid)
	if err != nil {
		return err
	}
	if t.SetupState == tenant.SetupStateActive {
		return ErrSetupComplete
	}
	c, err := s.checklist(ctx, t)
	if err != nil {
		return err
	}
	missing := c.missing()
	if len(missing) == 0 {
		missing = []string{SetupSMTP}
	}
	return &IncompleteError{Missing: missing}
}

// checklist computes the setup checklist of t from its configuration.
func (s *Service) checklist(ctx context.Context, t *tenant.Tenant) (Setup, error) {
	smtp, err := s.smtpTested(ctx, t)
	if err != nil {
		return Setup{}, err
	}
	rules, err := s.repo.networkRules(ctx, t.ID)
	if err != nil {
		return Setup{}, fmt.Errorf("tenantadmin: get network rules: %w", err)
	}
	notice, err := s.legalWritten(ctx, t, store.LegalNotice)
	if err != nil {
		return Setup{}, err
	}
	policy, err := s.legalWritten(ctx, t, store.PrivacyPolicy)
	if err != nil {
		return Setup{}, err
	}
	out := Setup{State: t.SetupState, Items: []SetupItem{
		{Key: SetupBrandingLogo, Done: t.HasLogo},
		{Key: SetupBrandingColors, Done: !strings.EqualFold(t.PrimaryColor, tenant.DefaultPrimaryColor) ||
			!strings.EqualFold(t.AccentColor, tenant.DefaultAccentColor)},
		{Key: SetupSMTP, Required: true, Done: smtp},
		{Key: SetupInternalNetworks, Required: true, Done: len(rules.CIDRs) > 0},
		{Key: SetupInternalDomains, Required: true, Done: len(rules.Domains) > 0},
		{Key: SetupLegalNotice, Required: true, Done: notice},
		{Key: SetupPrivacyPolicy, Required: true, Done: policy},
		{Key: SetupMailTemplates, Done: !t.MailTemplatesReviewedAt.IsZero()},
	}}
	out.CanComplete = len(out.missing()) == 0
	return out, nil
}

// smtpTested reports whether t has SMTP settings that passed a test send
// since their last change: the stamp recorded by the test equals their
// modification time ([store.Tenants.SetSMTPTested]).
func (s *Service) smtpTested(ctx context.Context, t *tenant.Tenant) (bool, error) {
	c, err := s.repo.smtp(ctx, t.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("tenantadmin: get smtp settings: %w", err)
	}
	return !t.SMTPTestedAt.IsZero() && t.SMTPTestedAt.Equal(c.UpdatedAt), nil
}

// legalWritten reports whether the legal document doc of t is written in
// the default language of t, without any "to complete" marker left from a
// text proposal.
func (s *Service) legalWritten(ctx context.Context, t *tenant.Tenant, doc string) (bool, error) {
	d, err := s.repo.legal(ctx, t.ID, doc, t.DefaultLanguage)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("tenantadmin: get legal document: %w", err)
	}
	return strings.TrimSpace(d.Content) != "" && !textproposals.HasPlaceholder(d.Content), nil
}

// TextProposal is a proposal of a legal text (OpenAPI TextProposal).
type TextProposal struct {
	Document string
	Language string
	// Markdown is the proposed text, in the limited Markdown of the legal
	// documents; it is never saved by the service.
	Markdown string
	// Notice is the translation key of the review warning to show with it.
	Notice string
}

// TextProposal returns a proposal of the legal document doc
// (store.LegalNotice or store.PrivacyPolicy) in lang for tenant tid,
// filled with its real configuration: name, FQDN, the transfer durations
// its confidentiality levels allow, the retention of the verified
// addresses (store.VerifiedRetentionMonths), of the invitations
// (store.InvitationValidityMonths) and of the logs
// (lifecycle.AuditRetentionMonths), and whether its antivirus is effective.
// Nothing is saved (T-265): the administrator publishes the reviewed text
// with [Service.UpdateLegal]. An unknown document or language answers
// ErrNotFound, like a tenant the caller may not read.
func (s *Service) TextProposal(ctx context.Context, p adminauth.Principal, tid tenant.ID, doc, lang string) (TextProposal, error) {
	if err := checkLegal(doc, lang); err != nil {
		return TextProposal{}, err
	}
	t, err := s.readable(ctx, p, tid)
	if err != nil {
		return TextProposal{}, err
	}
	levels, err := s.repo.confidentialityLevels(ctx, t.ID)
	if err != nil {
		return TextProposal{}, fmt.Errorf("tenantadmin: get confidentiality levels: %w", err)
	}
	var days []int
	for _, l := range levels {
		days = append(days, l.Rules.AllowedExpiryDays()...)
	}
	slices.Sort(days)
	md, err := s.propose(doc, lang, textproposals.Facts{
		TenantName: t.Name, FQDN: t.FQDN, ValidityDays: slices.Compact(days),
		VerifiedRetentionMonths:   store.VerifiedRetentionMonths,
		InvitationRetentionMonths: store.InvitationValidityMonths,
		LogRetentionMonths:        lifecycle.AuditRetentionMonths,
		AntivirusEnabled:          s.AntivirusEffective(t),
	})
	if err != nil {
		// checkLegal already refused what textproposals does not know: a
		// failure here is an internal inconsistency.
		return TextProposal{}, fmt.Errorf("tenantadmin: text proposal: %w", err)
	}
	return TextProposal{Document: doc, Language: lang, Markdown: md, Notice: textproposals.NoticeKey}, nil
}
