package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// JSON pointers of the confidentiality level and recipient rule bodies
// (OpenAPI ConfidentialityLevelList, RecipientRules).
const (
	FieldLevels         = "/items"
	FieldAllowedDomains = "/allowedDomains"
	FieldDeniedDomains  = "/deniedDomains"
)

// ConfidentialityRules are the rules a level imposes on a transfer
// (OpenAPI ConfidentialityRules).
type ConfidentialityRules struct {
	// AllowedExpiryDays is the non-empty subset of {1, 7, 30} of the
	// validities the level allows, ascending once stored.
	AllowedExpiryDays []int
	// MaxDownloads caps the maximum number of downloads, nil for none.
	MaxDownloads                  *int
	RequirePassword               bool
	RequireRecipientVerification  bool
	InternalRecipientsOnly        bool
	ForceDeleteAfterFirstDownload bool
}

// ConfidentialityLevel is a confidentiality level of a tenant (OpenAPI
// ConfidentialityLevel).
type ConfidentialityLevel struct {
	Key string
	// Labels are the names by language, every supported language set.
	Labels map[string]string
	// Descriptions are the optional explanations by language.
	Descriptions map[string]string
	IsDefault    bool
	Rules        ConfidentialityRules
}

// PublicConfidentialityLevel is a level as offered to the senders, with
// its label in one language (OpenAPI PublicConfidentialityLevel).
type PublicConfidentialityLevel struct {
	Key string
	// Label is the name in the language served.
	Label string
	// Description is the explanation in the language served, "" when none
	// is written.
	Description string
	IsDefault   bool
	Rules       ConfidentialityRules
}

// levelOf converts a stored level.
func levelOf(l store.ConfidentialityLevel) ConfidentialityLevel {
	r := l.Rules
	return ConfidentialityLevel{
		Key: l.Key, Labels: l.Labels, Descriptions: l.Descriptions, IsDefault: l.IsDefault,
		Rules: ConfidentialityRules{
			AllowedExpiryDays: r.AllowedExpiryDays(), MaxDownloads: r.MaxDownloadsCap,
			RequirePassword: r.RequirePassword, RequireRecipientVerification: r.RequireRecipientVerification,
			InternalRecipientsOnly: r.InternalRecipientsOnly, ForceDeleteAfterFirstDownload: r.ForceDeleteAfterFirstDownload,
		},
	}
}

// GetConfidentialityLevels returns the confidentiality levels of tenant
// tid, in display order.
func (s *Service) GetConfidentialityLevels(ctx context.Context, p adminauth.Principal, tid tenant.ID) ([]ConfidentialityLevel, error) {
	if _, err := s.readable(ctx, p, tid); err != nil {
		return nil, err
	}
	stored, err := s.repo.confidentialityLevels(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("tenantadmin: get confidentiality levels: %w", err)
	}
	out := make([]ConfidentialityLevel, len(stored))
	for i, l := range stored {
		out[i] = levelOf(l)
	}
	return out, nil
}

// UpdateConfidentialityLevels replaces the whole list of confidentiality
// levels of tenant tid and returns it. The list holds 1 to
// [store.MaxConfidentialityLevels] levels in display order, with distinct
// keys (lower-case letters, digits, "_" and "-", starting with a letter,
// 32 characters at most), exactly one default, labels in every supported
// language, and allowed validities that are a non-empty subset of {1, 7,
// 30}. A malformed value is an *InvalidError naming it, checked only once
// access to the tenant is granted. Past transfers keep their snapshot.
func (s *Service) UpdateConfidentialityLevels(ctx context.Context, p adminauth.Principal, tid tenant.ID, levels []ConfidentialityLevel, ip netip.Addr) ([]ConfidentialityLevel, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return nil, err
	}
	converted, err := levelsToStore(levels)
	if err != nil {
		return nil, err
	}
	stored, err := s.repo.replaceConfidentialityLevels(ctx, tid, converted, p.Admin.ID, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, ErrNotFound
	case errors.Is(err, store.ErrInvalid):
		// The checks above mirror the store's, so this cannot happen
		// unless they drift apart.
		return nil, invalid(FieldLevels, "invalid confidentiality levels")
	case err != nil:
		return nil, fmt.Errorf("tenantadmin: replace confidentiality levels: %w", err)
	}
	out := make([]ConfidentialityLevel, len(stored))
	keys := make([]string, len(stored))
	for i, l := range stored {
		out[i], keys[i] = levelOf(l), l.Key
	}
	s.record(ctx, p, ip, tid, ActionTenantConfidentialityUpdated, map[string]any{"keys": keys})
	return out, nil
}

// levelsToStore validates levels and converts them to the store form.
func levelsToStore(levels []ConfidentialityLevel) ([]store.ConfidentialityLevel, error) {
	if len(levels) < 1 || len(levels) > store.MaxConfidentialityLevels {
		return nil, invalid(FieldLevels, "must hold 1 to %d levels", store.MaxConfidentialityLevels)
	}
	out := make([]store.ConfidentialityLevel, len(levels))
	seen := map[string]bool{}
	defaults := 0
	for i, l := range levels {
		at := FieldLevels + "/" + strconv.Itoa(i)
		if !store.ValidLevelKey(l.Key) {
			return nil, invalid(at+"/key", "must match ^[a-z][a-z0-9_-]{0,%d}$", store.MaxLevelKeyLen-1)
		}
		if seen[l.Key] {
			return nil, invalid(at+"/key", "must be unique")
		}
		seen[l.Key] = true
		if err := checkLevelLabels(at, l.Labels); err != nil {
			return nil, err
		}
		for lang, d := range l.Descriptions {
			switch {
			case !tenant.IsLanguage(lang):
				return nil, invalid(at+"/descriptions", "unsupported language")
			case !utf8.ValidString(d) || utf8.RuneCountInString(d) > store.MaxLevelDescriptionRunes:
				return nil, invalid(at+"/descriptions/"+lang, "must hold at most %d characters", store.MaxLevelDescriptionRunes)
			}
		}
		if l.IsDefault {
			defaults++
			if defaults > 1 {
				return nil, invalid(at+"/isDefault", "only one level may be the default")
			}
		}
		rules, err := rulesToStore(at+"/rules", l.Rules)
		if err != nil {
			return nil, err
		}
		out[i] = store.ConfidentialityLevel{
			Key: l.Key, Position: i, Labels: l.Labels, Descriptions: l.Descriptions, IsDefault: l.IsDefault, Rules: rules,
		}
	}
	if defaults == 0 {
		return nil, invalid(FieldLevels, "one level must be the default")
	}
	return out, nil
}

// checkLevelLabels checks the labels of the level at pointer at: every
// supported language, no other, each a non-blank line of 1 to
// [store.MaxLevelLabelRunes] characters.
func checkLevelLabels(at string, labels map[string]string) error {
	for lang := range labels {
		if !tenant.IsLanguage(lang) {
			return invalid(at+"/labels", "unsupported language")
		}
	}
	for _, lang := range tenant.Languages() {
		l, ok := labels[lang]
		if !ok || strings.TrimSpace(l) == "" || !utf8.ValidString(l) ||
			utf8.RuneCountInString(l) > store.MaxLevelLabelRunes ||
			strings.IndexFunc(l, func(r rune) bool { return unicode.IsControl(r) || r == 0x2028 || r == 0x2029 }) >= 0 {
			return invalid(at+"/labels/"+lang, "must hold 1 to %d characters on one line", store.MaxLevelLabelRunes)
		}
	}
	return nil
}

// rulesToStore validates the rules at pointer at and converts them.
func rulesToStore(at string, r ConfidentialityRules) (store.ConfidentialityRules, error) {
	mask, ok := store.ExpiryDaysMaskOf(r.AllowedExpiryDays)
	if !ok {
		return store.ConfidentialityRules{}, invalid(at+"/allowedExpiryDays", "must be a non-empty subset of 1, 7 and 30")
	}
	if c := r.MaxDownloads; c != nil && (*c < 1 || *c > store.MaxDownloadsLimit) {
		return store.ConfidentialityRules{}, invalid(at+"/maxDownloads", "must be between 1 and %d", store.MaxDownloadsLimit)
	}
	return store.ConfidentialityRules{
		ExpiryDaysMask: mask, MaxDownloadsCap: r.MaxDownloads, RequirePassword: r.RequirePassword,
		RequireRecipientVerification: r.RequireRecipientVerification, InternalRecipientsOnly: r.InternalRecipientsOnly,
		ForceDeleteAfterFirstDownload: r.ForceDeleteAfterFirstDownload,
	}, nil
}

// PublicConfidentialityLevels returns the confidentiality levels of tenant
// t for the public configuration, in display order, with labels and
// descriptions in lang when written, else in the default language of the
// tenant, then in English, then in the smallest language written
// ([store.LevelLabel]).
func (s *Service) PublicConfidentialityLevels(ctx context.Context, t *tenant.Tenant, lang string) ([]PublicConfidentialityLevel, error) {
	stored, err := s.repo.confidentialityLevels(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("tenantadmin: list confidentiality levels: %w", err)
	}
	pick := func(texts map[string]string) string {
		return store.LevelLabel(texts, lang, t.DefaultLanguage, "en")
	}
	out := make([]PublicConfidentialityLevel, len(stored))
	for i, l := range stored {
		v := levelOf(l)
		out[i] = PublicConfidentialityLevel{
			Key: v.Key, Label: pick(l.Labels), Description: pick(l.Descriptions), IsDefault: v.IsDefault, Rules: v.Rules,
		}
	}
	return out, nil
}
