// Package systemsettings serves the instance settings that the super admin
// changes at runtime (CLAUDE.md section 19): the disk usage ratio that
// raises the disk alert, and an optional address that receives the alert
// in addition to the super admins.
//
// # Rules
//
//   - Only an authenticated super admin reads or changes the settings.
//   - The threshold is a ratio from 0.50 to 0.99, stored in basis points
//     (rounded to the nearest one); NaN and infinities are refused.
//   - The address must be a bare mail address (no display name, no
//     comment, see mail.ParseAddress); it is stored normalized, and the
//     alert is sent to it in the language of the admin who set it.
//   - Every change records the audit event config.updated, in the same
//     transaction as the change, with the names of the changed fields
//     only: never the address itself (threat model T-158).
//   - After a change, the Options.OnChange hook runs (the application
//     re-evaluates the disk alert at once with it).
package systemsettings

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/avselftest"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
)

// Bounds of the disk alert threshold, as ratios.
const (
	// MinThreshold is the lowest disk alert threshold.
	MinThreshold = float64(store.MinDiskAlertThresholdBP) / basisPoints
	// MaxThreshold is the highest disk alert threshold.
	MaxThreshold = float64(store.MaxDiskAlertThresholdBP) / basisPoints
	// DefaultThreshold is the disk alert threshold of a new instance.
	DefaultThreshold = float64(store.DefaultDiskAlertThresholdBP) / basisPoints
)

// basisPoints is the number of basis points in a ratio of 1.
const basisPoints = 10000

// Fields named by an [InvalidError] and by the audit event: JSON pointers
// (RFC 6901) of the request body for the former, the bare member names
// for the latter.
const (
	FieldDiskAlertThreshold = "/diskAlertThreshold"
	FieldAlertEmail         = "/alertEmail"
)

// objectID is the audit object ID of the settings (object kind system).
const objectID = "settings"

var (
	// ErrInvalidInput reports a malformed input (400 validation-failed).
	// The error is an *[InvalidError] naming the field.
	ErrInvalidInput = errors.New("systemsettings: invalid input")
	// ErrUnauthenticated reports a principal without an authenticated
	// session (401 unauthenticated). It is [adminauth.ErrUnauthenticated].
	ErrUnauthenticated = adminauth.ErrUnauthenticated
	// ErrForbidden reports an administrator other than a super admin (403
	// forbidden). It is [adminauth.ErrForbidden].
	ErrForbidden = adminauth.ErrForbidden
	// errInvalidOptions reports a [New] call without its dependencies.
	errInvalidOptions = errors.New("systemsettings: database and auditor required")
)

// InvalidError reports a malformed input field. It matches
// [ErrInvalidInput].
type InvalidError struct {
	// Field is FieldDiskAlertThreshold or FieldAlertEmail.
	Field string
	// Reason explains the problem in English; it never quotes the value.
	Reason string
}

// Error implements error.
func (e *InvalidError) Error() string {
	return "systemsettings: invalid " + e.Field + ": " + e.Reason
}

// Is makes errors.Is(err, ErrInvalidInput) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalidInput }

// Settings are the instance settings editable at runtime.
type Settings struct {
	// DiskAlertThreshold is the disk usage ratio at or above which the disk
	// alert is raised (MinThreshold to MaxThreshold).
	DiskAlertThreshold float64
	// AlertEmail is the extra recipient of the disk alert, "" for none.
	AlertEmail string
	// AlertEmailLanguage is the language of the mails sent to AlertEmail,
	// "" without it.
	AlertEmailLanguage string
	// AntivirusEngine is the antivirus engine of the instance
	// (TT_ANTIVIRUS_ENGINE), read only: Options.AntivirusEngine.
	AntivirusEngine string
	// AntivirusSelfTest is the last EICAR self-test of the antivirus
	// engine, read only (Options.AntivirusSelfTest); nil before the first
	// test ends or with the engine "none".
	AntivirusSelfTest *avselftest.Result
}

// Field is an optional member of a JSON Merge Patch: Set tells whether the
// member is present, and a nil Value is the JSON null.
type Field[T any] struct {
	// Set tells whether the patch carries the member.
	Set bool
	// Value is the new value; nil is the JSON null (the value is removed).
	Value *T
}

// Patch is the input of [Service.Update] (OpenAPI SystemSettingsUpdate,
// JSON Merge Patch).
type Patch struct {
	// Threshold is the new disk alert threshold, nil to keep it. The
	// handler refuses a JSON null before calling Update.
	Threshold *float64
	// Email changes the alert address when set; a nil value removes it.
	Email Field[string]
}

// Auditor records an audit event inside a system transaction.
// *audit.Writer implements it.
type Auditor interface {
	RecordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error
}

// repo is the storage of the settings. *store.SystemSettings implements it.
type repo interface {
	Get(ctx context.Context) (store.SystemSettingsRow, error)
	UpdateTx(ctx context.Context, fn func(tx *store.SystemTx, s *store.SystemSettingsRow) error) (store.SystemSettingsRow, error)
}

// Options configure a Service.
type Options struct {
	// OnChange runs after every committed change (nil for none). It must
	// not block: the application passes the non-blocking
	// diskalert.Monitor.Check.
	OnChange func()
	// AntivirusEngine is the antivirus engine of the instance, reported
	// read only in the settings ("" leaves it out).
	AntivirusEngine string
	// AntivirusSelfTest returns the last EICAR self-test of the engine,
	// reported read only in the settings (avselftest.Service.Last); nil
	// leaves it out.
	AntivirusSelfTest func() (avselftest.Result, bool)
}

// Service reads and changes the instance settings. It is safe for
// concurrent use.
type Service struct {
	repo     repo
	auditor  Auditor
	onChange func()
	engine   string
	selfTest func() (avselftest.Result, bool)
}

// New returns the service over db, recording the changes with auditor.
func New(db *store.DB, auditor Auditor, opts Options) (*Service, error) {
	if db == nil || auditor == nil {
		return nil, errInvalidOptions
	}
	return newService(db.SystemSettings(), auditor, opts), nil
}

// newService returns the service over r.
func newService(r repo, auditor Auditor, opts Options) *Service {
	s := &Service{repo: r, auditor: auditor, onChange: opts.OnChange, engine: opts.AntivirusEngine, selfTest: opts.AntivirusSelfTest}
	if s.onChange == nil {
		s.onChange = func() {}
	}
	return s
}

// Get returns the instance settings, for p. It returns ErrUnauthenticated
// for a session that is not authenticated and ErrForbidden unless p is a
// super admin.
func (s *Service) Get(ctx context.Context, p adminauth.Principal) (Settings, error) {
	if err := authorize(p); err != nil {
		return Settings{}, err
	}
	row, err := s.repo.Get(ctx)
	if err != nil {
		return Settings{}, fmt.Errorf("systemsettings: %w", err)
	}
	return s.fromRow(row), nil
}

// Update applies patch for p, from client ip, and returns the settings as
// stored. Setting the address records the language of p (its preferred
// language, else i18n.Default) as the language of the alert mails. A patch
// that changes nothing writes nothing and records no audit event. It
// returns ErrUnauthenticated, ErrForbidden (checked first, whatever the
// patch) and an *InvalidError for a malformed field.
func (s *Service) Update(ctx context.Context, p adminauth.Principal, patch Patch, ip netip.Addr) (Settings, error) {
	if err := authorize(p); err != nil {
		return Settings{}, err
	}
	var thresholdBP int
	if patch.Threshold != nil {
		bp, err := thresholdToBP(*patch.Threshold)
		if err != nil {
			return Settings{}, err
		}
		thresholdBP = bp
	}
	var email string
	if patch.Email.Set && patch.Email.Value != nil {
		e, err := parseEmail(*patch.Email.Value)
		if err != nil {
			return Settings{}, err
		}
		email = e
	}
	lang := p.Admin.Language
	if !i18n.IsSupported(lang) {
		lang = i18n.Default
	}
	changed := false
	row, err := s.repo.UpdateTx(ctx, func(tx *store.SystemTx, row *store.SystemSettingsRow) error {
		var fields []string
		if patch.Threshold != nil && row.DiskAlertThresholdBP != thresholdBP {
			row.DiskAlertThresholdBP = thresholdBP
			fields = append(fields, strings.TrimPrefix(FieldDiskAlertThreshold, "/"))
		}
		if patch.Email.Set {
			newLang := lang
			if email == "" {
				newLang = ""
			}
			if row.AlertEmail != email || row.AlertEmailLanguage != newLang {
				row.AlertEmail, row.AlertEmailLanguage = email, newLang
				fields = append(fields, strings.TrimPrefix(FieldAlertEmail, "/"))
			}
		}
		if len(fields) == 0 {
			return errUnchanged
		}
		changed = true
		return s.auditor.RecordTx(ctx, tx, audit.Event{
			ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip, Action: audit.ActionConfigUpdated,
			ObjectKind: audit.ObjectSystem, ObjectID: objectID, Details: map[string]any{"fields": fields},
		})
	})
	switch {
	case errors.Is(err, errUnchanged):
		return s.Get(ctx, p)
	case err != nil:
		return Settings{}, fmt.Errorf("systemsettings: %w", err)
	}
	if changed {
		s.onChange()
	}
	return s.fromRow(row), nil
}

// errUnchanged rolls back an update that changes nothing.
var errUnchanged = errors.New("systemsettings: nothing to change")

// authorize requires an authenticated super admin.
func authorize(p adminauth.Principal) error {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return err
	}
	return adminauth.RequireSuperAdmin(p.Admin)
}

// thresholdToBP validates the threshold t and returns it in basis points,
// rounded to the nearest one.
func thresholdToBP(t float64) (int, error) {
	if math.IsNaN(t) || math.IsInf(t, 0) || t < MinThreshold || t > MaxThreshold {
		return 0, &InvalidError{
			Field:  FieldDiskAlertThreshold,
			Reason: fmt.Sprintf("must be a number from %.2f to %.2f", MinThreshold, MaxThreshold),
		}
	}
	return int(math.Round(t * basisPoints)), nil
}

// parseEmail validates a bare mail address and returns it normalized.
func parseEmail(raw string) (string, error) {
	bad := &InvalidError{Field: FieldAlertEmail, Reason: "must be a bare mail address"}
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return "", bad
	}
	email, err := store.NormalizeEmail(addr)
	if err != nil {
		return "", bad
	}
	return email, nil
}

// fromRow returns the settings of row.
func (s *Service) fromRow(row store.SystemSettingsRow) Settings {
	out := Settings{
		DiskAlertThreshold: float64(row.DiskAlertThresholdBP) / basisPoints,
		AlertEmail:         row.AlertEmail,
		AlertEmailLanguage: row.AlertEmailLanguage,
		AntivirusEngine:    s.engine,
	}
	if s.selfTest != nil {
		if r, ok := s.selfTest(); ok {
			out.AntivirusSelfTest = &r
		}
	}
	return out
}
