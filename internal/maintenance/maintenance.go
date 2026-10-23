// Package maintenance holds the maintenance mode of the instance
// (CLAUDE.md section 4): while it is active, new deposits are refused with
// 503 and a maintenance message chosen by the super admin, and the health
// check, downloads and administration stay available.
//
// Two sources turn it on:
//
//   - the environment: TT_MAINTENANCE=true forces the mode for the life of
//     the process and always wins (source "environment", started at the
//     process start);
//   - the super admin, from the administration: the choice is stored in
//     the system settings, survives a restart and is audited in the same
//     transaction (source "admin").
//
// The state is held in memory behind one atomic pointer, so that the hot
// path ([Mode.Active], called by every deposit request and the health
// check) is a single atomic load. TransTeira runs one instance per
// database (CLAUDE.md section 17): the stored choice is read at start-up
// and every change goes through [Mode.Set].
//
// The maintenance messages are plain text (threat T-155): they are never
// rendered as HTML, and [Mode.Set] refuses control characters other than
// line feed, the Unicode line and paragraph separators and the
// bidirectional controls.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// MaxMessageRunes bounds each maintenance message, in characters.
const MaxMessageRunes = store.MaxMaintenanceMessageRunes

// ObjectID is the object of the maintenance audit events (object kind
// audit.ObjectSystem).
const ObjectID = "maintenance"

// FieldMessage is the JSON pointer of the maintenance messages; an invalid
// message is reported as FieldMessage + "/" + its language.
const FieldMessage = "/message"

// maxPointerKeyBytes bounds a message key quoted in an [InvalidError], so
// that a hostile key is not echoed at length.
const maxPointerKeyBytes = 64

// Source tells what turned the maintenance mode on.
type Source string

// Sources, as the OpenAPI Maintenance schema names them.
const (
	// SourceNone: the maintenance mode is off.
	SourceNone Source = "none"
	// SourceEnvironment: TT_MAINTENANCE=true forces the mode.
	SourceEnvironment Source = "environment"
	// SourceAdmin: the super admin enabled the mode.
	SourceAdmin Source = "admin"
)

// Errors of the maintenance mode. The adminauth errors (ErrUnauthenticated,
// ErrForbidden) are returned as is.
var (
	// ErrForcedByEnvironment reports an attempt to disable the maintenance
	// mode while TT_MAINTENANCE forces it (409 state-conflict).
	ErrForcedByEnvironment = errors.New("maintenance: forced on by the environment")
	// ErrInvalid is matched by every [InvalidError].
	ErrInvalid = errors.New("maintenance: invalid input")
)

// InvalidError reports an invalid maintenance message (400
// validation-failed). It matches [ErrInvalid].
type InvalidError struct {
	// Field is the JSON pointer of the invalid member, for example
	// "/message/fr", or FieldMessage when its key cannot be quoted.
	Field string
}

// Error implements error; it never quotes the message.
func (e *InvalidError) Error() string { return "maintenance: invalid " + e.Field }

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// State is the maintenance mode as the administration shows it (the
// OpenAPI Maintenance schema).
type State struct {
	// Enabled reports whether the maintenance mode is in effect.
	Enabled bool
	// Source is what turned it on, SourceNone when it is off.
	Source Source
	// AdminEnabled is the choice stored by the super admin, also while
	// the environment forces the mode.
	AdminEnabled bool
	// Since is the start of the maintenance (the process start when the
	// environment forces it), the zero time when it is off.
	Since time.Time
	// Message maps a supported language to its maintenance message; empty
	// (never nil) when there is none. It is a copy.
	Message map[string]string
}

// Repository reads and changes the stored choice of the super admin.
// *store.SystemSettings implements it.
type Repository interface {
	Get(ctx context.Context) (store.SystemSettingsRow, error)
	UpdateTx(ctx context.Context, fn func(tx *store.SystemTx, s *store.SystemSettingsRow) error) (store.SystemSettingsRow, error)
}

// Auditor records an audit event in the transaction of a settings change.
// *audit.Writer implements it.
type Auditor interface {
	RecordTx(ctx context.Context, tx *store.SystemTx, ev audit.Event) error
}

// Compile-time checks of the production dependencies.
var (
	_ Repository = (*store.SystemSettings)(nil)
	_ Auditor    = (*audit.Writer)(nil)
)

// Options configures [New].
type Options struct {
	// Forced is TT_MAINTENANCE: the maintenance mode is on whatever the
	// stored choice.
	Forced bool
	// Start is the process start, the Since of a forced maintenance; the
	// clock when zero.
	Start time.Time
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// snapshot is an immutable state of the mode, swapped atomically.
type snapshot struct {
	// active is forced || adminEnabled, precomputed for Active.
	active       bool
	forced       bool
	forcedSince  time.Time
	adminEnabled bool
	adminSince   time.Time
	// messages is never modified once published.
	messages map[string]string
}

// Mode is the maintenance mode of the instance. It is safe for concurrent
// use.
type Mode struct {
	repo  Repository
	audit Auditor
	now   func() time.Time

	// mu serializes the changes (Set, Force); readers only load state.
	mu    sync.Mutex
	state atomic.Pointer[snapshot]
}

// New returns the maintenance mode, loading the stored choice of the super
// admin from repo; audit records the changes made by [Mode.Set].
func New(ctx context.Context, repo Repository, auditor Auditor, opts Options) (*Mode, error) {
	if repo == nil || auditor == nil {
		return nil, errors.New("maintenance: repository and auditor are required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	row, err := repo.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("maintenance: load the system settings: %w", err)
	}
	m := &Mode{repo: repo, audit: auditor, now: now}
	s := fromRow(row)
	s.forced = opts.Forced
	if s.forced {
		s.forcedSince = opts.Start
		if s.forcedSince.IsZero() {
			s.forcedSince = now()
		}
	}
	m.publish(s)
	return m, nil
}

// fromRow returns the snapshot of the stored choice in row, not forced.
func fromRow(row store.SystemSettingsRow) snapshot {
	s := snapshot{adminEnabled: row.MaintenanceEnabled, messages: maps.Clone(row.MaintenanceMessage)}
	if s.adminEnabled {
		s.adminSince = row.MaintenanceSince
	}
	if s.messages == nil {
		s.messages = map[string]string{}
	}
	return s
}

// publish computes the active flag of s and makes it the current state.
// The caller holds mu, or is New.
func (m *Mode) publish(s snapshot) {
	s.active = s.forced || s.adminEnabled
	m.state.Store(&s)
}

// Active reports whether the maintenance mode is in effect: one atomic
// load.
func (m *Mode) Active() bool { return m.state.Load().active }

// State returns the current state, without authorization (internal use:
// logs, wiring). The administration uses [Mode.Get].
func (m *Mode) State() State {
	s := m.state.Load()
	st := State{AdminEnabled: s.adminEnabled, Message: maps.Clone(s.messages), Source: SourceNone}
	switch {
	case s.forced:
		st.Enabled, st.Source, st.Since = true, SourceEnvironment, s.forcedSince
	case s.adminEnabled:
		st.Enabled, st.Source, st.Since = true, SourceAdmin, s.adminSince
	}
	return st
}

// Message returns the maintenance message to show to a client whose
// negotiated language is lang, on a tenant whose default language is
// tenantDefault: the message in lang, else in tenantDefault, else in
// English, else in the first supported language that has one. It returns
// "" when the maintenance mode is off or no message is set.
func (m *Mode) Message(lang, tenantDefault string) string {
	s := m.state.Load()
	if !s.active || len(s.messages) == 0 {
		return ""
	}
	// The usual cases first, without allocating (Message runs on every
	// request during a maintenance).
	for _, l := range [...]string{lang, tenantDefault, i18n.English} {
		if msg, ok := s.messages[l]; ok {
			return msg
		}
	}
	for _, l := range i18n.Supported() {
		if msg, ok := s.messages[l]; ok {
			return msg
		}
	}
	// Unreachable while the stored keys are supported languages, which the
	// store enforces; kept so that a message is never silently lost.
	keys := slices.Sorted(maps.Keys(s.messages))
	return s.messages[keys[0]]
}

// Force turns the environment override on or off at run time: Run sets it
// from TT_MAINTENANCE through [Options.Forced]; tests use Force to toggle
// the mode without an administrator. A forced maintenance started by Force
// is dated now.
func (m *Mode) Force(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := *m.state.Load()
	if on && !s.forced {
		s.forcedSince = m.now()
	}
	if !on {
		s.forcedSince = time.Time{}
	}
	s.forced = on
	m.publish(s)
}

// Get returns the maintenance mode to any authenticated administrator. It
// returns adminauth.ErrUnauthenticated for a session that is not
// authenticated.
func (m *Mode) Get(_ context.Context, p adminauth.Principal) (State, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return State{}, err
	}
	return m.State(), nil
}

// Set stores the choice of the super admin p, from clientIP: the
// maintenance mode on or off, and messages, which replace the stored
// messages entirely (nil or empty for none). The change and its audit
// event (maintenance.enabled or maintenance.disabled, a global event whose
// details list the message languages only) commit in one transaction,
// then the new state takes effect at once.
//
// It returns adminauth.ErrUnauthenticated or adminauth.ErrForbidden for a
// caller who is not an authenticated super admin, an *InvalidError for an
// invalid message, and ErrForcedByEnvironment when enabled is false while
// TT_MAINTENANCE forces the mode (enabling is accepted then: the messages
// are stored and the source stays the environment).
func (m *Mode) Set(ctx context.Context, p adminauth.Principal, enabled bool, messages map[string]string, clientIP netip.Addr) (State, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return State{}, err
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return State{}, err
	}
	langs, err := validate(messages)
	if err != nil {
		return State{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.state.Load()
	if cur.forced && !enabled {
		return State{}, ErrForcedByEnvironment
	}
	ev := audit.Event{
		ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: clientIP,
		Action: audit.ActionMaintenanceDisabled, ObjectKind: audit.ObjectSystem, ObjectID: ObjectID,
	}
	if enabled {
		ev.Action = audit.ActionMaintenanceEnabled
	}
	if len(langs) > 0 {
		ev.Details = map[string]any{"languages": langs}
	}
	row, err := m.repo.UpdateTx(ctx, func(tx *store.SystemTx, s *store.SystemSettingsRow) error {
		if enabled && !s.MaintenanceEnabled {
			s.MaintenanceSince = time.Time{} // dated by the store
		}
		s.MaintenanceEnabled = enabled
		s.MaintenanceMessage = maps.Clone(messages)
		return m.audit.RecordTx(ctx, tx, ev)
	})
	if err != nil {
		return State{}, fmt.Errorf("maintenance: store the maintenance mode: %w", err)
	}
	next := fromRow(row)
	next.forced, next.forcedSince = cur.forced, cur.forcedSince
	m.publish(next)
	return m.State(), nil
}

// validate checks the maintenance messages and returns their languages,
// sorted. Each key must be a supported language and each value plain text
// of 1 to MaxMessageRunes characters without hidden line breaks or
// controls ([validMessage]). The first invalid member in key order is
// reported.
func validate(messages map[string]string) ([]string, error) {
	keys := slices.Sorted(maps.Keys(messages))
	for _, k := range keys {
		if !i18n.IsSupported(k) || !validMessage(messages[k]) {
			return nil, &InvalidError{Field: pointer(k)}
		}
	}
	return keys, nil
}

// validMessage reports whether msg is valid UTF-8 of 1 to MaxMessageRunes
// characters with no control character other than line feed, no Unicode
// line or paragraph separator and no bidirectional control.
func validMessage(msg string) bool {
	if msg == "" || !utf8.ValidString(msg) || utf8.RuneCountInString(msg) > MaxMessageRunes {
		return false
	}
	return strings.IndexFunc(msg, func(r rune) bool {
		return (r != '\n' && textsafe.IsControl(r)) || textsafe.IsLineSeparator(r) || textsafe.IsBidiControl(r)
	}) < 0
}

// pointer returns the JSON pointer (RFC 6901) of the message keyed k, or
// FieldMessage when k is too long, not valid UTF-8 or holds a hidden
// character.
func pointer(k string) string {
	if k == "" || len(k) > maxPointerKeyBytes || !utf8.ValidString(k) || strings.IndexFunc(k, textsafe.IsHidden) >= 0 {
		return FieldMessage
	}
	k = strings.ReplaceAll(k, "~", "~0")
	k = strings.ReplaceAll(k, "/", "~1")
	return FieldMessage + "/" + k
}
