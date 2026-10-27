package datasubject

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Retry policy of a transfer held by an upload request.
const (
	// BusyAttempts is the number of erasure attempts of one transfer before
	// [ErrBusy].
	BusyAttempts = 5
	// BusyDelay is the delay between two attempts.
	BusyDelay = 200 * time.Millisecond
	// RetryAfter is the delay suggested to the client after [ErrBusy], for
	// the Retry-After header.
	RetryAfter = 5 * time.Second
)

// saltSize is the size of the random key of the pseudonym HMAC.
const saltSize = 32

// TransferEraser erases one transfer now, whatever its status
// (*lifecycle.Sweeper).
type TransferEraser interface {
	EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode lifecycle.EraseMode) (lifecycle.EraseResult, error)
}

// Options configures a [Service].
type Options struct {
	// Eraser crypto-erases the transfers (required).
	Eraser TransferEraser
	// Holder is the antivirus worker (*scan.Worker), held while a
	// recipient is removed from a transfer; nil holds nothing.
	Holder lifecycle.Holder
	// Logger receives the failures of the audit writes and of the scrub,
	// never an address; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Audit is the shared audit writer of the application, which publishes
	// the events it writes; nil means a writer of its own over the
	// database, publishing nothing.
	Audit *audit.Writer
}

// Summary counts the data of one tenant linked to an address (schema
// DataSubjectSummary).
type Summary struct {
	// Email is the normalized address.
	Email string
	// VerifiedAddress tells whether the address has a verified address
	// record.
	VerifiedAddress bool
	// TransfersAsSender and TransfersAsRecipient count the transfers sent
	// and received, in every status.
	TransfersAsSender    int
	TransfersAsRecipient int
	// Invitations counts the invitations of which the address is the
	// invitee or the issuer, in every state.
	Invitations int
	// AuditEvents counts the audit events of the tenant whose actor is the
	// address.
	AuditEvents int
	// SecurityEvents is always 0: the security log never records
	// addresses.
	SecurityEvents int
}

// EraseReport counts what an erasure did (schema DataSubjectEraseReport).
type EraseReport struct {
	// TransfersDeleted counts the transfers crypto-erased and deleted:
	// sent by the address, deposited with one of its invitations, or of
	// which it was the only recipient.
	TransfersDeleted int
	// RecipientEntriesRemoved counts the transfers from which the address
	// was removed as a recipient, others remaining.
	RecipientEntriesRemoved int
	// VerifiedAddressDeleted tells whether a verified address record was
	// deleted.
	VerifiedAddressDeleted bool
	// InvitationsDeleted counts the invitations of which the address was
	// the invitee.
	InvitationsDeleted int
	// LogEntriesPseudonymised counts the audit events whose actor was
	// replaced by the pseudonym.
	LogEntriesPseudonymised int
}

// details returns the audit details of the report: counts only.
func (r EraseReport) details() map[string]any {
	return map[string]any{
		"transfersDeleted": r.TransfersDeleted, "recipientEntriesRemoved": r.RecipientEntriesRemoved,
		"verifiedAddressDeleted": r.VerifiedAddressDeleted, "invitationsDeleted": r.InvitationsDeleted,
		"logEntriesPseudonymised": r.LogEntriesPseudonymised,
	}
}

// Service serves the rights of the data subjects. It is safe for
// concurrent use; erasures are serialized.
type Service struct {
	repo   repo
	eraser TransferEraser
	holder lifecycle.Holder
	logger *slog.Logger
	now    func() time.Time
	// sleep waits between two attempts on a busy transfer (tests replace
	// it).
	sleep func(ctx context.Context, d time.Duration) error

	// mu serializes the erasures, so that two concurrent erasures of one
	// address do not leave two pseudonyms.
	mu sync.Mutex
}

// errMissingDependency reports a [New] call without a required option.
var errMissingDependency = errors.New("datasubject: db and Eraser are required")

// New returns the service over db. It fails when db or Eraser is missing.
func New(db *store.DB, opts Options) (*Service, error) {
	if db == nil || opts.Eraser == nil {
		return nil, errMissingDependency
	}
	s := &Service{
		repo: newStoreRepo(db, opts.Audit), eraser: opts.Eraser, holder: opts.Holder,
		logger: opts.Logger, now: opts.Now, sleep: sleepContext,
	}
	if s.holder == nil {
		s.holder = noHolder{}
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// noHolder holds nothing.
type noHolder struct{}

func (noHolder) Hold(context.Context, tenant.ID, string, lifecycle.HoldIntent) (func(), error) {
	return func() {}, nil
}

// sleepContext waits d, or until ctx is done.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- Authorization and input --------------------------------------------------

// authorize checks that p may change tenant tid, which must be active, and
// returns the normalized address.
func (s *Service) authorize(ctx context.Context, p adminauth.Principal, tid tenant.ID, email string) (string, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return "", err
	}
	if err := adminauth.RequireTenantWrite(p.Admin, tid); err != nil {
		return "", err
	}
	t, err := s.repo.getTenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", ErrNotFound
	case err != nil:
		return "", fmt.Errorf("datasubject: get tenant: %w", err)
	case t.Status != tenant.StatusActive:
		return "", ErrNotFound
	}
	// The address is checked with the restricted syntax of the deposit and
	// transfer services (mail.ParseAddress, then the store normalization):
	// only such addresses are ever stored, and the search response echoes
	// it as the OpenAPI Email.
	mailbox, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return "", &InvalidError{Field: FieldEmail, Reason: "not a valid mail address"}
	}
	addr, err := store.NormalizeEmail(mailbox)
	if err != nil {
		return "", &InvalidError{Field: FieldEmail, Reason: "not a valid mail address"}
	}
	return addr, nil
}

// --- Pseudonym ---------------------------------------------------------------

// newPseudonym returns a pseudonym of addr keyed with a new random salt,
// wiped before returning.
func newPseudonym(addr string) string {
	salt := make([]byte, saltSize)
	_, _ = rand.Read(salt) // never fails (crypto/rand, Go 1.24+)
	defer clear(salt)
	return pseudonymOf(salt, addr)
}

// pseudonymOf returns store.PseudonymPrefix followed by the first
// store.PseudonymHexLen hexadecimal characters of HMAC-SHA256(salt, addr).
func pseudonymOf(salt []byte, addr string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(addr))
	return store.PseudonymPrefix + hex.EncodeToString(m.Sum(nil))[:store.PseudonymHexLen]
}

// --- Audit -------------------------------------------------------------------

// record writes the audit event of an operation of p on tenant tid about
// the data subject known as pseudonym. A failure is logged, never
// returned.
func (s *Service) record(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID,
	action audit.Action, pseudonym string, details map[string]any,
) {
	ev := audit.Event{
		TenantID: tid, ActorKind: store.ActorAdmin, Actor: p.Admin.Username, IP: ip,
		Action: action, ObjectKind: audit.ObjectDataSubject, ObjectID: pseudonym, Details: details,
	}
	if err := s.repo.audit(ctx, tid, ev); err != nil {
		s.logger.ErrorContext(ctx, "audit write failed", slog.String("action", string(action)),
			slog.String("tenant", string(tid)), slog.String("error", err.Error()))
	}
}

// --- Search ------------------------------------------------------------------

// Search counts the data of tenant tid linked to the address email (spec
// operation searchDataSubject) and records data_subject.searched, with
// the counts and a pseudonym drawn for this search, never the address.
func (s *Service) Search(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, email string) (Summary, error) {
	addr, err := s.authorize(ctx, p, tid, email)
	if err != nil {
		return Summary{}, err
	}
	sent, err := s.repo.senderTransfers(ctx, tid, addr)
	if err != nil {
		return Summary{}, fmt.Errorf("datasubject: list sent transfers: %w", err)
	}
	received, err := s.repo.recipientTransfers(ctx, tid, addr)
	if err != nil {
		return Summary{}, fmt.Errorf("datasubject: list received transfers: %w", err)
	}
	invitee, inviter, err := s.repo.countInvitations(ctx, tid, addr)
	if err != nil {
		return Summary{}, fmt.Errorf("datasubject: count invitations: %w", err)
	}
	verified, err := s.repo.verified(ctx, tid, addr)
	if err != nil {
		return Summary{}, fmt.Errorf("datasubject: get verified address: %w", err)
	}
	events, err := s.repo.countAudit(ctx, tid, addr)
	if err != nil {
		return Summary{}, fmt.Errorf("datasubject: count audit events: %w", err)
	}
	sum := Summary{
		Email: addr, VerifiedAddress: verified, TransfersAsSender: len(sent), TransfersAsRecipient: len(received),
		Invitations: invitee + inviter, AuditEvents: events,
	}
	s.record(ctx, p, ip, tid, audit.ActionDataSubjectSearched, newPseudonym(addr), map[string]any{
		"verifiedAddress": sum.VerifiedAddress, "transfersAsSender": sum.TransfersAsSender,
		"transfersAsRecipient": sum.TransfersAsRecipient, "invitations": sum.Invitations, "auditEvents": sum.AuditEvents,
	})
	return sum, nil
}

// --- Erasure -----------------------------------------------------------------

// Erase erases the data of tenant tid linked to the address email (spec
// operation eraseDataSubject), in the order of the package documentation,
// then scrubs the database and records data_subject.erased with the counts
// of the report (and "complete": false when a step failed, the counts
// being what was done). A failed erasure is completed by a new call; an
// erasure of an address without data returns a zero report. It returns
// [ErrBusy] when a transfer stays held by an upload request.
func (s *Service) Erase(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, email string) (EraseReport, error) {
	addr, err := s.authorize(ctx, p, tid, email)
	if err != nil {
		return EraseReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pseudonym := newPseudonym(addr)
	var rep EraseReport
	err = s.erase(ctx, tid, addr, pseudonym, &rep)
	// The work done stays done: scrub and audit it even when the request
	// was canceled.
	bg := context.WithoutCancel(ctx)
	s.scrub(bg)
	details := rep.details()
	details["complete"] = err == nil
	s.record(bg, p, ip, tid, audit.ActionDataSubjectErased, pseudonym, details)
	if err != nil {
		return EraseReport{}, err
	}
	return rep, nil
}

// erase runs the steps of the erasure and fills rep as it goes.
func (s *Service) erase(ctx context.Context, tid tenant.ID, addr, pseudonym string, rep *EraseReport) error {
	// 1. No new deposit: codes, sessions and verified address.
	if err := s.repo.deleteDepositRows(ctx, tid, addr); err != nil {
		return fmt.Errorf("datasubject: delete codes and sessions: %w", err)
	}
	deleted, err := s.repo.deleteVerified(ctx, tid, addr)
	if err != nil {
		return fmt.Errorf("datasubject: delete verified address: %w", err)
	}
	rep.VerifiedAddressDeleted = deleted
	// 2. Transfers sent, directly or with an invitation of the address.
	ids, err := s.depositedTransfers(ctx, tid, addr)
	if err != nil {
		return err
	}
	for _, trfID := range ids {
		if err := s.eraseTransfer(ctx, tid, trfID, rep); err != nil {
			return err
		}
	}
	// 3. Transfers received.
	received, err := s.repo.recipientTransfers(ctx, tid, addr)
	if err != nil {
		return fmt.Errorf("datasubject: list received transfers: %w", err)
	}
	for _, trfID := range received {
		if err := s.removeRecipient(ctx, tid, trfID, addr, rep); err != nil {
			return err
		}
	}
	// 4. Invitations.
	n, err := s.repo.eraseInvitations(ctx, tid, addr, pseudonym, s.now())
	switch {
	case errors.Is(err, store.ErrConflict):
		// A deposit started with one of its invitations meanwhile.
		return fmt.Errorf("%w: a transfer was deposited with an invitation meanwhile", ErrBusy)
	case err != nil:
		return fmt.Errorf("datasubject: erase invitations: %w", err)
	}
	rep.InvitationsDeleted = int(n)
	// 5. Audit log.
	m, err := s.repo.pseudonymiseAudit(ctx, tid, addr, pseudonym)
	if err != nil {
		return fmt.Errorf("datasubject: pseudonymise audit events: %w", err)
	}
	rep.LogEntriesPseudonymised = int(m)
	return nil
}

// depositedTransfers returns the IDs of the transfers of tenant tid sent
// by addr or deposited with an invitation of which addr is the invitee,
// without duplicates.
func (s *Service) depositedTransfers(ctx context.Context, tid tenant.ID, addr string) ([]string, error) {
	ids, err := s.repo.senderTransfers(ctx, tid, addr)
	if err != nil {
		return nil, fmt.Errorf("datasubject: list sent transfers: %w", err)
	}
	invs, err := s.repo.inviteeInvitations(ctx, tid, addr)
	if err != nil {
		return nil, fmt.Errorf("datasubject: list invitations: %w", err)
	}
	seen := make(map[string]bool, len(ids))
	for _, trfID := range ids {
		seen[trfID] = true
	}
	for _, invID := range invs {
		more, err := s.repo.invitationTransfers(ctx, tid, invID)
		if err != nil {
			return nil, fmt.Errorf("datasubject: list transfers of an invitation: %w", err)
		}
		for _, trfID := range more {
			if !seen[trfID] {
				seen[trfID] = true
				ids = append(ids, trfID)
			}
		}
	}
	return ids, nil
}

// eraseTransfer crypto-erases the transfer trfID and deletes its row,
// retrying while an upload request holds it. A transfer already gone is
// not counted. Each attempt runs to its end even if the request is
// canceled meanwhile, so that a client disconnect never stops an erasure
// halfway; a canceled request stops before an attempt and during the wait
// between two, with an error matching ctx.Err() (errors.Is), never a
// server failure.
func (s *Service) eraseTransfer(ctx context.Context, tid tenant.ID, trfID string, rep *EraseReport) error {
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("datasubject: erase transfer %s: %w", trfID, err)
		}
		_, err := s.eraser.EraseTransfer(context.WithoutCancel(ctx), tid, trfID, lifecycle.DeleteRow)
		switch {
		case err == nil:
			rep.TransfersDeleted++
			return nil
		case errors.Is(err, lifecycle.ErrNotFound):
			return nil
		case !errors.Is(err, lifecycle.ErrBusy):
			return fmt.Errorf("datasubject: %w", err)
		case attempt == BusyAttempts:
			return fmt.Errorf("%w: transfer %s", ErrBusy, trfID)
		}
		if err := s.sleep(ctx, BusyDelay); err != nil {
			return fmt.Errorf("datasubject: wait to retry transfer %s: %w", trfID, err)
		}
	}
}

// removeRecipient removes addr from the recipients of the transfer trfID
// while the antivirus worker holds it for an edit (a conclusion committed
// meanwhile notifies the remaining recipients on release), or erases the
// transfer when addr is its only recipient.
//
// The erasure of a transfer whose only recipient is addr runs under the
// edit hold, released only afterwards: released before, a conclusion
// committed during the edit hold would send its deferred mails, to addr
// with a working link, before the erasure holds the transfer. Under the
// edit hold, the erasure hold cancels them (nested holds do not block).
func (s *Service) removeRecipient(ctx context.Context, tid tenant.ID, trfID, addr string, rep *EraseReport) error {
	release, err := s.holder.Hold(ctx, tid, trfID, lifecycle.HoldForEdit)
	if err != nil {
		return fmt.Errorf("datasubject: hold transfer %s: %w", trfID, err)
	}
	defer release()
	out, err := s.repo.removeRecipient(ctx, tid, trfID, addr)
	if err != nil {
		return fmt.Errorf("datasubject: remove recipient of transfer %s: %w", trfID, err)
	}
	switch out {
	case recipientRemoved:
		rep.RecipientEntriesRemoved++
	case recipientSole:
		return s.eraseTransfer(ctx, tid, trfID, rep)
	}
	return nil
}

// scrub purges the deleted data from the database files; a failure is
// logged only (the next erasure or cleanup scrubs again).
func (s *Service) scrub(ctx context.Context) {
	err := s.repo.scrub(ctx)
	switch {
	case errors.Is(err, store.ErrScrubBusy):
		s.logger.WarnContext(ctx, "datasubject: deleted data may remain in the database WAL until the next checkpoint")
	case err != nil:
		s.logger.ErrorContext(ctx, "datasubject: scrub of the deleted data failed", slog.String("error", err.Error()))
	}
}
