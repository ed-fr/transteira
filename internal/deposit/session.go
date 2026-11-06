package deposit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Kind tells how a depositor was allowed to deposit (OpenAPI DepositorKind).
type Kind = store.DepositorKind

// Depositor kinds.
const (
	// KindInternal is an internal user: internal IP and domain.
	KindInternal = store.DepositorInternal
	// KindExternal is an external user holding an invitation.
	KindExternal = store.DepositorExternal
	// KindInternalRemote is an internal user depositing from outside the
	// tenant ranges (V1.1, spec 6.4): a code on every deposit, no
	// recognition cookie, no invitation.
	KindInternalRemote = store.DepositorInternalRemote
	// KindReply is the recipient of a transfer sending files back to its
	// sender (V1.1, spec 10, [Service.OpenReply]): subject to the external
	// rules, no recognition cookie, no invitation.
	KindReply = store.DepositorReply
	// KindDropLink is a third party depositing through a permanent drop
	// link of the tenant (since 2.0, [Service.StartDropLink]): a code at
	// every use, no recognition cookie, no invitation, subject to the
	// external rules; its transfers go to the recipients of the link.
	KindDropLink = store.DepositorDropLink
)

// Limits are the deposit limits shown to a depositor (OpenAPI
// DepositSession.limits).
type Limits struct {
	// MaxTransferBytes is the maximum total size of one transfer.
	MaxTransferBytes int64
	// ExpiryDays are the transfer lifetimes the depositor may choose.
	ExpiryDays []int
}

// InvitationInfo describes the invitation of an external depositor.
type InvitationInfo struct {
	// ID is the invitation record ("inv_" + ULID), for the server only.
	ID string
	// InvitedBy is the internal user who invited, the recipient of the
	// files.
	InvitedBy string
	// ExpiresAt is the end of validity of the invitation.
	ExpiresAt time.Time
}

// ReplyInfo describes the source transfer of a reply session (OpenAPI
// DepositSession.reply).
type ReplyInfo struct {
	// Recipient is the sender of the source transfer, normalized: the
	// single recipient of the reply.
	Recipient string
	// TransferExpiresAt is the expiry of the source transfer; the session
	// never outlives it.
	TransferExpiresAt time.Time
}

// DropLinkInfo describes the permanent drop link of a drop link session
// (OpenAPI DepositSession.dropLink, since 2.0).
type DropLinkInfo struct {
	// ID is the drop link record ("drl_" + ULID), for the server only.
	ID string
	// Label is the label of the link, shown to the depositor.
	Label string
	// ValidityDays is the lifetime of the transfers deposited through the
	// link, imposed on the depositor.
	ValidityDays int
}

// SessionInfo describes an active deposit session (OpenAPI DepositSession).
type SessionInfo struct {
	// ID is the session record ("ds_" + ULID), for the server only.
	ID string
	// Email is the verified address of the depositor, normalized.
	Email string
	// Kind is the depositor kind.
	Kind Kind
	// ExpiresAt is the absolute end of the session.
	ExpiresAt time.Time
	// Limits are the deposit limits of the tenant.
	Limits Limits
	// CanInvite is true for internal depositors (KindInternal only, never
	// KindInternalRemote). Invite still checks the client IP again.
	CanInvite bool
	// Invitation is set for external depositors only.
	Invitation *InvitationInfo
	// Reply is set for reply depositors (KindReply) only.
	Reply *ReplyInfo
	// DropLink is set for drop link depositors (KindDropLink) only.
	DropLink *DropLinkInfo
	// OpenedAt is when the session was opened. A drop link session
	// deposits one transfer only: the transfer service marks the session
	// used, by ID, in the creation transaction
	// (store.DropLinks.UseSessionTx).
	OpenedAt time.Time
	// ReplyToTransferID is the source transfer of a reply session ("trf_"
	// + ULID), "" for any other kind. For the server only.
	ReplyToTransferID string
	// RecipientLinkID is the recipient link of the source transfer that
	// opened a reply session ("rcl_" + ULID), "" for any other kind. For
	// the server only.
	RecipientLinkID string
	// CSRFToken is the token the client must send in X-CSRF-Token with
	// every unsafe request.
	CSRFToken string
}

// Session is a newly opened deposit session.
type Session struct {
	// Token is the raw session token, the value of the session cookie. It
	// is only available when the session is created.
	Token string
	// Recognition is the new value of the recognition cookie
	// (RecognitionCookie) for an internal depositor: the HTTP layer sets it
	// with Max-Age RecognitionMaxAge. It is "" for an external depositor and
	// for an internal one depositing from outside, whose cookie is left
	// unchanged, and for a reply depositor.
	Recognition string
	SessionInfo
}

// limits returns the deposit limits of t.
func limits(t *tenant.Tenant) Limits {
	return Limits{MaxTransferBytes: t.MaxTransferBytes, ExpiryDays: append([]int(nil), expiryDays...)}
}

// csrfToken derives the CSRF token of a session token.
func (s *Service) csrfToken(rawToken string) (string, error) {
	mac, err := s.keys.MAC(crypto.MACPurposeCSRF, []byte(rawToken))
	if err != nil {
		return "", fmt.Errorf("deposit: compute csrf token: %w", err)
	}
	return CSRFPrefix + base64.RawURLEncoding.EncodeToString(mac), nil
}

// sessionSpec describes the session [Service.openSession] creates.
type sessionSpec struct {
	// email is the normalized address of the depositor.
	email string
	// kind is the depositor kind.
	kind Kind
	// inv is the invitation of an external depositor (kind KindExternal),
	// nil otherwise.
	inv *store.Invitation
	// replyTo and linkID are the source transfer and the recipient link of
	// a reply depositor (kind KindReply), "" otherwise.
	replyTo, linkID string
	// dropLink is the drop link of a drop link depositor (kind
	// KindDropLink), nil otherwise.
	dropLink *store.DropLink
	// notAfter, when not zero, caps the expiry of the session (the expiry
	// of the source transfer of a reply): a value not after the opening
	// time fails with ErrReplyGone.
	notAfter time.Time
}

// openSession creates the session described by spec in one transaction
// with prepare (the challenge consumption and address verification, or the
// use of an already verified address; nil for none) and, for an external
// depositor, the use of the invitation spec.inv. For a reply depositor, a
// source transfer or recipient link that no longer exists in the tenant (or
// a link of another transfer) fails with ErrReplyGone, and a link that
// already has MaxLiveReplySessions live reply sessions with errLimited.
func (s *Service) openSession(ctx context.Context, t *tenant.Tenant, spec sessionSpec, prepare func(txRepo, time.Time) error) (Session, error) {
	token, err := s.newToken(id.SessionTokenPrefix, id.SessionTokenBytes)
	if err != nil {
		return Session{}, fmt.Errorf("deposit: new session token: %w", err)
	}
	sessionID, err := s.newID(id.DepositSession)
	if err != nil {
		return Session{}, fmt.Errorf("deposit: new session id: %w", err)
	}
	csrf, err := s.csrfToken(token)
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	rec := store.DepositSession{
		ID: sessionID, TokenHash: tokenHash(token), Email: spec.email, Kind: spec.kind,
		CreatedAt: now, ExpiresAt: now.Add(s.sessionTTL),
		ReplyToTransferID: spec.replyTo, RecipientLinkID: spec.linkID,
	}
	if spec.dropLink != nil {
		rec.DropLinkID = spec.dropLink.ID
	}
	if !spec.notAfter.IsZero() {
		// At the precision of the stored timestamps, as now.
		notAfter := spec.notAfter.UTC().Truncate(time.Millisecond)
		if !notAfter.After(now) {
			return Session{}, ErrReplyGone
		}
		if rec.ExpiresAt.After(notAfter) {
			rec.ExpiresAt = notAfter
		}
	}
	inv := spec.inv
	if inv != nil {
		rec.InvitationID = inv.ID
	}
	err = s.repo.tx(ctx, t.ID, func(tx txRepo) error {
		if prepare != nil {
			if err := prepare(tx, now); err != nil {
				return err
			}
		}
		if spec.kind == KindReply {
			n, err := tx.countLiveReplies(ctx, spec.linkID, now)
			switch {
			case err != nil:
				return fmt.Errorf("deposit: count reply sessions: %w", err)
			case n >= MaxLiveReplySessions:
				return errLimited
			}
		}
		if spec.dropLink != nil {
			// Read again under the transaction: a link disabled, revoked
			// or expired since the code was checked opens nothing.
			l, err := tx.dropLink(ctx, spec.dropLink.ID)
			switch {
			case errors.Is(err, store.ErrNotFound) || (err == nil && !l.Usable(now)):
				return ErrDropLinkInvalid
			case err != nil:
				return fmt.Errorf("deposit: read drop link: %w", err)
			}
			spec.dropLink = &l
		}
		err := tx.createSession(ctx, rec)
		switch {
		case spec.kind == KindReply && errors.Is(err, store.ErrNotFound):
			return ErrReplyGone
		case spec.kind == KindDropLink && errors.Is(err, store.ErrNotFound):
			return ErrDropLinkInvalid
		case err != nil:
			return fmt.Errorf("deposit: create session: %w", err)
		case inv == nil:
			return nil
		}
		if err := tx.touchInvitation(ctx, inv.ID, now); errors.Is(err, store.ErrNotFound) {
			return ErrInvitationGone
		} else if err != nil {
			return fmt.Errorf("deposit: use invitation: %w", err)
		}
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	info := SessionInfo{
		ID: rec.ID, Email: rec.Email, Kind: rec.Kind, ExpiresAt: rec.ExpiresAt, Limits: limits(t),
		CanInvite: rec.Kind == KindInternal, CSRFToken: csrf,
		ReplyToTransferID: rec.ReplyToTransferID, RecipientLinkID: rec.RecipientLinkID, OpenedAt: rec.CreatedAt,
	}
	if l := spec.dropLink; l != nil {
		info.setDropLink(*l)
	}
	if inv != nil {
		// TouchTx moved the expiry to 12 months after this use when later.
		expires := inv.ExpiresAt
		if next := store.InvitationExpiry(now); next.After(expires) {
			expires = next
		}
		info.Invitation = &InvitationInfo{ID: inv.ID, InvitedBy: inv.InvitedBy, ExpiresAt: expires}
	}
	return Session{Token: token, SessionInfo: info}, nil
}

// setDropLink fills the drop link of a drop link session: its public part
// and, since the depositor cannot choose it, the validity of the link as
// the only expiry offered.
func (info *SessionInfo) setDropLink(l store.DropLink) {
	info.DropLink = &DropLinkInfo{ID: l.ID, Label: l.Label, ValidityDays: l.ValidityDays}
	info.Limits.ExpiryDays = []int{l.ValidityDays}
}

// Session returns the active session whose cookie token is rawToken, with
// its CSRF token. It returns ErrUnauthenticated when the token is malformed,
// unknown in the tenant, ended or expired, and for an external depositor
// whose invitation is no longer active (a revoked invitation ends its
// sessions). For a reply depositor it reads the source transfer to fill
// Reply, and returns ErrUnauthenticated when it no longer exists (its
// deletion also deletes the reply sessions). For a drop link depositor it
// reads the link to fill DropLink, and returns ErrUnauthenticated when the
// link is disabled or revoked (which ends its sessions) or gone.
func (s *Service) Session(ctx context.Context, t *tenant.Tenant, rawToken string) (SessionInfo, error) {
	if !validToken(id.SessionTokenPrefix, rawToken) {
		return SessionInfo{}, ErrUnauthenticated
	}
	rec, err := s.repo.session(ctx, t.ID, tokenHash(rawToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return SessionInfo{}, ErrUnauthenticated
	case err != nil:
		return SessionInfo{}, fmt.Errorf("deposit: read session: %w", err)
	}
	info := SessionInfo{
		ID: rec.ID, Email: rec.Email, Kind: rec.Kind, ExpiresAt: rec.ExpiresAt, Limits: limits(t),
		CanInvite: rec.Kind == KindInternal, ReplyToTransferID: rec.ReplyToTransferID,
		RecipientLinkID: rec.RecipientLinkID, OpenedAt: rec.CreatedAt,
	}
	switch rec.Kind {
	case KindExternal:
		inv, err := s.activeInvitation(ctx, t.ID, rec.InvitationID)
		switch {
		case errors.Is(err, ErrInvitationGone):
			return SessionInfo{}, ErrUnauthenticated
		case err != nil:
			return SessionInfo{}, err
		}
		info.Invitation = &InvitationInfo{ID: inv.ID, InvitedBy: inv.InvitedBy, ExpiresAt: inv.ExpiresAt}
	case KindReply:
		src, err := s.repo.transfer(ctx, t.ID, rec.ReplyToTransferID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return SessionInfo{}, ErrUnauthenticated
		case err != nil:
			return SessionInfo{}, fmt.Errorf("deposit: read source transfer: %w", err)
		}
		info.Reply = &ReplyInfo{Recipient: src.SenderEmail, TransferExpiresAt: src.ExpiresAt}
	case KindDropLink:
		l, err := s.repo.dropLink(ctx, t.ID, rec.DropLinkID)
		switch {
		case errors.Is(err, store.ErrNotFound) || (err == nil && !l.Usable(s.now())):
			// A disabled, revoked or expired link ends its sessions.
			return SessionInfo{}, ErrUnauthenticated
		case err != nil:
			return SessionInfo{}, fmt.Errorf("deposit: read drop link: %w", err)
		}
		info.setDropLink(l)
	}
	if info.CSRFToken, err = s.csrfToken(rawToken); err != nil {
		return SessionInfo{}, err
	}
	return info, nil
}

// CheckCSRF reports whether header is the CSRF token of the session token
// rawToken. The MAC comparison runs in constant time.
func (s *Service) CheckCSRF(rawToken, header string) bool {
	encoded, ok := strings.CutPrefix(header, CSRFPrefix)
	if !ok || rawToken == "" {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	valid, err := s.keys.VerifyMAC(crypto.MACPurposeCSRF, mac, []byte(rawToken))
	return err == nil && valid
}

// End ends the session whose cookie token is rawToken. It returns
// ErrUnauthenticated when no such session is active in the tenant.
func (s *Service) End(ctx context.Context, t *tenant.Tenant, rawToken string) error {
	if !validToken(id.SessionTokenPrefix, rawToken) {
		return ErrUnauthenticated
	}
	err := s.repo.endSession(ctx, t.ID, tokenHash(rawToken), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrUnauthenticated
	case err != nil:
		return fmt.Errorf("deposit: end session: %w", err)
	}
	return nil
}
