package deposit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// ReplyTarget is the source of a reply (V1.1, spec 10): the per-recipient
// link through which a recipient, whose address the caller already proved
// (recipient verification cookie), sends files back to the sender of a
// transfer. The HTTP layer builds it from the checks of the download
// package (tenant option, link, sender kind and policy, availability).
type ReplyTarget struct {
	// TransferID is the source transfer ("trf_" + ULID).
	TransferID string
	// LinkID is the recipient link of the source transfer ("rcl_" + ULID).
	LinkID string
	// Email is the address of the link, the replier.
	Email string
	// Recipient is the sender of the source transfer, the single recipient
	// of the reply.
	Recipient string
	// TransferExpiresAt is the expiry of the source transfer.
	TransferExpiresAt time.Time
}

// OpenReply opens a deposit session of kind KindReply for the recipient
// target.Email of the source transfer target.TransferID (OpenAPI
// startTransferReply), from clientIP, the real client IP. The caller has
// already checked the tenant option, the link, the recipient verification
// and the original sender (threats T-222 to T-225).
//
// It refuses, in this order:
//
//   - an unknown client IP, and a replier address or domain on the tenant
//     blocklist, with ErrForbidden and a deposit_refused security event
//     (reason ip or blocklist), as for any depositor;
//   - a source transfer whose expiry is not after now, or that, or whose
//     link, no longer exists in the tenant (including a link of another
//     transfer and identifiers of another tenant), with ErrReplyGone;
//   - a link that already has MaxLiveReplySessions reply sessions neither
//     ended nor expired (threat model P33), with a *RateLimitError
//     (ErrRateLimited) whose RetryAfter is the session lifetime and a
//     rate_limited security event (scope reply_session). The count and the
//     creation run in one transaction under the tenant lock.
//
// The session expires at the earlier of the session lifetime and the expiry
// of the source transfer; it never sets a recognition cookie
// (Session.Recognition is "") and cannot invite. Its opening is audited as
// address.verified with origin reply and the source transfer.
func (s *Service) OpenReply(ctx context.Context, t *tenant.Tenant, clientIP netip.Addr, target ReplyTarget) (Session, error) {
	email, err := store.NormalizeEmail(target.Email)
	if err != nil {
		return Session{}, fmt.Errorf("deposit: reply address: %w", err)
	}
	recipient, err := store.NormalizeEmail(target.Recipient)
	if err != nil {
		return Session{}, fmt.Errorf("deposit: reply recipient: %w", err)
	}
	if !clientIP.IsValid() {
		return Session{}, s.refuse(ctx, t, clientIP, securitylog.ReasonIP)
	}
	if err := s.checkBlocklist(ctx, t, clientIP, email); err != nil {
		return Session{}, err
	}
	if target.TransferExpiresAt.IsZero() {
		// A source never made available has no expiry and cannot be
		// replied to.
		return Session{}, ErrReplyGone
	}
	sess, err := s.openSession(ctx, t, sessionSpec{
		email: email, kind: KindReply, replyTo: target.TransferID, linkID: target.LinkID,
		notAfter: target.TransferExpiresAt,
	}, nil)
	if errors.Is(err, errLimited) {
		s.logEvent(ctx, t, clientIP, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: scopeReplySessions})
		return Session{}, &RateLimitError{RetryAfter: s.sessionTTL}
	}
	if err != nil {
		return Session{}, err
	}
	sess.Reply = &ReplyInfo{Recipient: recipient, TransferExpiresAt: target.TransferExpiresAt.UTC()}
	s.record(ctx, t, clientIP, email, audit.ActionAddressVerified, audit.ObjectDepositSession, sess.ID,
		map[string]any{"origin": originReply, "replyTo": target.TransferID})
	return sess, nil
}
