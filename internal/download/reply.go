package download

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Reasons of a reply refused because of its original sender (detail
// "reason" of the transfer.recipient_refused audit event).
const (
	// replyReasonBlocklist: the original sender or its domain is on the
	// blocklist of the tenant.
	replyReasonBlocklist = "blocklist"
	// replyReasonDomain: the domain of the original sender is no longer an
	// internal domain of the tenant.
	replyReasonDomain = "domain"
	// replyOrigin is the detail "origin" of that event.
	replyOrigin = "reply"
)

// ReplyTarget is a recipient link through which its recipient may reply to
// the transfer (startTransferReply): what package deposit needs to open a
// reply deposit session.
type ReplyTarget struct {
	// TransferID is the original transfer ("trf_" + ULID).
	TransferID string
	// LinkID is the recipient link of the replier ("rcl_" + ULID).
	LinkID string
	// Email is the address of the replier: the normalized address of the
	// recipient link, proved by code on this browser.
	Email string
	// Recipient is the address of the original sender, the single recipient
	// of the reply.
	Recipient string
	// TransferExpiresAt is when the original transfer expires; the reply
	// session never outlives it.
	TransferExpiresAt time.Time
	// OriginalCreatedAt is when the original transfer was created, for the
	// reply notice of the notification mail.
	OriginalCreatedAt time.Time
}

// replyEligible reports whether the recipient of link may reply to the
// transfer d of tenant tid (threat model T-222, T-224, P33): link is a
// recipient link (never a shared V1 link), d was sent by an internal
// depositor (see [replySource]), and the tenant allows replies (see
// [Service.replyEnabled]). The blocklist, the internal domains and the
// availability of the transfer are left to the callers. The deposit side
// applies the same rule when the reply is finalized (transfer.checkReply),
// and [deliverable] with [limitReached] match transfer.replyable.
func (s *Service) replyEligible(ctx context.Context, tid tenant.ID, d store.TransferDetails, link *store.RecipientLink) (bool, error) {
	if !replySource(d, link) {
		return false, nil
	}
	return s.replyEnabled(ctx, tid)
}

// replySource reports whether the transfer d may be replied to through
// link: link is a recipient link and d was sent by an internal depositor
// (internal, internal_remote, or an API token, whose transfers are
// internal; never an invited external nor a reply: no reply to a reply).
func replySource(d store.TransferDetails, link *store.RecipientLink) bool {
	return link != nil && d.SenderKind.IsInternal()
}

// replyEnabled reports whether tenant tid allows replies. The tenant
// settings are read again rather than taken from the request context, so
// that turning the option off applies at once; a tenant being deleted
// allows none.
func (s *Service) replyEnabled(ctx context.Context, tid tenant.ID) (bool, error) {
	cur, err := s.repo.tenant(ctx, tid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil // the tenant is being deleted
	case err != nil:
		return false, fmt.Errorf("download: read tenant: %w", err)
	}
	return cur.AllowTransferReply, nil
}

// ReplyAccess checks that the recipient of the link rawToken of tenant t
// may reply to its transfer now (startTransferReply), from the client IP
// clientIP, and returns what the reply deposit session needs.
// verificationCookie is the raw value of the VerificationCookieName cookie,
// "" when absent.
//
// The checks run in the order of the specification:
//
//  1. clientIP is valid: ErrNoClientIP otherwise, before any lookup;
//  2. the token names a known link of tenant t: ErrNotFound otherwise,
//     including a link of another tenant;
//  3. the tenant allows replies (see [Service.replyEnabled]):
//     ErrReplyNotAllowed otherwise;
//  4. the verification cookie holds a valid entry of the link, whatever the
//     options of the transfer (P33): ErrRecipientVerificationRequired
//     otherwise. It comes before the kind checks, so that a client without
//     a proved address learns nothing of the original sender (internal or
//     not). A shared V1 link never has a cookie entry: it is refused here
//     too, with ErrRecipientVerificationRequired rather than
//     ErrReplyNotAllowed, which reveals nothing either;
//  5. the link is a recipient link of a transfer sent by an internal
//     depositor (see [replySource]): ErrReplyNotAllowed otherwise;
//  6. the original sender, or its domain, is not on the blocklist, and its
//     domain is still an internal domain of the tenant (T-225):
//     ErrReplyNotAllowed otherwise. This refusal is a policy decision, not
//     an attack: it is recorded in the audit log (transfer.recipient_refused,
//     origin reply, with the reason, never an address) and not in the
//     security log;
//  7. the original transfer can still be downloaded: available, not
//     expired, not past its deletion after the first download, with a
//     deliverable file and below its download limit (ErrGone otherwise,
//     the limit included: there is no max-downloads-reached for a reply).
//
// The blocklist check of the replier itself comes last, in package
// deposit, which logs its refusal as a deposit refusal. A
// password-protected transfer needs no password for a reply: the link and
// the code sent to its address prove the recipient, and the reply reveals
// nothing of the transfer.
func (s *Service) ReplyAccess(ctx context.Context, t *tenant.Tenant, rawToken, verificationCookie string, clientIP netip.Addr) (ReplyTarget, error) {
	if !clientIP.IsValid() {
		return ReplyTarget{}, ErrNoClientIP
	}
	d, link, err := s.find(ctx, t, rawToken)
	if err != nil {
		return ReplyTarget{}, err
	}
	enabled, err := s.replyEnabled(ctx, t.ID)
	switch {
	case err != nil:
		return ReplyTarget{}, err
	case !enabled:
		return ReplyTarget{}, ErrReplyNotAllowed
	case link == nil:
		return ReplyTarget{}, ErrRecipientVerificationRequired
	}
	now := s.now()
	held, err := s.holds(verificationSpec, verificationCookie, t.ID, link.ID, now)
	switch {
	case err != nil:
		return ReplyTarget{}, err
	case !held:
		return ReplyTarget{}, ErrRecipientVerificationRequired
	case !replySource(d, link):
		return ReplyTarget{}, ErrReplyNotAllowed
	}
	if err := s.checkReplyRecipient(ctx, t, d, link, clientIP); err != nil {
		return ReplyTarget{}, err
	}
	if _, err := deliverable(d, now); err != nil || limitReached(d) {
		return ReplyTarget{}, ErrGone
	}
	return ReplyTarget{
		TransferID: d.ID, LinkID: link.ID, Email: link.Email, Recipient: d.SenderEmail,
		TransferExpiresAt: d.ExpiresAt, OriginalCreatedAt: d.CreatedAt,
	}, nil
}

// checkReplyRecipient refuses a reply to the transfer d whose sender is now
// on the blocklist of tenant t (address or domain), or whose domain is no
// longer an internal domain of t, recording the refusal in the audit log
// (see [Service.ReplyAccess]); link is the link of the replier, from the
// client IP ip.
func (s *Service) checkReplyRecipient(ctx context.Context, t *tenant.Tenant, d store.TransferDetails, link *store.RecipientLink, ip netip.Addr) error {
	blocked, err := s.repo.blocked(ctx, t.ID, d.SenderEmail)
	if err != nil {
		return fmt.Errorf("download: check blocklist: %w", err)
	}
	reason := ""
	if blocked {
		reason = replyReasonBlocklist
	} else {
		rules, err := s.repo.networkRules(ctx, t.ID)
		if err != nil {
			return fmt.Errorf("download: read network rules: %w", err)
		}
		if !netpolicy.DomainInternal(netpolicy.Rules{Domains: rules.Domains}, d.SenderEmail) {
			reason = replyReasonDomain
		}
	}
	if reason == "" {
		return nil
	}
	ev := audit.Event{
		ActorKind: store.ActorRecipient, Actor: link.Email, IP: ip,
		Action: audit.ActionTransferRecipientRefused, ObjectKind: audit.ObjectTransfer, ObjectID: d.ID,
		Details: map[string]any{"origin": replyOrigin, "reason": reason, "link": link.ID},
	}
	if err := s.repo.record(context.WithoutCancel(ctx), t.ID, ev); err != nil {
		// The refusal stands: the audit write is best effort.
		s.log(ctx, slog.LevelError, "audit write failed", t.ID, d.ID,
			slog.String("action", string(ev.Action)), slog.String("error", err.Error()))
	}
	return ErrReplyNotAllowed
}
