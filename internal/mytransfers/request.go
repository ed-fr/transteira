package mytransfers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/i18n"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// address is a validated mail address in its two forms.
type address struct {
	// mailbox is the form mail is sent to (domain lowercased).
	mailbox string
	// normalized is the form the store keeps and compares (lowercase).
	normalized string
}

// parseEmail validates a mail address like the deposit does: the
// restricted syntax of mail.ParseAddress, then the normalization of the
// store. It returns an *InvalidError on FieldEmail otherwise.
func parseEmail(raw string) (address, error) {
	mailbox, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return address{}, invalid(FieldEmail)
	}
	normalized, err := store.NormalizeEmail(mailbox)
	if err != nil {
		return address{}, invalid(FieldEmail)
	}
	return address{mailbox: mailbox, normalized: normalized}, nil
}

// RequestLink asks for an access link mailed to email (spec 8.7). It does
// the same work for every address (P32, T-207): it validates email and
// language (language "" negotiates the language from acceptLanguage and
// the tenant default), checks that the tenant has SMTP settings, records
// the request in the rate limit table of the tenant, applies the limits
// and queues the request for a worker. It returns nil (202) whether or not
// a link will be sent; the worker sends one only to a verified, active,
// not blocklisted address of the tenant.
//
// It returns an *InvalidError on FieldEmail or FieldLanguage,
// ErrMailUnavailable when the tenant has no SMTP settings or the service
// is closed, and a *RateLimitError beyond MaxRequestsPerIP requests per
// RequestWindow from ip (logged as rate_limited, scope ScopeRequestIP).
// Beyond MaxRequestsPerAddress requests per RequestWindow for the address,
// or when the queue is full, the request is dropped and nil returned.
func (s *Service) RequestLink(ctx context.Context, t *tenant.Tenant, ip netip.Addr, acceptLanguage, email, language string) error {
	addr, err := parseEmail(email)
	if err != nil {
		return err
	}
	switch {
	case language == "":
		language = i18n.Negotiate(acceptLanguage, t.DefaultLanguage)
	case !i18n.IsSupported(language):
		return invalid(FieldLanguage)
	}
	if s.isClosed() {
		return fmt.Errorf("%w: the service is closed", ErrMailUnavailable)
	}
	_, err = s.repo.smtp(ctx, t.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("%w: the tenant has no smtp settings", ErrMailUnavailable)
	case err != nil:
		return fmt.Errorf("mytransfers: read smtp settings: %w", err)
	}
	mac, err := s.keys.MAC(crypto.MACPurposeAccessRate, []byte(addr.normalized))
	if err != nil {
		return fmt.Errorf("mytransfers: compute address mac: %w", err)
	}
	counts, err := s.repo.recordRequest(ctx, t.ID, mac, ip, s.now())
	if err != nil {
		return fmt.Errorf("mytransfers: record link request: %w", err)
	}
	if counts.ByIP >= MaxRequestsPerIP {
		s.logEvent(ctx, t, ip, securitylog.RateLimited, securitylog.Field{Key: securitylog.KeyScope, Value: ScopeRequestIP})
		return &RateLimitError{RetryAfter: RequestWindow}
	}
	if counts.ByAddress >= MaxRequestsPerAddress {
		return nil // silently dropped (P32): the answer must not differ
	}
	s.submit(ctx, t, linkJob{tenant: t, ip: ip, mailbox: addr.mailbox, email: addr.normalized, lang: language})
	return nil
}

// isClosed reports whether Close was called.
func (s *Service) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// submit hands j to the workers without blocking: a full queue, or a queue
// closed since isClosed, drops it (logged without the address).
func (s *Service) submit(ctx context.Context, t *tenant.Tenant, j linkJob) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.closed {
		select {
		case s.jobs <- j:
			return
		default:
		}
	}
	s.logger.WarnContext(ctx, "my transfers link request dropped: queue full or closed", slog.String("tenant", t.FQDN))
}

// work processes the queued requests until the queue is closed and empty,
// or ctx is canceled.
func (s *Service) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-s.jobs:
			if !ok {
				return
			}
			s.process(ctx, j)
		}
	}
}

// process sends the access link of j when its address is verified and
// active in the tenant and not blocklisted. An unknown, expired or
// blocklisted address is ignored without any trace. Failures are logged
// without the address.
func (s *Service) process(ctx context.Context, j linkJob) {
	ctx, cancel := context.WithTimeout(ctx, s.jobTimeout)
	defer cancel()
	t := j.tenant
	if err := s.sendLink(ctx, j); err != nil {
		s.logger.ErrorContext(ctx, "my transfers link not sent", slog.String("tenant", t.FQDN), slog.String("error", err.Error()))
	}
}

// sendLink implements process; it returns nil when nothing is to be sent.
func (s *Service) sendLink(ctx context.Context, j linkJob) error {
	t := j.tenant
	now := s.now()
	v, err := s.repo.verified(ctx, t.ID, j.email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("read verified address: %w", err)
	case !v.Active(now):
		return nil
	}
	blocked, err := s.repo.blocked(ctx, t.ID, j.email)
	switch {
	case err != nil:
		return fmt.Errorf("check blocklist: %w", err)
	case blocked:
		return nil
	}
	token, err := s.newToken(id.AccessLinkTokenPrefix, id.AccessLinkTokenBytes)
	if err != nil {
		return fmt.Errorf("new access link token: %w", err)
	}
	// The mail is built before the link is stored, so that a mail that
	// cannot be built leaves no link behind. A link stored but whose mail
	// cannot be queued is unusable (its token is dropped with the job) and
	// purged once expired.
	job, err := s.notifier.MyTransfersLinkJob(ctx, t, j.lang, j.mailbox, "https://"+t.FQDN+id.MyTransfersPath+"#"+token, LinkTTL)
	if err != nil {
		return fmt.Errorf("build access link mail: %w", err)
	}
	link, err := s.repo.createLink(ctx, t.ID, tokenHash(token), j.email, now, now.Add(LinkTTL))
	if err != nil {
		return fmt.Errorf("create access link: %w", err)
	}
	if err := s.queue.Enqueue(job); err != nil {
		return fmt.Errorf("queue access link mail: %w", err)
	}
	s.record(ctx, t, j.ip, j.email, audit.ActionMyTransfersLinkRequested, audit.ObjectAccessLink, link.ID, nil)
	return nil
}
