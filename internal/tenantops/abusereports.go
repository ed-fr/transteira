package tenantops

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// MaxAbuseNoteLen bounds the note of an abuse report, in characters
// (OpenAPI AbuseReportUpdate.note).
const MaxAbuseNoteLen = 1000

// FieldNote is the JSON pointer of the note of an abuse report update.
const FieldNote = "/note"

// ListAbuseReports returns a page of the abuse reports of tenant tid,
// newest first, filtered by status ("" for all). A bad status, limit or
// cursor is an *InvalidError.
func (s *Service) ListAbuseReports(ctx context.Context, p adminauth.Principal, tid tenant.ID, status store.AbuseReportStatus, limit int, cursor string) (store.Page[store.AbuseReport], error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.Page[store.AbuseReport]{}, err
	}
	if status != "" && !status.Valid() {
		return store.Page[store.AbuseReport]{}, invalid(FieldStatus, "must be open or closed")
	}
	if err := checkLimit(limit); err != nil {
		return store.Page[store.AbuseReport]{}, err
	}
	page, err := s.repo.listAbuseReports(ctx, tid, status, limit, cursor)
	if err != nil {
		return store.Page[store.AbuseReport]{}, listError("list abuse reports", err)
	}
	return page, nil
}

// GetAbuseReport returns the abuse report repID of tenant tid; a missing
// report, and a report of another tenant, are ErrNotFound.
func (s *Service) GetAbuseReport(ctx context.Context, p adminauth.Principal, tid tenant.ID, repID string) (store.AbuseReport, error) {
	if err := s.readable(ctx, p, tid); err != nil {
		return store.AbuseReport{}, err
	}
	if !id.Valid(id.AbuseReport, repID) {
		return store.AbuseReport{}, ErrNotFound
	}
	r, err := s.repo.getAbuseReport(ctx, tid, repID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.AbuseReport{}, ErrNotFound
	case err != nil:
		return store.AbuseReport{}, fmt.Errorf("tenantops: get abuse report: %w", err)
	}
	return r, nil
}

// UpdateAbuseReport sets the status of report repID of tenant tid, with an
// optional note (control and bidirectional characters removed, mail
// addresses kept, at most [MaxAbuseNoteLen] characters). Setting the
// current status again is a no-op returning the report, without audit
// event. A change records abuse.report_closed or abuse.report_reopened.
// It requires the right to change the tenant. A concurrent change is
// ErrStateConflict.
func (s *Service) UpdateAbuseReport(ctx context.Context, p adminauth.Principal, tid tenant.ID, repID string, status store.AbuseReportStatus, note *string, ip netip.Addr) (store.AbuseReport, error) {
	if _, err := s.writable(ctx, p, tid); err != nil {
		return store.AbuseReport{}, err
	}
	if !id.Valid(id.AbuseReport, repID) {
		return store.AbuseReport{}, ErrNotFound
	}
	if !status.Valid() {
		return store.AbuseReport{}, invalid(FieldStatus, "must be open or closed")
	}
	var clean *string
	if note != nil {
		if !utf8.ValidString(*note) {
			return store.AbuseReport{}, invalid(FieldNote, "must be valid text")
		}
		n := textsafe.SanitizeMessage(*note)
		if utf8.RuneCountInString(n) > MaxAbuseNoteLen {
			return store.AbuseReport{}, invalid(FieldNote, "must be at most %d characters", MaxAbuseNoteLen)
		}
		clean = &n
	}
	r, changed, err := s.repo.setAbuseReportStatus(ctx, tid, repID, status, p.Admin.Username, clean, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.AbuseReport{}, ErrNotFound
	case errors.Is(err, store.ErrConflict):
		return store.AbuseReport{}, ErrStateConflict
	case err != nil:
		return store.AbuseReport{}, fmt.Errorf("tenantops: update abuse report: %w", err)
	}
	if changed {
		action := audit.ActionAbuseReportReopened
		if status == store.AbuseReportClosed {
			action = audit.ActionAbuseReportClosed
		}
		s.record(ctx, p, ip, tid, action, audit.ObjectAbuseReport, repID, map[string]any{"reportId": repID})
	}
	return r, nil
}
