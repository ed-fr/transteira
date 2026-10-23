package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/datasubject"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/stats"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tenantops"
)

// OperationsService serves the operations of the tenants: transfers,
// invitations, blocklist and audit log (*tenantops.Service). Every method
// checks the principal itself: a tenant the administrator is not attached
// to answers tenantops.ErrNotFound, like an unknown one.
type OperationsService interface {
	ListTransfers(ctx context.Context, p adminauth.Principal, tid tenant.ID, f tenantops.TransferFilter) (store.Page[tenantops.Transfer], error)
	GetTransfer(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID string) (tenantops.TransferDetail, error)
	DeleteTransfer(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID, reason string, ip netip.Addr) error
	ResendNotification(ctx context.Context, p adminauth.Principal, tid tenant.ID, trfID string, recipients []string, ip netip.Addr) error
	ListInvitations(ctx context.Context, p adminauth.Principal, tid tenant.ID, f tenantops.InvitationFilter) (store.Page[tenantops.Invitation], error)
	RevokeInvitation(ctx context.Context, p adminauth.Principal, tid tenant.ID, invID string, ip netip.Addr) error
	ListBlocklist(ctx context.Context, p adminauth.Principal, tid tenant.ID, f tenantops.BlocklistFilter) (store.Page[store.BlocklistEntry], error)
	CreateBlocklistEntry(ctx context.Context, p adminauth.Principal, tid tenant.ID, in tenantops.BlocklistInput, ip netip.Addr) (store.BlocklistEntry, error)
	DeleteBlocklistEntry(ctx context.Context, p adminauth.Principal, tid tenant.ID, entryID string, ip netip.Addr) error
	ListAuditEvents(ctx context.Context, p adminauth.Principal, tid tenant.ID, f tenantops.AuditFilter) (store.Page[store.AuditEvent], error)
	ListGlobalAuditEvents(ctx context.Context, p adminauth.Principal, f tenantops.GlobalAuditFilter) (store.Page[store.AuditEvent], error)
}

// DataSubjectService serves the rights of the data subjects
// (*datasubject.Service).
type DataSubjectService interface {
	Search(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, email string) (datasubject.Summary, error)
	Erase(ctx context.Context, p adminauth.Principal, ip netip.Addr, tid tenant.ID, email string) (datasubject.EraseReport, error)
}

// StatsService computes the dashboard statistics (*stats.Service).
type StatsService interface {
	TenantStats(ctx context.Context, p adminauth.Principal, tid tenant.ID, period stats.Period) (stats.TenantStats, error)
	GlobalStats(ctx context.Context, p adminauth.Principal, period stats.Period) (stats.GlobalStats, error)
}

// Compile-time checks that the services fit.
var (
	_ OperationsService  = (*tenantops.Service)(nil)
	_ DataSubjectService = (*datasubject.Service)(nil)
	_ StatsService       = (*stats.Service)(nil)
)

// WithOperationsService serves the transfer, invitation, blocklist and
// audit operations with svc. Without it they answer 500.
func WithOperationsService(svc OperationsService) Option {
	return func(s *Server) { s.opsSvc = svc }
}

// WithDataSubjectService serves the data subject operations with svc.
// Without it they answer 500.
func WithDataSubjectService(svc DataSubjectService) Option {
	return func(s *Server) { s.subjectSvc = svc }
}

// WithStatsService serves the statistics operations with svc. Without it
// they answer 500.
func WithStatsService(svc StatsService) Option {
	return func(s *Server) { s.statsSvc = svc }
}

// Wiring errors, answered 500.
var (
	errNoOperationsService  = errors.New("admin: no tenant operations service configured")
	errNoDataSubjectService = errors.New("admin: no data subject service configured")
	errNoStatsService       = errors.New("admin: no statistics service configured")
)

// fieldPeriod is the query parameter of the statistics period.
const fieldPeriod = "period"

// operationError maps an error of the operations, data subject or
// statistics service to the error the strict handler renders. The three
// services share the authorization errors of package adminauth. Server
// errors keep their cause, which is logged (the services never put an
// address, a token or a secret in it).
func operationError(err error) error {
	var (
		opsInvalid     *tenantops.InvalidError
		subjectInvalid *datasubject.InvalidError
		busy           *tenantops.BusyError
		limited        *tenantops.RateLimitError
	)
	switch {
	case errors.As(err, &opsInvalid):
		return validationFailed(opsInvalid.Field, formatCode(opsInvalid.NotAnAddress))
	case errors.As(err, &subjectInvalid):
		return validationFailed(subjectInvalid.Field, formatCode(subjectInvalid.Field == datasubject.FieldEmail))
	case errors.Is(err, stats.ErrInvalidPeriod):
		return validationFailed(fieldPeriod, fieldInvalidFormat)
	case errors.Is(err, tenantops.ErrInvalid), errors.Is(err, datasubject.ErrInvalid):
		return problem.New(problem.CodeValidationFailed)
	case errors.As(err, &busy):
		return problem.New(problem.CodeStateConflict, problem.WithRetryAfter(busy.RetryAfter))
	case errors.Is(err, datasubject.ErrBusy):
		return problem.New(problem.CodeStateConflict, problem.WithRetryAfter(datasubject.RetryAfter))
	case errors.Is(err, tenantops.ErrStateConflict):
		return problem.New(problem.CodeStateConflict)
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, tenantops.ErrRateLimited):
		return problem.New(problem.CodeRateLimited)
	case errors.Is(err, tenantops.ErrMailUnavailable):
		return problem.New(problem.CodeMailUnavailable)
	case errors.Is(err, adminauth.ErrUnauthenticated):
		return problem.New(problem.CodeUnauthenticated)
	case errors.Is(err, adminauth.ErrForbidden):
		return problem.New(problem.CodeForbidden)
	case errors.Is(err, adminauth.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, tenantops.ErrAlreadyExists):
		return problem.New(problem.CodeAlreadyExists)
	default:
		return err
	}
}

// opsSession returns the operations service and the session of the
// request, or the error to answer.
func (s *Server) opsSession(ctx context.Context) (OperationsService, adminauth.Principal, error) {
	if s.opsSvc == nil {
		return nil, adminauth.Principal{}, errNoOperationsService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.opsSvc, p, nil
}

// subjectSession returns the data subject service and the session of the
// request, or the error to answer.
func (s *Server) subjectSession(ctx context.Context) (DataSubjectService, adminauth.Principal, error) {
	if s.subjectSvc == nil {
		return nil, adminauth.Principal{}, errNoDataSubjectService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.subjectSvc, p, nil
}

// statsSession returns the statistics service and the session of the
// request, or the error to answer.
func (s *Server) statsSession(ctx context.Context) (StatsService, adminauth.Principal, error) {
	if s.statsSvc == nil {
		return nil, adminauth.Principal{}, errNoStatsService
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.statsSvc, p, nil
}

// nextCursor returns the nextCursor of a page: nil (absent) on the last
// page.
func nextCursor(c string) *gen.PageCursor {
	if c == "" {
		return nil
	}
	return &c
}

// makeLike returns a slice of the type of like with n elements: the
// generated types declare some lists with an anonymous element type.
func makeLike[S ~[]E, E any](_ S, n int) S {
	return make(S, n)
}

// --- Transfers ---------------------------------------------------------------

// ListTenantTransfers lists the transfers of a tenant, most recent first.
func (s *Server) ListTenantTransfers(ctx context.Context, req gen.ListTenantTransfersRequestObject) (gen.ListTenantTransfersResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	f := tenantops.TransferFilter{
		Status: string(deref(req.Params.Status)), Email: string(deref(req.Params.Email)),
		CreatedAfter: deref(req.Params.CreatedAfter), Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	}
	page, err := svc.ListTransfers(ctx, p, tenant.ID(req.TenantId), f)
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.ListTenantTransfers200JSONResponse{Items: make([]gen.AdminTransfer, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, t := range page.Items {
		resp.Items[i] = adminTransferBody(t)
	}
	return resp, nil
}

// adminTransferBody renders t as the OpenAPI AdminTransfer. The sender
// and the recipients are stored only once validated as bare addresses by
// the deposit and transfer services (mail.ParseAddress), so the e-mail
// fields never hold anything else. The recipients are an empty list
// rather than null.
func adminTransferBody(t tenantops.Transfer) gen.AdminTransfer {
	recipients := t.Recipients
	if recipients == nil {
		recipients = []string{}
	}
	return gen.AdminTransfer{
		Id: t.ID, Status: gen.TransferStatus(t.Status), Origin: gen.TransferOrigin(t.Origin), SenderEmail: t.SenderEmail,
		Recipients: recipients, InvitationId: optional(t.InvitationID), ApiTokenId: optional(t.APITokenID),
		FileCount: t.FileCount, TotalBytes: t.TotalBytes,
		PasswordProtected: t.PasswordProtected, DeleteAfterFirstDownload: t.DeleteAfterFirstDownload,
		CreatedAt: t.CreatedAt, ExpiresAt: optionalTime(t.ExpiresAt), FirstDownloadedAt: optionalTime(t.FirstDownloadedAt),
		DownloadCount: int(t.DownloadCount),
	}
}

// GetTenantTransfer returns the metadata and files of a transfer, never
// their content nor the download link.
func (s *Server) GetTenantTransfer(ctx context.Context, req gen.GetTenantTransferRequestObject) (gen.GetTenantTransferResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	d, err := svc.GetTransfer(ctx, p, tenant.ID(req.TenantId), req.TransferId)
	if err != nil {
		return nil, operationError(err)
	}
	t := adminTransferBody(d.Transfer)
	resp := gen.GetTenantTransfer200JSONResponse{
		Id: t.Id, Status: t.Status, Origin: t.Origin, SenderEmail: t.SenderEmail, Recipients: t.Recipients,
		InvitationId: t.InvitationId, ApiTokenId: t.ApiTokenId, FileCount: t.FileCount, TotalBytes: t.TotalBytes,
		PasswordProtected: t.PasswordProtected, DeleteAfterFirstDownload: t.DeleteAfterFirstDownload,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, FirstDownloadedAt: t.FirstDownloadedAt,
		DownloadCount: t.DownloadCount,
	}
	if d.SenderIP.IsValid() {
		ip := d.SenderIP.String()
		resp.SenderIp = &ip
	}
	resp.Files = makeLike(resp.Files, len(d.Files))
	for i, f := range d.Files {
		out := &resp.Files[i]
		out.Id, out.Name, out.Size, out.MediaType = f.ID, f.Name, f.Size, optional(f.MediaType)
		out.Sha256, out.ScanStatus = optional(f.SHA256), gen.ScanStatus(f.ScanStatus)
	}
	return resp, nil
}

// DeleteTenantTransfer crypto-erases a transfer before its expiry (204,
// also when it had already ended).
func (s *Server) DeleteTenantTransfer(ctx context.Context, req gen.DeleteTenantTransferRequestObject) (gen.DeleteTenantTransferResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	var reason string
	if req.Body != nil {
		reason = deref(req.Body.Reason)
	}
	if err := svc.DeleteTransfer(ctx, p, tenant.ID(req.TenantId), req.TransferId, reason, middleware.ClientIP(ctx)); err != nil {
		return nil, operationError(err)
	}
	return gen.DeleteTenantTransfer204Response{}, nil
}

// ResendTransferNotification queues the notification mail of a transfer
// again (202), to all or some of its recipients.
func (s *Server) ResendTransferNotification(ctx context.Context, req gen.ResendTransferNotificationRequestObject) (gen.ResendTransferNotificationResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	var recipients []string
	if req.Body != nil && req.Body.Recipients != nil {
		for _, r := range *req.Body.Recipients {
			recipients = append(recipients, string(r))
		}
	}
	if err := svc.ResendNotification(ctx, p, tenant.ID(req.TenantId), req.TransferId, recipients, middleware.ClientIP(ctx)); err != nil {
		return nil, operationError(err)
	}
	return gen.ResendTransferNotification202Response{}, nil
}

// --- Invitations -------------------------------------------------------------

// ListTenantInvitations lists the invitations of a tenant with their
// issuer and status.
func (s *Server) ListTenantInvitations(ctx context.Context, req gen.ListTenantInvitationsRequestObject) (gen.ListTenantInvitationsResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListInvitations(ctx, p, tenant.ID(req.TenantId), tenantops.InvitationFilter{
		Status: string(deref(req.Params.Status)), Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	})
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.ListTenantInvitations200JSONResponse{Items: make([]gen.Invitation, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, inv := range page.Items {
		// The invitee is a bare address (validated by the deposit service);
		// InvitedBy holds the pseudonym after an erasure of the issuer.
		resp.Items[i] = gen.Invitation{
			Id: inv.ID, Email: inv.Email, InvitedBy: inv.InvitedBy, Status: gen.InvitationStatus(inv.Status),
			CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt, LastUsedAt: optionalTime(inv.LastUsedAt),
		}
	}
	return resp, nil
}

// RevokeInvitation revokes an invitation (204, also when it was already
// revoked or expired).
func (s *Server) RevokeInvitation(ctx context.Context, req gen.RevokeInvitationRequestObject) (gen.RevokeInvitationResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.RevokeInvitation(ctx, p, tenant.ID(req.TenantId), req.InvitationId, middleware.ClientIP(ctx)); err != nil {
		return nil, operationError(err)
	}
	return gen.RevokeInvitation204Response{}, nil
}

// --- Blocklist ---------------------------------------------------------------

// ListBlocklist lists the blocklist entries of a tenant.
func (s *Server) ListBlocklist(ctx context.Context, req gen.ListBlocklistRequestObject) (gen.ListBlocklistResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListBlocklist(ctx, p, tenant.ID(req.TenantId), tenantops.BlocklistFilter{
		Kind: string(deref(req.Params.Kind)), Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	})
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.ListBlocklist200JSONResponse{Items: make([]gen.BlocklistEntry, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, e := range page.Items {
		resp.Items[i] = blocklistBody(e)
	}
	return resp, nil
}

// CreateBlocklistEntry adds an address, a domain or a fingerprint to the
// blocklist of a tenant (201).
func (s *Server) CreateBlocklistEntry(ctx context.Context, req gen.CreateBlocklistEntryRequestObject) (gen.CreateBlocklistEntryResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	// A missing body is checked by the service after the access, so that a
	// tenant the administrator may not change answers 404 whatever the body.
	var in tenantops.BlocklistInput
	if req.Body != nil {
		in = tenantops.BlocklistInput{Kind: string(req.Body.Kind), Value: req.Body.Value, Comment: deref(req.Body.Comment)}
	}
	e, err := svc.CreateBlocklistEntry(ctx, p, tenant.ID(req.TenantId), in, middleware.ClientIP(ctx))
	switch {
	case err != nil && req.Body == nil && errors.Is(err, tenantops.ErrInvalid):
		return nil, validationFailed(tenantops.FieldKind, fieldRequired)
	case err != nil:
		return nil, operationError(err)
	}
	return gen.CreateBlocklistEntry201JSONResponse(blocklistBody(e)), nil
}

// DeleteBlocklistEntry removes an entry from the blocklist of a tenant
// (204).
func (s *Server) DeleteBlocklistEntry(ctx context.Context, req gen.DeleteBlocklistEntryRequestObject) (gen.DeleteBlocklistEntryResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := svc.DeleteBlocklistEntry(ctx, p, tenant.ID(req.TenantId), req.EntryId, middleware.ClientIP(ctx)); err != nil {
		return nil, operationError(err)
	}
	return gen.DeleteBlocklistEntry204Response{}, nil
}

// blocklistBody renders e as the OpenAPI BlocklistEntry: an empty comment
// is absent.
func blocklistBody(e store.BlocklistEntry) gen.BlocklistEntry {
	return gen.BlocklistEntry{
		Id: e.ID, Kind: gen.BlocklistKind(e.Kind), Value: e.Value, Comment: optional(e.Comment),
		CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt,
	}
}

// --- Audit log ---------------------------------------------------------------

// ListTenantAuditEvents returns the audit log of a tenant, most recent
// first.
func (s *Server) ListTenantAuditEvents(ctx context.Context, req gen.ListTenantAuditEventsRequestObject) (gen.ListTenantAuditEventsResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListAuditEvents(ctx, p, tenant.ID(req.TenantId), tenantops.AuditFilter{
		Action: string(deref(req.Params.Action)), Actor: deref(req.Params.Actor),
		From: deref(req.Params.From), To: deref(req.Params.To),
		Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	})
	if err != nil {
		return nil, operationError(err)
	}
	list, err := auditListBody(page)
	if err != nil {
		return nil, err
	}
	return gen.ListTenantAuditEvents200JSONResponse(list), nil
}

// ListGlobalAuditEvents returns the audit log of the instance (super
// admin), most recent first.
func (s *Server) ListGlobalAuditEvents(ctx context.Context, req gen.ListGlobalAuditEventsRequestObject) (gen.ListGlobalAuditEventsResponseObject, error) {
	svc, p, err := s.opsSession(ctx)
	if err != nil {
		return nil, err
	}
	page, err := svc.ListGlobalAuditEvents(ctx, p, tenantops.GlobalAuditFilter{
		TenantID: tenant.ID(deref(req.Params.TenantId)), Action: string(deref(req.Params.Action)),
		Cursor: deref(req.Params.Cursor), Limit: deref(req.Params.Limit),
	})
	if err != nil {
		return nil, operationError(err)
	}
	list, err := auditListBody(page)
	if err != nil {
		return nil, err
	}
	return gen.ListGlobalAuditEvents200JSONResponse(list), nil
}

// auditListBody renders a page of audit events as the OpenAPI
// AuditEventList.
func auditListBody(page store.Page[store.AuditEvent]) (gen.AuditEventList, error) {
	out := gen.AuditEventList{Items: make([]gen.AuditEvent, len(page.Items)), NextCursor: nextCursor(page.NextCursor)}
	for i, ev := range page.Items {
		item := &out.Items[i]
		item.Id, item.OccurredAt, item.Action = ev.ID, ev.At, gen.AuditAction(ev.Action)
		item.TenantId = optional(string(ev.TenantID))
		item.Actor.Kind, item.Actor.Id = gen.AuditEventActorKind(ev.ActorKind), ev.Actor
		item.Object.Kind, item.Object.Id = ev.ObjectKind, ev.ObjectID
		if ev.IP.IsValid() {
			ip := ev.IP.String()
			item.Ip = &ip
		}
		if len(ev.Details) > 0 {
			var details map[string]any
			if err := json.Unmarshal(ev.Details, &details); err != nil {
				return gen.AuditEventList{}, fmt.Errorf("admin: decode the details of audit event %s: %w", ev.ID, err)
			}
			if details != nil {
				item.Details = &details
			}
		}
	}
	return out, nil
}

// --- Statistics --------------------------------------------------------------

// GetTenantStats returns the dashboard statistics of a tenant.
func (s *Server) GetTenantStats(ctx context.Context, req gen.GetTenantStatsRequestObject) (gen.GetTenantStatsResponseObject, error) {
	svc, p, err := s.statsSession(ctx)
	if err != nil {
		return nil, err
	}
	// The service checks the period after the access.
	st, err := svc.TenantStats(ctx, p, tenant.ID(req.TenantId), stats.Period(deref(req.Params.Period)))
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.GetTenantStats200JSONResponse{
		Period: gen.TenantStatsPeriod(st.Period), TransferCount: int(st.Transfers), BytesUploaded: st.BytesUploaded,
		DownloadCount: int(st.Downloads), BytesDownloaded: st.BytesDownloaded, VirusDetections: int(st.VirusDetections),
		StorageUsedBytes: st.UsedBytes, StorageQuotaBytes: st.QuotaBytes, StorageUsedRatio: float32(st.UsedRatio),
	}
	resp.Series = makeLike(resp.Series, len(st.Series))
	for i, pt := range st.Series {
		out := &resp.Series[i]
		out.Date, out.Transfers, out.BytesUploaded = openapi_types.Date{Time: pt.Date}, int(pt.Transfers), pt.BytesUploaded
	}
	return resp, nil
}

// GetGlobalStats returns the disk usage and the statistics of every
// active tenant (super admin).
func (s *Server) GetGlobalStats(ctx context.Context, req gen.GetGlobalStatsRequestObject) (gen.GetGlobalStatsResponseObject, error) {
	svc, p, err := s.statsSession(ctx)
	if err != nil {
		return nil, err
	}
	// The service checks the period after the access.
	st, err := svc.GlobalStats(ctx, p, stats.Period(deref(req.Params.Period)))
	if err != nil {
		return nil, operationError(err)
	}
	resp := gen.GetGlobalStats200JSONResponse{Period: gen.GlobalStatsPeriod(st.Period)}
	resp.Disk.TotalBytes, resp.Disk.UsedBytes = byteSize(st.Disk.TotalBytes), byteSize(st.Disk.UsedBytes)
	resp.Disk.UsedRatio, resp.Disk.AlertThreshold = float32(st.Disk.UsedRatio), float32(st.Disk.AlertThreshold)
	resp.Tenants = makeLike(resp.Tenants, len(st.Tenants))
	for i, row := range st.Tenants {
		out := &resp.Tenants[i]
		out.TenantId, out.Name = string(row.TenantID), row.Name
		out.TransferCount, out.BytesUploaded = int(row.Transfers), row.BytesUploaded
		out.StorageUsedBytes, out.StorageQuotaBytes, out.StorageUsedRatio = row.UsedBytes, row.QuotaBytes, float32(row.UsedRatio)
	}
	return resp, nil
}

// byteSize converts a filesystem size, capped at the largest ByteSize.
func byteSize(n uint64) gen.ByteSize {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}
	return gen.ByteSize(n)
}

// --- Data subjects -----------------------------------------------------------

// SearchDataSubject counts the data of a tenant linked to a mail address.
func (s *Server) SearchDataSubject(ctx context.Context, req gen.SearchDataSubjectRequestObject) (gen.SearchDataSubjectResponseObject, error) {
	svc, p, err := s.subjectSession(ctx)
	if err != nil {
		return nil, err
	}
	sum, err := svc.Search(ctx, p, middleware.ClientIP(ctx), tenant.ID(req.TenantId), subjectAddress(req.Body))
	if err != nil {
		return nil, subjectError(err, subjectAddress(req.Body))
	}
	return gen.SearchDataSubject200JSONResponse{
		Email: sum.Email, VerifiedAddress: sum.VerifiedAddress, TransfersAsSender: sum.TransfersAsSender,
		TransfersAsRecipient: sum.TransfersAsRecipient, Invitations: sum.Invitations, AuditEvents: sum.AuditEvents,
		SecurityEvents: sum.SecurityEvents,
	}, nil
}

// EraseDataSubject erases the data of a tenant linked to a mail address
// and reports what was done.
func (s *Server) EraseDataSubject(ctx context.Context, req gen.EraseDataSubjectRequestObject) (gen.EraseDataSubjectResponseObject, error) {
	svc, p, err := s.subjectSession(ctx)
	if err != nil {
		return nil, err
	}
	rep, err := svc.Erase(ctx, p, middleware.ClientIP(ctx), tenant.ID(req.TenantId), subjectAddress(req.Body))
	if err != nil {
		return nil, subjectError(err, subjectAddress(req.Body))
	}
	return gen.EraseDataSubject200JSONResponse{
		TransfersDeleted: rep.TransfersDeleted, RecipientEntriesRemoved: rep.RecipientEntriesRemoved,
		VerifiedAddressDeleted: rep.VerifiedAddressDeleted, InvitationsDeleted: rep.InvitationsDeleted,
		LogEntriesPseudonymised: rep.LogEntriesPseudonymised,
	}, nil
}

// subjectAddress returns the address of a data subject request, empty
// without a body: the service checks it after the access, so that a tenant
// the administrator may not change answers 404 whatever the body.
func subjectAddress(b *gen.DataSubjectRequest) string {
	if b == nil {
		return ""
	}
	return b.Email
}

// subjectError maps an error of the data subject service for the address
// addr: an empty address is reported as required rather than malformed.
func subjectError(err error, addr string) error {
	if addr == "" && errors.Is(err, datasubject.ErrInvalid) {
		return validationFailed(datasubject.FieldEmail, fieldRequired)
	}
	return operationError(err)
}
