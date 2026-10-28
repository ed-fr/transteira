package tenantadmin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// maxNameLen bounds a tenant name, in characters (OpenAPI Tenant.name).
const maxNameLen = 100

// TenantView is a tenant as returned to an administrator (OpenAPI Tenant).
type TenantView struct {
	ID                 tenant.ID
	Name               string
	FQDN               string
	DefaultLanguage    string
	MaxTransferBytes   int64
	MaxTransferCeiling int64
	StorageQuotaBytes  int64
	StorageUsedBytes   int64
	// Status is active, or deleting while a deletion is in progress (only
	// the super admin sees such a tenant, to resume its deletion).
	Status tenant.Status
	// WebhookIncludeAddresses tells whether the tenant webhooks receive the
	// addresses concerned by an event.
	WebhookIncludeAddresses bool
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// TenantPage is a page of tenants.
type TenantPage struct {
	Items []TenantView
	// NextCursor is the cursor of the next page, "" on the last one.
	NextCursor string
}

// TenantCreate is the input of [Service.CreateTenant] (OpenAPI
// TenantCreate).
type TenantCreate struct {
	Name              string
	FQDN              string
	DefaultLanguage   string
	StorageQuotaBytes int64
	// MaxTransferBytes is the transfer limit; 0 means the ceiling when
	// one is given, else [tenant.MaxTransferLimit].
	MaxTransferBytes int64
	// MaxTransferCeiling is the ceiling of MaxTransferBytes for the
	// delegated admins; nil means MaxTransferBytes.
	MaxTransferCeiling *int64
}

// TenantUpdate is the input of [Service.UpdateTenant] (OpenAPI
// TenantUpdate, JSON Merge Patch): a nil field is left unchanged.
type TenantUpdate struct {
	Name              *string
	FQDN              *string
	DefaultLanguage   *string
	StorageQuotaBytes *int64
	MaxTransferBytes  *int64
	// MaxTransferCeiling is the ceiling of MaxTransferBytes, super admin
	// only.
	MaxTransferCeiling *int64
	// WebhookIncludeAddresses turns on or off the addresses in the payloads
	// of the tenant webhooks; a delegated admin may change it.
	WebhookIncludeAddresses *bool
}

// view builds the administrator view of t with its storage usage.
func (s *Service) view(ctx context.Context, t *tenant.Tenant) (TenantView, error) {
	used, err := s.repo.usedBytes(ctx, t.ID)
	if err != nil {
		return TenantView{}, fmt.Errorf("tenantadmin: storage usage: %w", err)
	}
	return TenantView{
		ID: t.ID, Name: t.Name, FQDN: t.FQDN, DefaultLanguage: t.DefaultLanguage,
		MaxTransferBytes: t.MaxTransferBytes, MaxTransferCeiling: t.MaxTransferCeiling,
		StorageQuotaBytes: t.StorageQuotaBytes, StorageUsedBytes: used, Status: t.Status,
		WebhookIncludeAddresses: t.WebhookIncludeAddresses, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}, nil
}

// ListTenants returns the tenants visible to p: every tenant, page by page,
// for the super admin (deleting ones included); the active tenants it is
// attached to, in one page, for a delegated admin. A malformed cursor is
// an *InvalidError.
func (s *Service) ListTenants(ctx context.Context, p adminauth.Principal, cursor string, limit int) (TenantPage, error) {
	if err := adminauth.RequireAuthenticated(p); err != nil {
		return TenantPage{}, err
	}
	var (
		items []*tenant.Tenant
		next  string
	)
	if adminauth.RequireSuperAdmin(p.Admin) == nil {
		page, err := s.repo.listTenants(ctx, store.TenantListOptions{Cursor: cursor, Limit: limit})
		switch {
		case errors.Is(err, store.ErrInvalid):
			return TenantPage{}, invalid("cursor", "malformed cursor")
		case err != nil:
			return TenantPage{}, fmt.Errorf("tenantadmin: list tenants: %w", err)
		}
		items, next = page.Items, page.NextCursor
	} else {
		for _, tid := range p.Admin.TenantIDs {
			if !adminauth.CanAccessTenant(p.Admin, tid) {
				continue
			}
			t, err := s.activeTenant(ctx, tid)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return TenantPage{}, err
			}
			items = append(items, t)
		}
	}
	out := TenantPage{Items: make([]TenantView, 0, len(items)), NextCursor: next}
	for _, t := range items {
		v, err := s.view(ctx, t)
		if err != nil {
			return TenantPage{}, err
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}

// GetTenant returns tenant tid. The super admin also reaches a tenant
// being deleted.
func (s *Service) GetTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID) (TenantView, error) {
	var (
		t   *tenant.Tenant
		err error
	)
	if superAdmin(p) == nil {
		t, err = s.tenant(ctx, tid)
	} else {
		t, err = s.readable(ctx, p, tid)
	}
	if err != nil {
		return TenantView{}, err
	}
	return s.view(ctx, t)
}

// CreateTenant creates a tenant (super admin only) with the default
// branding; templates and legal documents use the built-in defaults until
// customized. The transfer limit and its ceiling are set in one step: the
// ceiling defaults to the limit and the limit to the ceiling. It returns an
// *InvalidError for a malformed field, a limit above the ceiling or an FQDN
// equal to an admin host, and ErrAlreadyExists for an FQDN already used.
func (s *Service) CreateTenant(ctx context.Context, p adminauth.Principal, in TenantCreate, ip netip.Addr) (TenantView, error) {
	if err := superAdmin(p); err != nil {
		return TenantView{}, err
	}
	name, err := checkName(in.Name)
	if err != nil {
		return TenantView{}, err
	}
	fqdn, err := s.checkFQDN(in.FQDN)
	if err != nil {
		return TenantView{}, err
	}
	if !tenant.IsLanguage(in.DefaultLanguage) {
		return TenantView{}, invalid(FieldDefaultLanguage, "unsupported language")
	}
	if in.StorageQuotaBytes <= 0 {
		return TenantView{}, invalid(FieldStorageQuotaBytes, "must be positive")
	}
	maxBytes, ceiling, err := createLimits(in)
	if err != nil {
		return TenantView{}, err
	}
	t, err := s.repo.createTenant(ctx, &tenant.Tenant{
		Name: name, FQDN: fqdn, DefaultLanguage: in.DefaultLanguage, StorageQuotaBytes: in.StorageQuotaBytes,
		MaxTransferBytes: maxBytes, MaxTransferCeiling: ceiling,
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		return TenantView{}, ErrAlreadyExists
	case err != nil:
		return TenantView{}, fmt.Errorf("tenantadmin: create tenant: %w", err)
	}
	s.invalidate(t.ID, t.FQDN)
	s.record(ctx, p, ip, t.ID, ActionTenantCreated, map[string]any{"name": audit.RedactAddresses(t.Name), "fqdn": t.FQDN})
	return s.view(ctx, t)
}

// createLimits returns the transfer limit and ceiling of a new tenant.
func createLimits(in TenantCreate) (limit, ceiling int64, err error) {
	limit = in.MaxTransferBytes
	if in.MaxTransferCeiling != nil {
		ceiling = *in.MaxTransferCeiling
		if err := checkTransferBytes(FieldMaxTransferCeiling, ceiling); err != nil {
			return 0, 0, err
		}
		if limit == 0 {
			limit = ceiling
		}
	}
	if limit == 0 {
		limit = tenant.MaxTransferLimit
	}
	if err := checkTransferBytes(FieldMaxTransferBytes, limit); err != nil {
		return 0, 0, err
	}
	if in.MaxTransferCeiling == nil {
		ceiling = limit
	}
	if limit > ceiling {
		return 0, 0, invalid(FieldMaxTransferBytes, "must not exceed the ceiling")
	}
	return limit, ceiling, nil
}

// UpdateTenant changes the general settings of tenant tid. The super admin
// may change every field; when it sets the transfer limit above the
// ceiling without a new ceiling, the ceiling rises with it, and a ceiling
// below the limit lowers the limit. A delegated admin may only change the
// default language and the webhook address option, and set the transfer
// limit at most to the ceiling:
// another changed field, or a limit above the ceiling, is ErrForbidden.
// The audit event names the changed fields.
func (s *Service) UpdateTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, in TenantUpdate, ip netip.Addr) (TenantView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.writable(ctx, p, tid)
	if err != nil {
		return TenantView{}, err
	}
	next, err := s.applyUpdate(cur, in, superAdmin(p) == nil)
	if err != nil {
		return TenantView{}, err
	}
	changed := changedFields(cur, next)
	if len(changed) == 0 {
		return s.view(ctx, cur)
	}
	t, err := s.repo.updateTenant(ctx, next)
	switch {
	case errors.Is(err, store.ErrConflict):
		return TenantView{}, ErrAlreadyExists
	case errors.Is(err, store.ErrNotFound):
		return TenantView{}, ErrNotFound
	case err != nil:
		return TenantView{}, fmt.Errorf("tenantadmin: update tenant: %w", err)
	}
	s.invalidate(t.ID, cur.FQDN, t.FQDN)
	s.record(ctx, p, ip, t.ID, ActionTenantUpdated, map[string]any{"fields": changed})
	return s.view(ctx, t)
}

// applyUpdate validates in against cur and returns the updated tenant.
func (s *Service) applyUpdate(cur *tenant.Tenant, in TenantUpdate, super bool) (*tenant.Tenant, error) {
	next := cur.Clone()
	var err error
	if in.Name != nil {
		if next.Name, err = checkName(*in.Name); err != nil {
			return nil, err
		}
	}
	if in.FQDN != nil {
		if next.FQDN, err = s.checkFQDN(*in.FQDN); err != nil {
			return nil, err
		}
	}
	if in.DefaultLanguage != nil {
		if !tenant.IsLanguage(*in.DefaultLanguage) {
			return nil, invalid(FieldDefaultLanguage, "unsupported language")
		}
		next.DefaultLanguage = *in.DefaultLanguage
	}
	if in.StorageQuotaBytes != nil {
		if *in.StorageQuotaBytes <= 0 {
			return nil, invalid(FieldStorageQuotaBytes, "must be positive")
		}
		next.StorageQuotaBytes = *in.StorageQuotaBytes
	}
	if in.WebhookIncludeAddresses != nil {
		next.WebhookIncludeAddresses = *in.WebhookIncludeAddresses
	}
	if in.MaxTransferCeiling != nil {
		if err := checkTransferBytes(FieldMaxTransferCeiling, *in.MaxTransferCeiling); err != nil {
			return nil, err
		}
		next.MaxTransferCeiling = *in.MaxTransferCeiling
		next.MaxTransferBytes = min(next.MaxTransferBytes, next.MaxTransferCeiling)
	}
	if in.MaxTransferBytes != nil {
		if err := checkTransferBytes(FieldMaxTransferBytes, *in.MaxTransferBytes); err != nil {
			return nil, err
		}
		next.MaxTransferBytes = *in.MaxTransferBytes
		if next.MaxTransferBytes > next.MaxTransferCeiling {
			switch {
			case !super:
				return nil, ErrForbidden
			case in.MaxTransferCeiling != nil:
				return nil, invalid(FieldMaxTransferBytes, "must not exceed the ceiling")
			}
			next.MaxTransferCeiling = next.MaxTransferBytes
		}
	}
	if !super && (next.Name != cur.Name || next.FQDN != cur.FQDN ||
		next.StorageQuotaBytes != cur.StorageQuotaBytes || next.MaxTransferCeiling != cur.MaxTransferCeiling) {
		return nil, ErrForbidden
	}
	return next, nil
}

// changedFields returns the API names of the fields that differ.
func changedFields(a, b *tenant.Tenant) []string {
	var out []string
	add := func(diff bool, name string) {
		if diff {
			out = append(out, name)
		}
	}
	add(a.Name != b.Name, "name")
	add(a.FQDN != b.FQDN, "fqdn")
	add(a.DefaultLanguage != b.DefaultLanguage, "defaultLanguage")
	add(a.StorageQuotaBytes != b.StorageQuotaBytes, "storageQuotaBytes")
	add(a.MaxTransferBytes != b.MaxTransferBytes, "maxTransferBytes")
	add(a.MaxTransferCeiling != b.MaxTransferCeiling, "maxTransferCeiling")
	add(a.WebhookIncludeAddresses != b.WebhookIncludeAddresses, "webhookIncludeAddresses")
	return out
}

// DeleteTenant deletes tenant tid and all its data (super admin only).
// confirm must be the exact tenant name, else an *InvalidError on
// [FieldConfirm]. The tenant first moves to the deleting status (it stops
// resolving and accepts no further change) and the tenant.deletion_started
// event records the administrator (also on a resumed deletion), then the
// eraser erases it; the eraser itself records tenant.deleted once done.
// The erasure runs on a context detached from the cancellation of ctx, so
// that a client disconnecting does not stop it halfway. An interrupted
// deletion leaves the tenant deleting: calling DeleteTenant again (or the
// hourly eraser run) resumes it. The audit and security logs of the tenant
// are kept until their retention ends.
func (s *Service) DeleteTenant(ctx context.Context, p adminauth.Principal, tid tenant.ID, confirm string, ip netip.Addr) error {
	if err := superAdmin(p); err != nil {
		return err
	}
	t, err := s.tenant(ctx, tid)
	if err != nil {
		return err
	}
	if confirm != t.Name {
		return invalid(FieldConfirm, "must be the exact tenant name")
	}
	resumed := t.Status != tenant.StatusActive
	if !resumed {
		if err := s.repo.setTenantStatus(ctx, tid, tenant.StatusDeleting); err != nil {
			return fmt.Errorf("tenantadmin: start tenant deletion: %w", err)
		}
	}
	s.invalidate(tid, t.FQDN)
	// Detached from the request: the erasure must not stop halfway because
	// the client went away (it would only resume at the next hourly run).
	ectx := context.WithoutCancel(ctx)
	s.record(ectx, p, ip, tid, ActionTenantDeletionStarted, map[string]any{
		"name": audit.RedactAddresses(t.Name), "fqdn": t.FQDN, "resumed": resumed,
	})
	if err := s.eraser.EraseTenant(ectx, tid); err != nil {
		return fmt.Errorf("tenantadmin: erase tenant: %w", err)
	}
	s.invalidate(tid, t.FQDN)
	return nil
}

// checkName validates a tenant name and returns it trimmed.
func checkName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(name)
	if n == 0 || n > maxNameLen || !utf8.ValidString(name) {
		return "", invalid(FieldName, "must be 1 to %d characters", maxNameLen)
	}
	if strings.ContainsFunc(name, func(r rune) bool {
		return textsafe.IsControl(r) || textsafe.IsBidiControl(r) || textsafe.IsLineSeparator(r)
	}) {
		return "", invalid(FieldName, "must not contain control characters")
	}
	return name, nil
}

// checkFQDN validates and normalizes a tenant FQDN: a host name without
// port, never one of the admin hosts.
func (s *Service) checkFQDN(raw string) (string, error) {
	if strings.ContainsAny(raw, ":/@ []") {
		return "", invalid(FieldFQDN, "must be a host name without port")
	}
	fqdn, err := tenant.NormalizeHost(raw)
	if err != nil {
		return "", invalid(FieldFQDN, "must be a valid host name")
	}
	if slices.Contains(s.adminHosts, fqdn) {
		return "", &InvalidError{Field: FieldFQDN, Reason: "must not be an admin host", Code: CodeAdminHost}
	}
	return fqdn, nil
}

// checkTransferBytes validates a transfer limit or ceiling.
func checkTransferBytes(field string, n int64) error {
	if n <= 0 || n > tenant.MaxTransferLimit {
		return invalid(field, "must be between 1 and %d bytes", tenant.MaxTransferLimit)
	}
	return nil
}
