package store

import (
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/tenant"
)

// TestTenantLegalDocumentsListFaults injects a driver failure into each
// step of the listing and checks that it surfaces as an error.
func TestTenantLegalDocumentsListFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	a, err := db.Tenants().Create(ctx, &tenant.Tenant{Name: "A", FQDN: "a.example.com", DefaultLanguage: "fr", MaxTransferBytes: 1, StorageQuotaBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.TenantLegalDocuments().Put(ctx, a.ID, LegalDocument{Document: LegalNotice, Language: "fr", Content: "c"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ op, match string }{
		{faultBegin, ""},
		{faultQuery, "FROM tenant_legal_documents"},
		{faultNext, "FROM tenant_legal_documents"},
		{faultScanNil, "FROM tenant_legal_documents"},
	} {
		plan.reset()
		plan.add(f.op, f.match, 0)
		if got, err := db.TenantLegalDocuments().List(ctx, a.ID); err == nil || got != nil {
			t.Errorf("%s fault ignored: %v, %v", f.op, got, err)
		}
	}
	plan.reset()
	if got, err := db.TenantLegalDocuments().List(ctx, a.ID); err != nil || len(got) != 1 {
		t.Errorf("List without faults = %v, %v", got, err)
	}
}
