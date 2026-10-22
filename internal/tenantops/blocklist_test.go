package tenantops

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestCreateBlocklistEntry normalizes, validates and stores an entry, and
// audits it without ever recording a mail address.
func TestCreateBlocklistEntry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		email, err := ev.svc.CreateBlocklistEntry(ctx, ev.adminA, ev.a.ID,
			BlocklistInput{Kind: "email", Value: " Mallory@Example.NET ", Comment: "Phishing attempts"}, clientIP)
		mustNoErr(t, "create email", err)
		if !id.Valid(id.Blocklist, email.ID) || email.Kind != store.BlockEmail || email.Value != "mallory@example.net" ||
			email.Comment != "Phishing attempts" || email.CreatedBy != "alice.admin" || email.CreatedAt.IsZero() {
			t.Fatalf("email entry = %+v", email)
		}
		domain, err := ev.svc.CreateBlocklistEntry(ctx, ev.super, ev.a.ID,
			BlocklistInput{Kind: "domain", Value: "Spam.Example.net"}, clientIP)
		mustNoErr(t, "create domain", err)
		hash, err := ev.svc.CreateBlocklistEntry(ctx, ev.adminA, ev.a.ID,
			BlocklistInput{Kind: "sha256", Value: strings.ToUpper(fingerprint)}, clientIP)
		mustNoErr(t, "create sha256", err)
		if domain.Value != "spam.example.net" || domain.CreatedBy != "root" || hash.Value != fingerprint {
			t.Errorf("normalized values = %q, %q", domain.Value, hash.Value)
		}

		evs := ev.auditEvents(ev.a.ID, audit.ActionBlocklistUpdated)
		if len(evs) != 3 {
			t.Fatalf("audit events = %d, want 3", len(evs))
		}
		byID := map[string]store.AuditEvent{}
		for _, a := range evs {
			byID[a.ObjectID] = a
		}
		emailDetails := ev.details(byID[email.ID])
		if _, ok := emailDetails["value"]; ok || emailDetails["op"] != "created" || emailDetails["kind"] != "email" ||
			emailDetails["entryId"] != email.ID || byID[email.ID].ObjectKind != audit.ObjectBlocklistEntry ||
			byID[email.ID].IP != clientIP {
			t.Errorf("email entry audit = %+v", byID[email.ID])
		}
		if d := ev.details(byID[domain.ID]); d["value"] != "spam.example.net" || d["kind"] != "domain" {
			t.Errorf("domain entry audit details = %v", d)
		}
		if d := ev.details(byID[hash.ID]); d["value"] != fingerprint || d["kind"] != "sha256" {
			t.Errorf("sha256 entry audit details = %v", d)
		}

		_, err = ev.svc.CreateBlocklistEntry(ctx, ev.adminA, ev.a.ID, BlocklistInput{Kind: "email", Value: "MALLORY@example.net"}, clientIP)
		wantErr(t, "duplicate", err, ErrAlreadyExists)
		_, err = ev.svc.CreateBlocklistEntry(ctx, ev.adminB, ev.b.ID, BlocklistInput{Kind: "email", Value: "mallory@example.net"}, clientIP)
		mustNoErr(t, "same value in B", err)

		for _, c := range []struct {
			in    BlocklistInput
			field string
		}{
			{BlocklistInput{Kind: "ip", Value: "192.0.2.1"}, FieldKind},
			{BlocklistInput{Kind: "", Value: "x"}, FieldKind},
			{BlocklistInput{Kind: "domain", Value: "   "}, FieldValue},
			{BlocklistInput{Kind: "domain", Value: strings.Repeat("a", MaxBlocklistValueLen+1)}, FieldValue},
			{BlocklistInput{Kind: "email", Value: "no-at-sign"}, FieldValue},
			{BlocklistInput{Kind: "domain", Value: "user@spam.example.net"}, FieldValue},
			{BlocklistInput{Kind: "sha256", Value: "abc"}, FieldValue},
			{BlocklistInput{Kind: "domain", Value: "ok.example.net", Comment: strings.Repeat("x", MaxBlocklistCommentLen+1)}, FieldComment},
			{BlocklistInput{Kind: "domain", Value: "ok.example.net", Comment: "\xff"}, FieldComment},
		} {
			_, err := ev.svc.CreateBlocklistEntry(ctx, ev.adminA, ev.a.ID, c.in, clientIP)
			wantInvalid(t, "create "+c.in.Kind+" "+c.field, err, c.field)
		}
		ev.faults("createBlocklistEntry")
		_, err = ev.svc.CreateBlocklistEntry(ctx, ev.adminA, ev.a.ID, BlocklistInput{Kind: "domain", Value: "new.example.net"}, clientIP)
		wantErr(t, "create failure", err, errBoom)
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionBlocklistUpdated)); n != 3 {
			t.Errorf("audit events after refusals = %d, want 3", n)
		}
	})
}

// TestListBlocklist lists the entries of a tenant, by kind and by page.
func TestListBlocklist(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		for _, in := range []BlocklistInput{
			{Kind: "email", Value: "mallory@example.net"},
			{Kind: "domain", Value: "spam.example.net"},
			{Kind: "sha256", Value: fingerprint},
		} {
			_, err := ev.svc.CreateBlocklistEntry(ctx, ev.adminA, ev.a.ID, in, clientIP)
			mustNoErr(t, "create", err)
		}
		_, err := ev.svc.CreateBlocklistEntry(ctx, ev.adminB, ev.b.ID, BlocklistInput{Kind: "domain", Value: "other.example.net"}, clientIP)
		mustNoErr(t, "create in B", err)

		page, err := ev.svc.ListBlocklist(ctx, ev.adminA, ev.a.ID, BlocklistFilter{})
		if err != nil || len(page.Items) != 3 || page.NextCursor != "" {
			t.Fatalf("list = %+v, %v", page, err)
		}
		page, err = ev.svc.ListBlocklist(ctx, ev.adminA, ev.a.ID, BlocklistFilter{Kind: "domain"})
		if err != nil || len(page.Items) != 1 || page.Items[0].Value != "spam.example.net" {
			t.Errorf("kind filter = %+v, %v", page, err)
		}
		page, err = ev.svc.ListBlocklist(ctx, ev.super, ev.a.ID, BlocklistFilter{Limit: 2})
		if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
			t.Fatalf("first page = %+v, %v", page, err)
		}
		page, err = ev.svc.ListBlocklist(ctx, ev.super, ev.a.ID, BlocklistFilter{Limit: 2, Cursor: page.NextCursor})
		if err != nil || len(page.Items) != 1 {
			t.Errorf("second page = %+v, %v", page, err)
		}
		_, err = ev.svc.ListBlocklist(ctx, ev.adminA, ev.a.ID, BlocklistFilter{Kind: "ip"})
		wantInvalid(t, "kind", err, FieldKindParam)
		_, err = ev.svc.ListBlocklist(ctx, ev.adminA, ev.a.ID, BlocklistFilter{Limit: -5})
		wantInvalid(t, "limit", err, FieldLimit)
		_, err = ev.svc.ListBlocklist(ctx, ev.adminA, ev.a.ID, BlocklistFilter{Cursor: "garbage"})
		wantInvalid(t, "cursor", err, FieldCursor)
		ev.faults("listBlocklist")
		_, err = ev.svc.ListBlocklist(ctx, ev.adminA, ev.a.ID, BlocklistFilter{})
		wantErr(t, "list failure", err, errBoom)
	})
}

// TestDeleteBlocklistEntry removes an entry and audits it like its
// creation.
func TestDeleteBlocklistEntry(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		email, err := ev.db.Blocklist().Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: store.BlockEmail, Value: "mallory@example.net"})
		mustNoErr(t, "email", err)
		domain, err := ev.db.Blocklist().Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: store.BlockDomain, Value: "spam.example.net"})
		mustNoErr(t, "domain", err)

		mustNoErr(t, "delete email", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, email.ID, clientIP))
		mustNoErr(t, "delete domain", ev.svc.DeleteBlocklistEntry(ctx, ev.super, ev.a.ID, domain.ID, clientIP))
		if _, err := ev.db.Blocklist().Get(ctx, ev.a.ID, email.ID); err == nil {
			t.Error("the entry is still listed")
		}
		byID := map[string]store.AuditEvent{}
		for _, a := range ev.auditEvents(ev.a.ID, audit.ActionBlocklistUpdated) {
			byID[a.ObjectID] = a
		}
		if d := ev.details(byID[email.ID]); d["op"] != "deleted" || d["kind"] != "email" || d["entryId"] != email.ID || d["value"] != nil {
			t.Errorf("email deletion audit = %v", d)
		}
		if d := ev.details(byID[domain.ID]); d["op"] != "deleted" || d["value"] != "spam.example.net" || byID[domain.ID].Actor != "root" {
			t.Errorf("domain deletion audit = %v", d)
		}

		wantErr(t, "again", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, email.ID, clientIP), ErrNotFound)
		wantErr(t, "malformed", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, "blk_bad", clientIP), ErrNotFound)
		wantErr(t, "missing", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, missingBlk, clientIP), ErrNotFound)

		fresh, err := ev.db.Blocklist().Create(ctx, ev.a.ID, store.BlocklistEntry{Kind: store.BlockSHA256, Value: fingerprint})
		mustNoErr(t, "fresh", err)
		f := ev.faults("getBlocklistEntry")
		wantErr(t, "get failure", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, fresh.ID, clientIP), errBoom)
		f.errs = map[string]error{"deleteBlocklistEntry": errBoom}
		wantErr(t, "delete failure", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, fresh.ID, clientIP), errBoom)
		f.errs = map[string]error{"deleteBlocklistEntry": store.ErrNotFound}
		wantErr(t, "deleted concurrently", ev.svc.DeleteBlocklistEntry(ctx, ev.adminA, ev.a.ID, fresh.ID, clientIP), ErrNotFound)
		if n := len(ev.auditEvents(ev.a.ID, audit.ActionBlocklistUpdated)); n != 2 {
			t.Errorf("audit events = %d, want 2", n)
		}
	})
}
