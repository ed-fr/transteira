package tenantadmin

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestLegal(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		d, err := ev.svc.GetLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr")
		mustNoErr(t, "get empty", err)
		if d.Markdown != "" || !d.UpdatedAt.IsZero() {
			t.Fatalf("empty: %+v", d)
		}
		docs, err := ev.svc.LegalDocuments(ctx, ev.a)
		mustNoErr(t, "documents", err)
		if len(docs) != 0 {
			t.Fatalf("documents: %v", docs)
		}
		_, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "fr")
		wantErr(t, "public none", err, ErrNotFound)

		src := "# Mentions\n\n<script>alert(1)</script> [site](javascript:alert(1)) **gras**"
		d, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", src, clientIP)
		mustNoErr(t, "update", err)
		if d.Markdown != src || d.UpdatedAt.IsZero() {
			t.Fatalf("stored: %+v", d)
		}
		d, err = ev.svc.GetLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr")
		mustNoErr(t, "get", err)
		if d.Markdown != src {
			t.Fatalf("get: %+v", d)
		}

		// Public: the negotiated language, else the default (en for A),
		// else any written language: A only has fr here, served for all.
		p, err := ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "fr")
		mustNoErr(t, "public fr", err)
		if p.Language != "fr" || strings.Contains(p.HTML, "<script") || strings.Contains(p.HTML, "javascript:") ||
			!strings.Contains(p.HTML, "<strong>gras</strong>") {
			t.Fatalf("public: %+v", p)
		}
		p, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "en")
		mustNoErr(t, "public en without default version", err)
		if p.Language != "fr" {
			t.Fatalf("any-language fallback %q", p.Language)
		}
		docs, err = ev.svc.LegalDocuments(ctx, ev.a)
		mustNoErr(t, "documents fr only", err)
		if !slices.Equal(docs, []string{store.LegalNotice}) {
			t.Fatalf("documents: %v", docs)
		}
		_, err = ev.svc.PublicLegal(ctx, ev.a, store.PrivacyPolicy, "fr")
		wantErr(t, "public other document", err, ErrNotFound)
		_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "en", "Legal notice", clientIP)
		mustNoErr(t, "update en", err)
		p, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "de")
		mustNoErr(t, "fallback", err)
		if p.Language != "en" {
			t.Fatalf("fallback language %q", p.Language)
		}
		// The negotiated language comes first when written.
		p, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "fr")
		mustNoErr(t, "negotiated", err)
		if p.Language != "fr" {
			t.Fatalf("negotiated language %q", p.Language)
		}
		_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.PrivacyPolicy, "fr", "Privacy", clientIP)
		mustNoErr(t, "update privacy", err)
		docs, _ = ev.svc.LegalDocuments(ctx, ev.a)
		if !slices.Equal(docs, []string{store.LegalNotice, store.PrivacyPolicy}) {
			t.Fatalf("documents: %v", docs)
		}
		_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.PrivacyPolicy, "fr", "", clientIP)
		mustNoErr(t, "remove privacy", err)
		docs, _ = ev.svc.LegalDocuments(ctx, ev.a)
		if !slices.Equal(docs, []string{store.LegalNotice}) {
			t.Fatalf("documents: %v", docs)
		}

		// A blank source removes the document.
		d, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "en", "  \n", clientIP)
		mustNoErr(t, "remove", err)
		if d.Markdown != "" {
			t.Fatalf("removed: %+v", d)
		}
		_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "en", "", clientIP)
		mustNoErr(t, "remove again", err)
		if n := len(ev.auditEvents(t, ev.a.ID, ActionTenantLegalUpdated)); n != 6 {
			t.Fatalf("%d events", n)
		}

		_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", "a\x00b", clientIP)
		wantInvalid(t, "nul", err, FieldMarkdown)
		_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", strings.Repeat("a", store.MaxLegalContentLen+1), clientIP)
		wantInvalid(t, "long", err, FieldMarkdown)
		for _, k := range [][2]string{{"terms", "fr"}, {store.PrivacyPolicy, "de"}} {
			_, err = ev.svc.GetLegal(ctx, ev.adminA, ev.a.ID, k[0], k[1])
			wantErr(t, "get "+k[0], err, ErrNotFound)
			_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, k[0], k[1], "x", clientIP)
			wantErr(t, "update "+k[0], err, ErrNotFound)
		}
		_, err = ev.svc.PublicLegal(ctx, ev.a, "terms", "fr")
		wantErr(t, "public unknown", err, ErrNotFound)
		_, err = ev.svc.GetLegal(ctx, ev.adminB, ev.a.ID, store.LegalNotice, "fr")
		wantErr(t, "other get", err, ErrNotFound)
		_, err = ev.svc.UpdateLegal(ctx, ev.adminB, ev.a.ID, store.LegalNotice, "fr", "x", clientIP)
		wantErr(t, "other update", err, ErrNotFound)
		// B never sees A's documents.
		_, err = ev.svc.PublicLegal(ctx, ev.b, store.LegalNotice, "fr")
		wantErr(t, "public of B", err, ErrNotFound)
	})
}

func TestLegalFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	_, err := ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", "x", clientIP)
	mustNoErr(t, "seed", err)
	f := ev.faults("legal", "putLegal", "deleteLegal", "listLegal")
	_, err = ev.svc.GetLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr")
	wantErr(t, "get", err, errBoom)
	_, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "fr")
	wantErr(t, "public list", err, errBoom)
	_, err = ev.svc.LegalDocuments(ctx, ev.a)
	wantErr(t, "documents", err, errBoom)
	delete(f.errs, "listLegal")
	_, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "fr")
	wantErr(t, "public get", err, errBoom)
	// Removed between the listing and the read.
	f.errs["legal"] = store.ErrNotFound
	_, err = ev.svc.PublicLegal(ctx, ev.a, store.LegalNotice, "fr")
	wantErr(t, "public removed", err, ErrNotFound)
	f.errs["legal"] = errBoom
	_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", "x", clientIP)
	wantErr(t, "put", err, errBoom)
	_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", "", clientIP)
	wantErr(t, "delete", err, errBoom)
	f.errs["putLegal"] = store.ErrInvalid
	_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", "x", clientIP)
	wantInvalid(t, "store invalid", err, FieldMarkdown)
	f.errs["putLegal"] = store.ErrNotFound
	_, err = ev.svc.UpdateLegal(ctx, ev.adminA, ev.a.ID, store.LegalNotice, "fr", "x", clientIP)
	wantErr(t, "gone", err, ErrNotFound)
}
