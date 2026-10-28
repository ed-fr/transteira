package store_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// intp returns a pointer to n.
func intp(n int) *int { return &n }

func TestConfidentialityRulesHelpers(t *testing.T) {
	t.Parallel()
	for days, bit := range map[int]int{1: store.ExpiryMask1Day, 7: store.ExpiryMask7Days, 30: store.ExpiryMask30Days, 2: 0, 0: 0} {
		if got := store.ExpiryDayBit(days); got != bit {
			t.Errorf("ExpiryDayBit(%d) = %d, want %d", days, got, bit)
		}
	}
	for _, tc := range []struct {
		days []int
		mask int
		ok   bool
	}{
		{[]int{1, 7, 30}, store.ExpiryMaskAll, true},
		{[]int{30, 1, 1}, 5, true},
		{nil, 0, false},
		{[]int{7, 14}, 0, false},
	} {
		if mask, ok := store.ExpiryDaysMaskOf(tc.days); mask != tc.mask || ok != tc.ok {
			t.Errorf("ExpiryDaysMaskOf(%v) = %d, %v", tc.days, mask, ok)
		}
	}
	if got := store.ExpiryDaysOfMask(3); !slices.Equal(got, []int{1, 7}) {
		t.Errorf("ExpiryDaysOfMask(3) = %v", got)
	}
	if got := store.ExpiryDaysOfMask(0); got == nil || len(got) != 0 {
		t.Errorf("ExpiryDaysOfMask(0) = %#v", got)
	}
	r := store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMask1Day | store.ExpiryMask30Days}
	if !r.AllowsExpiry(1) || r.AllowsExpiry(7) || !r.AllowsExpiry(30) || r.AllowsExpiry(2) {
		t.Errorf("AllowsExpiry with mask 5 is wrong")
	}
	if got := r.AllowedExpiryDays(); !slices.Equal(got, []int{1, 30}) {
		t.Errorf("AllowedExpiryDays = %v", got)
	}
	if !r.AllowsMaxDownloads(nil) || !r.AllowsMaxDownloads(intp(1000)) {
		t.Error("rules without cap must allow any limit")
	}
	r.MaxDownloadsCap = intp(5)
	if r.AllowsMaxDownloads(nil) || r.AllowsMaxDownloads(intp(6)) || !r.AllowsMaxDownloads(intp(5)) {
		t.Error("rules with a cap of 5 must allow 1 to 5 only")
	}
}

// seededLevels are the levels Tenants.Create seeds (migration 0016).
func checkSeededLevels(t *testing.T, levels []store.ConfidentialityLevel) {
	t.Helper()
	want := []struct {
		key     string
		def     bool
		mask    int
		strict  bool
		labelFr string
	}{
		{"public", false, 7, false, "Public"},
		{"internal", true, 7, false, "Interne"},
		{"confidential", false, 3, true, "Confidentiel"}, //nolint:misspell // French label
	}
	if len(levels) != len(want) {
		t.Fatalf("seeded levels = %+v", levels)
	}
	for i, w := range want {
		l := levels[i]
		r := l.Rules
		if l.Key != w.key || l.Position != i || l.IsDefault != w.def || r.ExpiryDaysMask != w.mask ||
			r.RequirePassword != w.strict || r.RequireRecipientVerification != w.strict || r.InternalRecipientsOnly != w.strict ||
			r.ForceDeleteAfterFirstDownload || r.MaxDownloadsCap != nil || l.Labels["fr"] != w.labelFr ||
			l.Descriptions == nil || len(l.Descriptions) != 0 || l.UpdatedBy != "" || !l.UpdatedAt.Equal(time.UnixMilli(0)) {
			t.Errorf("seeded level %d = %+v", i, l)
		}
	}
}

// twoLevels returns a valid list of two levels, the second the default.
func twoLevels() []store.ConfidentialityLevel {
	return []store.ConfidentialityLevel{
		{
			Key: "secret_1", Labels: map[string]string{"fr": "Secret", "en": "Secret"},
			Descriptions: map[string]string{"fr": "Très sensible.\nAvec deux lignes.", "en": ""},
			Rules: store.ConfidentialityRules{
				ExpiryDaysMask: store.ExpiryMask1Day, MaxDownloadsCap: intp(3), RequirePassword: true,
				RequireRecipientVerification: true, InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
			},
			Position: 7, // ignored: assigned from the order
		},
		{
			Key: "open-a", Labels: map[string]string{"fr": "Ouvert", "en": "Open"}, IsDefault: true,
			Rules: store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMaskAll},
		},
	}
}

func TestConfidentialityLevels(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		b := newTenant(t, db, "b.example.com")
		repo := db.ConfidentialityLevels()

		// Seeded with the tenant.
		levels, err := repo.List(ctx, a.ID)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		checkSeededLevels(t, levels)
		if d, err := repo.Default(ctx, a.ID); err != nil || d.Key != "internal" {
			t.Errorf("Default = %+v, %v", d, err)
		}
		if c, err := repo.Get(ctx, a.ID, "confidential"); err != nil || c.Position != 2 || !c.Rules.RequirePassword {
			t.Errorf("Get(confidential) = %+v, %v", c, err)
		}
		_, err = repo.Get(ctx, a.ID, "missing")
		wantErr(t, "Get(missing)", err, store.ErrNotFound)
		_, err = repo.Get(ctx, a.ID, "Bad Key")
		wantErr(t, "Get(malformed)", err, store.ErrInvalid)

		// Replace.
		later := fixedNow.Add(time.Hour)
		in := twoLevels()
		out, err := repo.Replace(ctx, a.ID, in, "adm_01", later)
		if err != nil {
			t.Fatalf("Replace: %v", err)
		}
		check := func(name string, got []store.ConfidentialityLevel) {
			t.Helper()
			if len(got) != 2 {
				t.Fatalf("%s = %+v", name, got)
			}
			s, o := got[0], got[1]
			if s.Key != "secret_1" || s.Position != 0 || s.IsDefault || s.Rules.MaxDownloadsCap == nil || *s.Rules.MaxDownloadsCap != 3 ||
				!s.Rules.RequirePassword || !s.Rules.RequireRecipientVerification || !s.Rules.InternalRecipientsOnly ||
				!s.Rules.ForceDeleteAfterFirstDownload || s.Rules.ExpiryDaysMask != 1 ||
				!maps.Equal(s.Descriptions, map[string]string{"fr": "Très sensible.\nAvec deux lignes."}) ||
				!maps.Equal(s.Labels, map[string]string{"fr": "Secret", "en": "Secret"}) ||
				s.UpdatedBy != "adm_01" || !s.UpdatedAt.Equal(later.Truncate(time.Millisecond)) {
				t.Errorf("%s[0] = %+v", name, s)
			}
			if o.Key != "open-a" || o.Position != 1 || !o.IsDefault || o.Rules.MaxDownloadsCap != nil || o.Rules.RequirePassword ||
				o.Descriptions == nil || len(o.Descriptions) != 0 || o.Labels["en"] != "Open" {
				t.Errorf("%s[1] = %+v", name, o)
			}
		}
		check("Replace result", out)
		// The result is a copy: changing the input changes nothing.
		*in[0].Rules.MaxDownloadsCap, in[0].Labels["fr"] = 9, "x"
		check("Replace result after input change", out)
		stored, err := repo.List(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		check("List", stored)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			got, err := repo.ListTx(ctx, tx)
			check("ListTx", got)
			return err
		})
		if err != nil {
			t.Errorf("ListTx: %v", err)
		}
		if d, err := repo.Default(ctx, a.ID); err != nil || d.Key != "open-a" {
			t.Errorf("Default after Replace = %+v, %v", d, err)
		}
		// Zero now uses the store's clock, an empty author is allowed.
		if out, err := repo.Replace(ctx, a.ID, twoLevels(), "", time.Time{}); err != nil || !out[0].UpdatedAt.Equal(fixedNow.Truncate(time.Millisecond)) {
			t.Errorf("Replace(zero now) = %+v, %v", out, err)
		}
		if _, err := repo.Replace(ctx, a.ID, twoLevels(), "adm_01", later); err != nil {
			t.Fatal(err)
		}

		// Isolation: tenant B keeps its seeded levels, never sees A's, and
		// its replace leaves A intact.
		levelsB, err := repo.List(ctx, b.ID)
		if err != nil {
			t.Fatal(err)
		}
		checkSeededLevels(t, levelsB)
		_, err = repo.Get(ctx, b.ID, "secret_1")
		wantErr(t, "Get(B, A's key)", err, store.ErrNotFound)
		onlyB := []store.ConfidentialityLevel{{
			Key: "secret_1", Labels: map[string]string{"fr": "B", "en": "B"}, IsDefault: true,
			Rules: store.ConfidentialityRules{ExpiryDaysMask: 2},
		}}
		if _, err := repo.Replace(ctx, b.ID, onlyB, "adm_b", later); err != nil {
			t.Fatalf("Replace(B): %v", err)
		}
		stored, _ = repo.List(ctx, a.ID)
		check("List(A) after Replace(B)", stored)
		if got, err := repo.Get(ctx, b.ID, "secret_1"); err != nil || got.Labels["fr"] != "B" || !got.IsDefault {
			t.Errorf("Get(B) = %+v, %v", got, err)
		}

		// Invalid lists change nothing.
		mutate := func(f func([]store.ConfidentialityLevel) []store.ConfidentialityLevel) []store.ConfidentialityLevel {
			return f(twoLevels())
		}
		long := strings.Repeat("é", store.MaxLevelLabelRunes+1)
		for name, tc := range map[string]struct {
			levels []store.ConfidentialityLevel
			by     string
		}{
			"empty":       {levels: nil},
			"too many":    {levels: slices.Repeat(twoLevels()[:1], store.MaxConfidentialityLevels+1)},
			"author":      {levels: twoLevels(), by: strings.Repeat("a", store.MaxLevelUpdatedByRunes+1)},
			"author line": {levels: twoLevels(), by: "a\nb"},
			"key upper":   {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Key = "Secret"; return l })},
			"key digit":   {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Key = "1a"; return l })},
			"key long": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Key = "a" + strings.Repeat("b", store.MaxLevelKeyLen)
				return l
			})},
			"key char":     {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Key = "a.b"; return l })},
			"key empty":    {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Key = ""; return l })},
			"duplicate":    {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Key = "open-a"; return l })},
			"no default":   {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[1].IsDefault = false; return l })},
			"two defaults": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].IsDefault = true; return l })},
			"label missing": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Labels = map[string]string{"fr": "x"}
				return l
			})},
			"label language": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Labels = map[string]string{"fr": "x", "de": "x"}
				return l
			})},
			"label extra": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Labels["de"] = "x"
				return l
			})},
			"label blank": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Labels["en"] = "  "; return l })},
			"label long":  {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel { l[0].Labels["en"] = long; return l })},
			"label line": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Labels["en"] = "a\nb"
				return l
			})},
			"description language": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Descriptions = map[string]string{"de": "x"}
				return l
			})},
			"description long": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Descriptions = map[string]string{"en": strings.Repeat("x", store.MaxLevelDescriptionRunes+1)}
				return l
			})},
			"mask zero": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Rules.ExpiryDaysMask = 0
				return l
			})},
			"mask high": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Rules.ExpiryDaysMask = 8
				return l
			})},
			"cap zero": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Rules.MaxDownloadsCap = intp(0)
				return l
			})},
			"cap high": {levels: mutate(func(l []store.ConfidentialityLevel) []store.ConfidentialityLevel {
				l[0].Rules.MaxDownloadsCap = intp(store.MaxDownloadsLimit + 1)
				return l
			})},
		} {
			_, err := repo.Replace(ctx, a.ID, tc.levels, tc.by, later)
			wantErr(t, "Replace("+name+")", err, store.ErrInvalid)
		}
		stored, _ = repo.List(ctx, a.ID)
		if len(stored) != 2 || stored[0].Key != "secret_1" {
			t.Errorf("levels after invalid replaces = %+v", stored)
		}

		// Ten levels are accepted.
		ten := make([]store.ConfidentialityLevel, store.MaxConfidentialityLevels)
		for i := range ten {
			ten[i] = store.ConfidentialityLevel{
				Key: "l" + string(rune('a'+i)), Labels: map[string]string{"fr": "x", "en": "y"}, IsDefault: i == 9,
				Rules: store.ConfidentialityRules{ExpiryDaysMask: 7, MaxDownloadsCap: intp(store.MaxDownloadsLimit)},
			}
		}
		if out, err := repo.Replace(ctx, a.ID, ten, "adm", later); err != nil || out[9].Position != 9 || !out[9].IsDefault {
			t.Errorf("Replace(10 levels) = %v", err)
		}

		// Unknown or malformed tenants.
		ghost := tenant.ID(id.New(id.Tenant))
		_, err = repo.Replace(ctx, ghost, twoLevels(), "", later)
		wantErr(t, "Replace(unknown tenant)", err, store.ErrNotFound)
		if l, err := repo.List(ctx, ghost); err != nil || len(l) != 0 {
			t.Errorf("List(unknown tenant) = %+v, %v", l, err)
		}
		_, err = repo.Default(ctx, ghost)
		wantErr(t, "Default(unknown tenant)", err, store.ErrNotFound)
		_, err = repo.List(ctx, "")
		wantErr(t, "List(empty id)", err, store.ErrInvalid)
		_, err = repo.Replace(ctx, "ten_bad", twoLevels(), "", later)
		wantErr(t, "Replace(bad id)", err, store.ErrInvalid)

		// Deleting the tenant cascades.
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatalf("Delete(B): %v", err)
		}
		if l, _ := repo.List(ctx, b.ID); len(l) != 0 {
			t.Errorf("levels of a deleted tenant: %+v", l)
		}
	})
}

func TestConfidentialityLevelsConcurrentReplace(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = db.ConfidentialityLevels().Replace(ctx, a.ID, twoLevels(), "adm", fixedNow)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("Replace #%d: %v", i, err)
			}
		}
		if l, err := db.ConfidentialityLevels().List(ctx, a.ID); err != nil || len(l) != 2 {
			t.Errorf("List = %+v, %v", l, err)
		}
	})
}

func TestRecipientRules(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "a.example.com")
		b := newTenant(t, db, "b.example.com")
		repo := db.RecipientRules()

		empty, err := repo.Get(ctx, a.ID)
		if err != nil || empty.Allowed == nil || empty.Denied == nil || len(empty.Allowed)+len(empty.Denied) != 0 {
			t.Fatalf("Get(empty) = %+v, %v", empty, err)
		}
		in := store.RecipientRuleSet{
			Allowed: []string{"partner.example.org", "entity-a.example.com", "xn--bcher-kva.example"},
			Denied:  []string{"mail.example.net", "entity-a.example.com"},
		}
		want := store.RecipientRuleSet{
			Allowed: []string{"entity-a.example.com", "partner.example.org", "xn--bcher-kva.example"},
			Denied:  []string{"entity-a.example.com", "mail.example.net"},
		}
		check := func(name string, got store.RecipientRuleSet) {
			t.Helper()
			if !slices.Equal(got.Allowed, want.Allowed) || !slices.Equal(got.Denied, want.Denied) {
				t.Errorf("%s = %+v, want %+v", name, got, want)
			}
		}
		out, err := repo.Replace(ctx, a.ID, in, fixedNow)
		if err != nil {
			t.Fatalf("Replace: %v", err)
		}
		check("Replace result", out)
		if in.Allowed[0] != "partner.example.org" {
			t.Error("Replace sorted the caller's slice")
		}
		got, err := repo.Get(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		check("Get", got)
		err = inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
			got, err := repo.GetTx(ctx, tx)
			check("GetTx", got)
			return err
		})
		if err != nil {
			t.Errorf("GetTx: %v", err)
		}

		// Isolation: B sees nothing, and its replace leaves A intact.
		if other, err := repo.Get(ctx, b.ID); err != nil || len(other.Allowed)+len(other.Denied) != 0 {
			t.Errorf("Get(B) = %+v, %v", other, err)
		}
		if _, err := repo.Replace(ctx, b.ID, store.RecipientRuleSet{Denied: []string{"b.example.com"}}, time.Time{}); err != nil {
			t.Fatalf("Replace(B): %v", err)
		}
		got, _ = repo.Get(ctx, a.ID)
		check("Get(A) after Replace(B)", got)

		// Invalid rules change nothing.
		maxed := make([]string, store.MaxRecipientRules+1)
		for i := range maxed {
			maxed[i] = "d" + strings.Repeat("x", i%50) + ".example"
		}
		for name, rs := range map[string]store.RecipientRuleSet{
			"upper":     {Allowed: []string{"Example.com"}},
			"empty":     {Denied: []string{""}},
			"leading":   {Denied: []string{".example.com"}},
			"trailing":  {Allowed: []string{"example.com."}},
			"double":    {Allowed: []string{"a..example.com"}},
			"unicode":   {Allowed: []string{"bücher.example"}},
			"space":     {Allowed: []string{"a example.com"}},
			"long":      {Allowed: []string{strings.Repeat("a", store.MaxRecipientDomainLen+1)}},
			"duplicate": {Denied: []string{"x.example", "y.example", "x.example"}},
			"too many":  {Allowed: maxed},
		} {
			_, err := repo.Replace(ctx, a.ID, rs, fixedNow)
			wantErr(t, "Replace("+name+")", err, store.ErrInvalid)
		}
		got, _ = repo.Get(ctx, a.ID)
		check("Get(A) after invalid replaces", got)

		// A full list and a 253-byte domain are accepted.
		full := make([]string, store.MaxRecipientRules)
		for i := range full {
			full[i] = fmt.Sprintf("d%03d.example", i)
		}
		long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
		if _, err := repo.Replace(ctx, a.ID, store.RecipientRuleSet{Allowed: full, Denied: []string{long}}, fixedNow); err != nil {
			t.Errorf("Replace(full) = %v", err)
		}
		if got, _ := repo.Get(ctx, a.ID); len(got.Allowed) != store.MaxRecipientRules || got.Denied[0] != long {
			t.Errorf("Get(full) = %d allowed, %v", len(got.Allowed), got.Denied)
		}

		// Clearing.
		if out, err := repo.Replace(ctx, a.ID, store.RecipientRuleSet{}, fixedNow); err != nil || out.Allowed == nil || len(out.Allowed) != 0 {
			t.Fatalf("Replace(clear) = %+v, %v", out, err)
		}
		if got, _ := repo.Get(ctx, a.ID); len(got.Allowed)+len(got.Denied) != 0 {
			t.Errorf("rules after clear = %+v", got)
		}

		// Unknown or malformed tenants.
		ghost := tenant.ID(id.New(id.Tenant))
		_, err = repo.Replace(ctx, ghost, store.RecipientRuleSet{Allowed: []string{"x.example"}}, fixedNow)
		wantErr(t, "Replace(unknown tenant)", err, store.ErrNotFound)
		_, err = repo.Get(ctx, "")
		wantErr(t, "Get(empty id)", err, store.ErrInvalid)
		_, err = repo.Replace(ctx, "ten_bad", store.RecipientRuleSet{}, fixedNow)
		wantErr(t, "Replace(bad id)", err, store.ErrInvalid)

		// Deleting the tenant cascades.
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatalf("Delete(B): %v", err)
		}
		if got, _ := repo.Get(ctx, b.ID); len(got.Denied) != 0 {
			t.Errorf("rules of a deleted tenant: %+v", got)
		}
	})
}

// confidentialTransfer returns a valid transfer with every V1.1 option of
// this step set.
func confidentialTransfer() store.Transfer {
	tr := newTransfer()
	tr.MaxDownloads = intp(5)
	tr.ConfidentialityLevel = "confidential"
	tr.ConfidentialityLabel = map[string]string{"fr": "Confidentiel", "en": "Confidential"} //nolint:misspell // French label
	tr.Rules = &store.ConfidentialityRules{
		ExpiryDaysMask: 3, MaxDownloadsCap: intp(10), RequirePassword: true,
		RequireRecipientVerification: true, InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
	}
	return tr
}

func TestTransfersConfidentialitySnapshot(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")

		// Round trip of every new field.
		tr := confidentialTransfer()
		d := mustTransfer(t, db, a.ID, tr)
		r := d.Rules
		if d.MaxDownloads == nil || *d.MaxDownloads != 5 || d.ConfidentialityLevel != "confidential" ||
			!maps.Equal(d.ConfidentialityLabel, tr.ConfidentialityLabel) || r == nil || r.ExpiryDaysMask != 3 ||
			r.MaxDownloadsCap == nil || *r.MaxDownloadsCap != 10 || !r.RequirePassword || !r.RequireRecipientVerification ||
			!r.InternalRecipientsOnly || !r.ForceDeleteAfterFirstDownload {
			t.Errorf("transfer with options = %+v, rules %+v", d.Transfer, r)
		}
		// A level without cap, and false rules, read back as such.
		tr = confidentialTransfer()
		tr.MaxDownloads, tr.Rules = nil, &store.ConfidentialityRules{ExpiryDaysMask: 7}
		d = mustTransfer(t, db, a.ID, tr)
		if d.MaxDownloads != nil || d.Rules == nil || *d.Rules != (store.ConfidentialityRules{ExpiryDaysMask: 7}) {
			t.Errorf("transfer with a plain level = %+v, rules %+v", d.Transfer, d.Rules)
		}
		// Without any option.
		d = mustTransfer(t, db, a.ID, newTransfer())
		if d.MaxDownloads != nil || d.ConfidentialityLevel != "" || d.ConfidentialityLabel != nil || d.Rules != nil {
			t.Errorf("plain transfer = %+v", d.Transfer)
		}
		// The bounds of the limit.
		for _, n := range []int{1, store.MaxDownloadsLimit} {
			tr := newTransfer()
			tr.MaxDownloads = intp(n)
			if d := mustTransfer(t, db, a.ID, tr); *d.MaxDownloads != n {
				t.Errorf("MaxDownloads %d read back as %d", n, *d.MaxDownloads)
			}
		}
		// An empty label map without level is accepted.
		tr = newTransfer()
		tr.ConfidentialityLabel = map[string]string{}
		if d := mustTransfer(t, db, a.ID, tr); d.ConfidentialityLabel != nil {
			t.Errorf("empty label = %#v", d.ConfidentialityLabel)
		}

		// Inconsistent snapshots are refused.
		for name, f := range map[string]func(*store.Transfer){
			"max zero":       func(tr *store.Transfer) { tr.MaxDownloads = intp(0) },
			"max high":       func(tr *store.Transfer) { tr.MaxDownloads = intp(store.MaxDownloadsLimit + 1) },
			"label no level": func(tr *store.Transfer) { tr.ConfidentialityLevel = "" },
			"rules no level": func(tr *store.Transfer) { tr.ConfidentialityLevel, tr.ConfidentialityLabel = "", nil },
			"bad level":      func(tr *store.Transfer) { tr.ConfidentialityLevel = "Confidential" },
			"no label":       func(tr *store.Transfer) { tr.ConfidentialityLabel = nil },
			"half label":     func(tr *store.Transfer) { tr.ConfidentialityLabel = map[string]string{"fr": "x"} },
			"long label":     func(tr *store.Transfer) { tr.ConfidentialityLabel["en"] = strings.Repeat("x", 51) },
			"no rules":       func(tr *store.Transfer) { tr.Rules = nil },
			"bad mask":       func(tr *store.Transfer) { tr.Rules.ExpiryDaysMask = 0 },
			"bad cap":        func(tr *store.Transfer) { tr.Rules.MaxDownloadsCap = intp(1001) },
		} {
			tr := confidentialTransfer()
			f(&tr)
			fl := newFile(t, db, a.ID, "x", 1)
			err := inTx(t, db, a.ID, func(tx *store.ScopedTx) error {
				return db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.org"}, []store.TransferFile{fl})
			})
			wantErr(t, "CreateTx("+name+")", err, store.ErrInvalid)
		}
	})
}

// limitedTransfer creates an available transfer of tid limited to max
// downloads, with the "delete after the first download" option set to
// deleteOpt.
func limitedTransfer(t *testing.T, db *store.DB, tid tenant.ID, maxDownloads int, deleteOpt bool) store.TransferDetails {
	t.Helper()
	ctx := context.Background()
	fl := newFile(t, db, tid, "f.bin", 10)
	fl.SHA256, fl.CiphertextSize, fl.UploadedAt = sha1111, 50, fixedNow
	tr := newTransfer()
	tr.MaxDownloads, tr.DeleteAfterFirstDownload = intp(maxDownloads), deleteOpt
	d := mustTransfer(t, db, tid, tr, fl)
	err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
		if err := db.Transfers().FinalizeTx(ctx, tx, d.ID, fixedNow); err != nil {
			return err
		}
		return db.TransferFiles().SetScanResultTx(ctx, tx, d.Files[0].ID, store.ScanClean, "", fixedNow)
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	markAvailable(t, db, tid, d.ID)
	return d
}

func TestTransfersClaimDownload(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		grace := fixedNow.Add(time.Hour)
		claim := func(tid tenant.ID, trfID string, deleteAfter time.Time) (int, error) {
			var remaining int
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				remaining, err = transfers.ClaimDownloadTx(ctx, tx, trfID, deleteAfter)
				return err
			})
			return remaining, err
		}
		get := func(tid tenant.ID, trfID string) store.TransferDetails {
			t.Helper()
			d, err := transfers.Get(ctx, tid, trfID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			return d
		}

		d := limitedTransfer(t, db, a.ID, 3, false)
		// Tenant B cannot claim A's transfer.
		_, err := claim(b.ID, d.ID, grace)
		wantErr(t, "claim from B", err, store.ErrNotFound)
		for i, want := range []int{2, 1, 0} {
			remaining, err := claim(a.ID, d.ID, grace)
			if err != nil || remaining != want {
				t.Fatalf("claim #%d = %d, %v; want %d", i, remaining, err, want)
			}
			got := get(a.ID, d.ID)
			if got.DownloadCount != int64(i+1) || got.DeleteAfter.IsZero() != (want > 0) {
				t.Errorf("after claim #%d: count %d, delete after %v", i, got.DownloadCount, got.DeleteAfter)
			}
		}
		if got := get(a.ID, d.ID); !got.DeleteAfter.Equal(grace.Truncate(time.Millisecond)) || got.Status != store.TransferAvailable {
			t.Errorf("at the limit: %+v", got.Transfer)
		}
		_, err = claim(a.ID, d.ID, grace.Add(time.Hour))
		wantErr(t, "claim over the limit", err, store.ErrMaxDownloads)
		if got := get(a.ID, d.ID); got.DownloadCount != 3 || !got.DeleteAfter.Equal(grace.Truncate(time.Millisecond)) {
			t.Errorf("after a refused claim: %+v", got.Transfer)
		}

		// An earlier due time (delete after the first download) is kept.
		del := limitedTransfer(t, db, a.ID, 1, true)
		first := fixedNow.Add(time.Minute)
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := transfers.MarkFirstDownloadTx(ctx, tx, del.ID, fixedNow, first)
			return err
		})
		if err != nil {
			t.Fatalf("MarkFirstDownloadTx: %v", err)
		}
		if remaining, err := claim(a.ID, del.ID, grace); err != nil || remaining != 0 {
			t.Errorf("claim(delete option) = %d, %v", remaining, err)
		}
		if got := get(a.ID, del.ID); !got.DeleteAfter.Equal(first.Truncate(time.Millisecond)) {
			t.Errorf("delete after = %v, want the earlier %v", got.DeleteAfter, first)
		}

		// Errors.
		_, err = claim(a.ID, d.ID, time.Time{})
		wantErr(t, "zero deleteAfter", err, store.ErrInvalid)
		_, err = claim(a.ID, id.New(id.Transfer), grace)
		wantErr(t, "missing transfer", err, store.ErrNotFound)
		_, err = claim(a.ID, availableTransfer(t, db, a.ID, false).ID, grace)
		wantErr(t, "unlimited transfer", err, store.ErrInvalid)
		tr := newTransfer()
		tr.MaxDownloads = intp(2)
		uploading := mustTransfer(t, db, a.ID, tr)
		_, err = claim(a.ID, uploading.ID, grace)
		wantErr(t, "uploading transfer", err, store.ErrConflict)
	})
}

func TestTransfersClaimDownloadConcurrent(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		d := limitedTransfer(t, db, a.ID, 3, false)
		const n = 12
		var wg sync.WaitGroup
		errs := make([]error, n)
		s, err := db.Scoped(a.ID)
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = s.Tx(ctx, func(tx *store.ScopedTx) error {
					_, err := db.Transfers().ClaimDownloadTx(ctx, tx, d.ID, fixedNow.Add(time.Hour))
					return err
				})
			}()
		}
		wg.Wait()
		ok, refused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrMaxDownloads):
				refused++
			default:
				t.Errorf("concurrent claim: %v", err)
			}
		}
		if ok != 3 || refused != n-3 {
			t.Errorf("concurrent claims: %d accepted, %d refused; want 3 and %d", ok, refused, n-3)
		}
		got, err := db.Transfers().Get(ctx, a.ID, d.ID)
		if err != nil || got.DownloadCount != 3 || got.DeleteAfter.IsZero() {
			t.Errorf("after concurrent claims: %+v, %v", got.Transfer, err)
		}
	})
}

func TestValidLevelKey(t *testing.T) {
	t.Parallel()
	for k, want := range map[string]bool{
		"a": true, "internal": true, "c0n_f-1": true, strings.Repeat("a", 32): true,
		"": false, "A": false, "1a": false, "_a": false, "a b": false, "aé": false, strings.Repeat("a", 33): false,
	} {
		if got := store.ValidLevelKey(k); got != want {
			t.Errorf("ValidLevelKey(%q) = %v", k, got)
		}
	}
}

func TestLevelLabel(t *testing.T) {
	t.Parallel()
	labels := map[string]string{"fr": "Interne", "en": "Internal"}
	for _, c := range []struct {
		texts map[string]string
		langs []string
		want  string
	}{
		{labels, []string{"fr", "en"}, "Interne"},
		{labels, []string{"", "en"}, "Internal"},
		{labels, []string{"de", "fr", "en"}, "Interne"},
		{map[string]string{"fr": "", "en": "Internal"}, []string{"fr", "en"}, "Internal"},
		{map[string]string{"fr": "Interne", "de": "Intern"}, []string{"it", "en"}, "Intern"},
		{map[string]string{"de": "", "fr": "Interne"}, nil, "Interne"},
		{map[string]string{"de": ""}, []string{"fr"}, ""},
		{nil, []string{"fr", "en"}, ""},
	} {
		if got := store.LevelLabel(c.texts, c.langs...); got != c.want {
			t.Errorf("LevelLabel(%v, %v) = %q, want %q", c.texts, c.langs, got, c.want)
		}
	}
}
