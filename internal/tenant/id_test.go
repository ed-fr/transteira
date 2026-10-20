package tenant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
)

const (
	validID  = "ten_01JAB00000000000000ENTXTYA"
	validIDB = "ten_01JAB00000000000000ENTXTYB"
)

func TestParseID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in string
		ok       bool
	}{
		{"valid", validID, true},
		{"all digits", "ten_" + strings.Repeat("0", 26), true},
		{"empty", "", false},
		{"no prefix", "01JAB00000000000000ENTXTYA", false},
		{"wrong prefix", "trf_01JAB00000000000000ENTXTYA", false},
		{"short", "ten_01JAB0000000000000ENTXTY", false},
		{"long", validID + "B", false},
		{"lowercase", "ten_01jab00000000000000entxtya", false},
		{"symbol", "ten_01JAB00000000000000ENTXT-A", false},
		{"crockford I", "ten_01JAB00000000000000ENTITYA", false},
		{"crockford L", "ten_01JAB00000000000000ENTLYA", false},
		{"crockford O", "ten_01JAB00000000000000ENTOYA", false},
		{"crockford U", "ten_01JAB00000000000000ENTUYA", false},
		{"overflow first char", "ten_81JAB00000000000000ENTXTYA", false},
		{"generated", id.New(id.Tenant), true},
		{"upper prefix", "TEN_01JAB00000000000000ENTXTYA", false},
		{"huge", strings.Repeat("x", 10_000), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, err := ParseID(tc.in)
			if tc.ok {
				if err != nil || id.String() != tc.in || id.IsZero() {
					t.Fatalf("ParseID(%q) = %q, %v", tc.in, id, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidID) || id != "" {
				t.Fatalf("ParseID(%q) = %q, %v; want ErrInvalidID", tc.in, id, err)
			}
			if len(err.Error()) > 200 {
				t.Fatalf("error message too long")
			}
		})
	}
}

func TestIDIsZero(t *testing.T) {
	t.Parallel()
	var id ID
	if !id.IsZero() || id.String() != "" {
		t.Fatal("zero ID not reported as zero")
	}
}

func TestContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, ok := FromContext(ctx); ok {
		t.Fatal("empty context carries a tenant")
	}
	if _, ok := IDFromContext(ctx); ok {
		t.Fatal("empty context carries a tenant id")
	}
	if got := WithTenant(ctx, nil); got != ctx {
		t.Fatal("WithTenant(nil) changed the context")
	}

	ten := &Tenant{ID: validID, Name: "Entity A"}
	ctx2 := WithTenant(ctx, ten)
	got, ok := FromContext(ctx2)
	if !ok || got != ten {
		t.Fatalf("FromContext = %v, %v", got, ok)
	}
	id, ok := IDFromContext(ctx2)
	if !ok || id != validID {
		t.Fatalf("IDFromContext = %q, %v", id, ok)
	}

	if _, ok := IDFromContext(WithTenant(ctx, &Tenant{})); ok {
		t.Fatal("IDFromContext accepted a tenant without id")
	}
	// A foreign key with the same underlying value must not collide.
	type otherKey struct{}
	if _, ok := FromContext(context.WithValue(ctx, otherKey{}, ten)); ok {
		t.Fatal("FromContext read a foreign key")
	}
}
