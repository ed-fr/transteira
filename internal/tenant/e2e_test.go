package tenant

import "testing"

func TestE2EPolicyValid(t *testing.T) {
	t.Parallel()
	for p, want := range map[E2EPolicy]bool{
		E2EForbidden: true, E2EAllowed: true, E2ERequired: true, "": false, "Allowed": false, "none": false,
	} {
		if got := p.Valid(); got != want {
			t.Errorf("%q.Valid() = %v, want %v", p, got, want)
		}
	}
}

func TestEffectiveE2EPolicy(t *testing.T) {
	t.Parallel()
	ptr := func(p E2EPolicy) *E2EPolicy { return &p }
	for _, c := range []struct {
		name   string
		tenant E2EPolicy
		level  *E2EPolicy
		want   E2EPolicy
	}{
		{"forbidden follows", E2EForbidden, nil, E2EForbidden},
		{"forbidden beats allowed", E2EForbidden, ptr(E2EAllowed), E2EForbidden},
		{"forbidden beats required", E2EForbidden, ptr(E2ERequired), E2EForbidden},
		{"required follows", E2ERequired, nil, E2ERequired},
		{"required beats forbidden", E2ERequired, ptr(E2EForbidden), E2ERequired},
		{"required beats allowed", E2ERequired, ptr(E2EAllowed), E2ERequired},
		{"allowed follows", E2EAllowed, nil, E2EAllowed},
		{"allowed level forbids", E2EAllowed, ptr(E2EForbidden), E2EForbidden},
		{"allowed level requires", E2EAllowed, ptr(E2ERequired), E2ERequired},
		{"allowed level allows", E2EAllowed, ptr(E2EAllowed), E2EAllowed},
		{"allowed unknown level", E2EAllowed, ptr("bogus"), E2EAllowed},
		{"unset tenant", "", ptr(E2EAllowed), E2EForbidden},
		{"unknown tenant", "bogus", ptr(E2ERequired), E2EForbidden},
	} {
		if got := EffectiveE2EPolicy(c.tenant, c.level); got != c.want {
			t.Errorf("%s: EffectiveE2EPolicy(%q, %v) = %q, want %q", c.name, c.tenant, c.level, got, c.want)
		}
	}
}
