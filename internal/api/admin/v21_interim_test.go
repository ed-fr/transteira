package admin

import (
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store"
)

// The members of API 2.1 that are not implemented yet are refused with a
// 400 not-supported, before the service: the one-time secrets settings of an
// imported tenant configuration. The new operations answer 404 through the
// stubs (tested with the isolation suite).
func TestInterimNotSupportedV21(t *testing.T) {
	t.Parallel()
	super := ctxWith(store.SessionAuthenticated, superRoot)
	settings := `"secretSettings":{"enabled":true,"durations":["1h","1d"],"fileAllowed":true,"fileMaxBytes":10485760,"emailAllowed":true},`
	raw := strings.Replace(validImport, `"network"`, settings+`"network"`, 1)

	tsvc := &fakeTenantService{}
	_, err := tenantServer(tsvc).ImportTenant(importCtx(super, raw), importReq())
	wantNotSupported(t, "import secretSettings", err, "/config/secretSettings")
	if len(tsvc.args["ImportTenant"]) != 0 {
		t.Errorf("import secretSettings: the service was called")
	}

	// A malformed secretSettings is still a strict import error, checked
	// before the interim refusal (missing required member).
	bad := strings.Replace(validImport, `"network"`, `"secretSettings":{"enabled":true},"network"`, 1)
	_, err = tenantServer(&fakeTenantService{}).ImportTenant(importCtx(super, bad), importReq())
	if err == nil {
		t.Error("import with an incomplete secretSettings: no error")
	}
}
