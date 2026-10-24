package tenantadmin

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// operations returns every tenant operation of the service on tid, as
// called by p.
func operations(ev *env, logo []byte) map[string]func(p adminauth.Principal, tid tenant.ID) error {
	ctx := context.Background()
	return map[string]func(adminauth.Principal, tenant.ID) error{
		"GetTenant": func(p adminauth.Principal, tid tenant.ID) error { _, err := ev.svc.GetTenant(ctx, p, tid); return err },
		"UpdateTenant": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.UpdateTenant(ctx, p, tid, TenantUpdate{DefaultLanguage: ptr("fr")}, clientIP)
			return err
		},
		"GetBranding": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.GetBranding(ctx, p, tid)
			return err
		},
		"UpdateBranding": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.UpdateBranding(ctx, p, tid, "#000000", "#000000", clientIP)
			return err
		},
		"GetAsset": func(p adminauth.Principal, tid tenant.ID) error {
			// The super admin stores a background first (it fails on a
			// missing tenant), so that only p's access decides.
			_ = ev.svc.UploadAsset(ctx, ev.super, tid, "background", bytes.NewReader(logo), clientIP)
			_, err := ev.svc.GetAsset(ctx, p, tid, "background")
			return err
		},
		"UploadAsset": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.UploadAsset(ctx, p, tid, "logo", bytes.NewReader(logo), clientIP)
		},
		"DeleteAsset": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.DeleteAsset(ctx, p, tid, "logo", clientIP)
		},
		"GetNetworkRules": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.GetNetworkRules(ctx, p, tid)
			return err
		},
		"UpdateNetworkRules": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.UpdateNetworkRules(ctx, p, tid, []string{"10.0.0.0/8"}, nil, clientIP)
			return err
		},
		"GetSMTP": func(p adminauth.Principal, tid tenant.ID) error { _, err := ev.svc.GetSMTP(ctx, p, tid); return err },
		"UpdateSMTP": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.UpdateSMTP(ctx, p, tid, relay(), clientIP)
			return err
		},
		"TestSMTP": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.TestSMTP(ctx, p, tid, "a@example.com", clientIP)
			return err
		},
		"CheckMailDNS": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.CheckMailDNS(ctx, p, tid, nil)
			return err
		},
		"ListTemplates": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.ListTemplates(ctx, p, tid)
			return err
		},
		"GetTemplate": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.GetTemplate(ctx, p, tid, keyCode, "en")
			return err
		},
		"UpdateTemplate": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.UpdateTemplate(ctx, p, tid, keyCode, "en", goodTemplate(), clientIP)
			return err
		},
		"ResetTemplate": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.ResetTemplate(ctx, p, tid, keyCode, "en", clientIP)
		},
		"PreviewTemplate": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.PreviewTemplate(ctx, p, tid, keyCode, "en", nil)
			return err
		},
		"GetLegal": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.GetLegal(ctx, p, tid, store.LegalNotice, "en")
			return err
		},
		"UpdateLegal": func(p adminauth.Principal, tid tenant.ID) error {
			_, err := ev.svc.UpdateLegal(ctx, p, tid, store.LegalNotice, "en", "x", clientIP)
			return err
		},
		"DeleteTenant": func(p adminauth.Principal, tid tenant.ID) error {
			return ev.svc.DeleteTenant(ctx, p, tid, "wrong name", clientIP)
		},
	}
}

// TestRightsMatrix runs every operation as the super admin, the delegated
// admin of A, the delegated admin of B and an unauthenticated session, on
// tenant A.
func TestRightsMatrix(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		_, err := ev.svc.UpdateSMTP(ctx, ev.super, ev.a.ID, relay(), clientIP)
		mustNoErr(t, "smtp", err)
		ops := operations(ev, pngImage(t, 8, 8))
		superOnly := map[string]bool{"DeleteTenant": true}
		unauth := ev.adminA
		unauth.State = store.SessionTOTPRequired
		for name, op := range ops {
			// B's admin cannot even tell that A exists.
			if err := op(ev.adminB, ev.a.ID); !errors.Is(err, ErrNotFound) && (!superOnly[name] || !errors.Is(err, ErrForbidden)) {
				t.Errorf("%s by B's admin on A: %v", name, err)
			}
			if err := op(unauth, ev.a.ID); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("%s unauthenticated: %v", name, err)
			}
			err := op(ev.adminA, ev.a.ID)
			if superOnly[name] {
				wantErr(t, name+" by A's admin", err, ErrForbidden)
			} else if err != nil {
				t.Errorf("%s by A's admin: %v", name, err)
			}
			err = op(ev.super, ev.a.ID)
			if superOnly[name] {
				wantInvalid(t, name+" by super", err, FieldConfirm)
			} else if err != nil {
				t.Errorf("%s by super admin: %v", name, err)
			}
			// A missing tenant answers like an inaccessible one.
			if err := op(ev.super, "ten_01JAB00000000000000000000Z"); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s on a missing tenant: %v", name, err)
			}
		}
	})
}

// TestAccessBeforeValidation checks that every operation taking a request
// body checks access first: on a tenant the caller cannot reach (or that
// does not exist) an invalid body still answers ErrNotFound, so that the
// answer never depends on the body.
func TestAccessBeforeValidation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		_, err := ev.svc.UpdateSMTP(ctx, ev.super, ev.a.ID, relay(), clientIP)
		mustNoErr(t, "smtp", err)
		badSMTP := relay()
		badSMTP.Host = "bad host"
		ops := []struct {
			name, field string
			op          func(p adminauth.Principal, tid tenant.ID) error
		}{
			{"UpdateTenant", FieldDefaultLanguage, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.UpdateTenant(ctx, p, tid, TenantUpdate{DefaultLanguage: ptr("de")}, clientIP)
				return err
			}},
			{"UpdateBranding", FieldPrimaryColor, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.UpdateBranding(ctx, p, tid, "red", "#000000", clientIP)
				return err
			}},
			{"UpdateNetworkRules", FieldInternalCIDRs + "/0", func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.UpdateNetworkRules(ctx, p, tid, []string{"not a range"}, nil, clientIP)
				return err
			}},
			{"UpdateSMTP", FieldHost, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.UpdateSMTP(ctx, p, tid, badSMTP, clientIP)
				return err
			}},
			{"TestSMTP", FieldTo, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.TestSMTP(ctx, p, tid, "not an address", clientIP)
				return err
			}},
			{"CheckMailDNS", FieldDKIMSelector, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.CheckMailDNS(ctx, p, tid, []string{"bad selector!"})
				return err
			}},
			{"UpdateTemplate", FieldTemplate, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.UpdateTemplate(ctx, p, tid, keyCode, "en", TemplateInput{Subject: "{{", Text: "{{"}, clientIP)
				return err
			}},
			{"UpdateLegal", FieldMarkdown, func(p adminauth.Principal, tid tenant.ID) error {
				_, err := ev.svc.UpdateLegal(ctx, p, tid, store.LegalNotice, "en", "a\x00b", clientIP)
				return err
			}},
		}
		unauth := ev.adminA
		unauth.State = store.SessionTOTPRequired
		for _, o := range ops {
			wantErr(t, o.name+" by B's admin on A", o.op(ev.adminB, ev.a.ID), ErrNotFound)
			wantErr(t, o.name+" on a missing tenant", o.op(ev.super, "ten_01JAB00000000000000000000Z"), ErrNotFound)
			wantErr(t, o.name+" unauthenticated", o.op(unauth, ev.a.ID), ErrUnauthenticated)
			// The body is indeed invalid for a caller with access.
			wantInvalid(t, o.name+" by A's admin", o.op(ev.adminA, ev.a.ID), o.field)
		}
	})
}
