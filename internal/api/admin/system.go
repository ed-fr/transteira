package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/httpserver/middleware"
	"github.com/ed-fr/transteira/internal/keyrotation"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/systemsettings"
)

// MaintenanceService reads and changes the maintenance mode
// (*maintenance.Mode). It checks the principal itself: every authenticated
// administrator reads the mode, only a super admin changes it.
type MaintenanceService interface {
	Get(ctx context.Context, p adminauth.Principal) (maintenance.State, error)
	Set(ctx context.Context, p adminauth.Principal, enabled bool, messages map[string]string, clientIP netip.Addr) (maintenance.State, error)
}

// SystemSettingsService reads and changes the instance settings editable
// at runtime (*systemsettings.Service), for the super admin only.
type SystemSettingsService interface {
	Get(ctx context.Context, p adminauth.Principal) (systemsettings.Settings, error)
	Update(ctx context.Context, p adminauth.Principal, patch systemsettings.Patch, ip netip.Addr) (systemsettings.Settings, error)
}

// KeyRotationService starts and follows the master key rotations
// (*keyrotation.Service), for the super admin only.
type KeyRotationService interface {
	Start(ctx context.Context, p adminauth.Principal, code, recoveryCode string, clientIP netip.Addr) (keyrotation.Rotation, error)
	Get(ctx context.Context, p adminauth.Principal, rotID string) (keyrotation.Rotation, error)
	Status(ctx context.Context, p adminauth.Principal) (keyrotation.MasterKeyStatus, error)
}

// Compile-time checks that the system services fit.
var (
	_ MaintenanceService    = (*maintenance.Mode)(nil)
	_ SystemSettingsService = (*systemsettings.Service)(nil)
	_ KeyRotationService    = (*keyrotation.Service)(nil)
)

// WithMaintenance serves the maintenance operations with m. Without it they
// answer 500.
func WithMaintenance(m MaintenanceService) Option {
	return func(s *Server) { s.maintenance = m }
}

// WithSystemSettings serves the system settings operations with svc.
// Without it they answer 500.
func WithSystemSettings(svc SystemSettingsService) Option {
	return func(s *Server) { s.settings = svc }
}

// WithKeyRotation serves the master key operations with svc. Without it
// they answer 500.
func WithKeyRotation(svc KeyRotationService) Option {
	return func(s *Server) { s.rotations = svc }
}

// Wiring errors, answered 500.
var (
	errNoMaintenance    = errors.New("admin: no maintenance mode configured")
	errNoSystemSettings = errors.New("admin: no system settings service configured")
	errNoKeyRotation    = errors.New("admin: no key rotation service configured")
)

// systemError maps an error of the maintenance, system settings or key
// rotation services to the error the strict handler renders; the adminauth
// errors they return unchanged (session, role, TOTP re-confirmation) are
// mapped by serviceError. keyrotation.ErrClosed (a start during the
// shutdown) and the other server errors keep their cause and answer 500:
// the contract has no 503 for these operations, and the instance is going
// away anyway. No service puts a code, a key or an address in its errors.
func systemError(err error) error {
	var (
		maint    *maintenance.InvalidError
		settings *systemsettings.InvalidError
	)
	switch {
	case errors.As(err, &maint):
		return validationFailed(maint.Field, fieldInvalidFormat)
	case errors.Is(err, maintenance.ErrInvalid):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, maintenance.ErrForcedByEnvironment):
		return problem.New(problem.CodeStateConflict)
	case errors.As(err, &settings):
		return validationFailed(settings.Field, formatCode(settings.Field == systemsettings.FieldAlertEmail))
	case errors.Is(err, systemsettings.ErrInvalidInput):
		return problem.New(problem.CodeValidationFailed)
	case errors.Is(err, keyrotation.ErrNoNewKey):
		return problem.New(problem.CodeNewMasterKeyMissing)
	case errors.Is(err, keyrotation.ErrRunning):
		return problem.New(problem.CodeStateConflict, problem.WithDetail(detailRotationRunning))
	case errors.Is(err, keyrotation.ErrRotationMismatch):
		return problem.New(problem.CodeStateConflict, problem.WithDetail(detailRotationMismatch))
	case errors.Is(err, keyrotation.ErrRestartRequired):
		return problem.New(problem.CodeStateConflict, problem.WithDetail(detailRestartRequired))
	case errors.Is(err, keyrotation.ErrConflict):
		return problem.New(problem.CodeStateConflict)
	case errors.Is(err, keyrotation.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	default:
		return serviceError(err)
	}
}

// Details of the 409 state-conflict answers of startMasterKeyRotation, as in
// the OpenAPI examples. They name the case, never a key.
const (
	detailRotationRunning  = "A master key rotation is already running."
	detailRotationMismatch = "A rotation between other keys is unfinished; finish or abandon it with the command line."
	detailRestartRequired  = "The last rotation is complete; restart with the new key as " + config.EnvMasterKeyFile +
		" before starting another."
)

// --- Maintenance ---------------------------------------------------------------

// maintenanceSession returns the maintenance mode and the session of the
// request, or the error to answer.
func (s *Server) maintenanceSession(ctx context.Context) (MaintenanceService, adminauth.Principal, error) {
	if s.maintenance == nil {
		return nil, adminauth.Principal{}, errNoMaintenance
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.maintenance, p, nil
}

// GetMaintenance returns the maintenance mode to any authenticated
// administrator: it holds no tenant data.
func (s *Server) GetMaintenance(ctx context.Context, _ gen.GetMaintenanceRequestObject) (gen.GetMaintenanceResponseObject, error) {
	m, p, err := s.maintenanceSession(ctx)
	if err != nil {
		return nil, err
	}
	st, err := m.Get(ctx, p)
	if err != nil {
		return nil, systemError(err)
	}
	return gen.GetMaintenance200JSONResponse(maintenanceBody(st)), nil
}

// SetMaintenance turns the maintenance mode on or off (super admin). The
// messages given replace the stored ones entirely; a missing or null
// message stores none. Disabling while TT_MAINTENANCE forces the mode
// answers 409 state-conflict. As for UpdateSystemSettings and
// startMasterKeyRotation, the role is checked before the body is decoded
// (see decodeMaintenanceUpdate): another administrator gets 403 whatever
// the body; the service checks it again.
func (s *Server) SetMaintenance(ctx context.Context, req gen.SetMaintenanceRequestObject) (gen.SetMaintenanceResponseObject, error) {
	m, p, err := s.maintenanceSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return nil, serviceError(err)
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	enabled, messages, err := decodeMaintenanceUpdate(*req.Body)
	if err != nil {
		return nil, err
	}
	st, err := m.Set(ctx, p, enabled, messages, middleware.ClientIP(ctx))
	if err != nil {
		return nil, systemError(err)
	}
	return gen.SetMaintenance200JSONResponse(maintenanceBody(st)), nil
}

// Members of the OpenAPI MaintenanceUpdate.
const (
	memberEnabled = "enabled"
	memberMessage = "message"
)

// maintenanceUpdateFields lists the members of a MaintenanceUpdate.
var maintenanceUpdateFields = []string{memberEnabled, memberMessage}

// decodeMaintenanceUpdate decodes the OpenAPI MaintenanceUpdate (the
// generated type is raw JSON, so that a missing enabled is not taken for
// false): a body that is not an object answers invalid-format on the whole
// body (""), an unknown member invalid-format on its pointer, a missing
// enabled required, a null enabled not-nullable, and an enabled or message
// of the wrong type invalid-format on its pointer. A null message stores
// none; its keys and values are checked by the maintenance mode.
func decodeMaintenanceUpdate(raw []byte) (bool, map[string]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return false, nil, validationFailed("", fieldInvalidFormat)
	}
	if err := rejectUnknownMembers(members, maintenanceUpdateFields); err != nil {
		return false, nil, err
	}
	rawEnabled, ok := members[memberEnabled]
	switch {
	case !ok:
		return false, nil, validationFailed("/"+memberEnabled, fieldRequired)
	case isNull(members, memberEnabled):
		return false, nil, validationFailed("/"+memberEnabled, fieldNotNullable)
	}
	var enabled bool
	if err := json.Unmarshal(rawEnabled, &enabled); err != nil {
		return false, nil, validationFailed("/"+memberEnabled, fieldInvalidFormat)
	}
	var messages map[string]string
	if rawMessage, ok := members[memberMessage]; ok {
		if err := json.Unmarshal(rawMessage, &messages); err != nil {
			return false, nil, validationFailed("/"+memberMessage, fieldInvalidFormat)
		}
	}
	return enabled, messages, nil
}

// maintenanceBody renders st as the OpenAPI Maintenance: since and message
// absent when unset.
func maintenanceBody(st maintenance.State) gen.Maintenance {
	out := gen.Maintenance{
		Enabled: st.Enabled, Source: gen.MaintenanceSource(st.Source), AdminEnabled: st.AdminEnabled,
		Since: optionalTime(st.Since),
	}
	if len(st.Message) > 0 {
		msg := gen.MaintenanceMessages(maps.Clone(st.Message))
		out.Message = &msg
	}
	return out
}

// --- System settings -----------------------------------------------------------

// settingsSession returns the settings service and the session of the
// request, or the error to answer.
func (s *Server) settingsSession(ctx context.Context) (SystemSettingsService, adminauth.Principal, error) {
	if s.settings == nil {
		return nil, adminauth.Principal{}, errNoSystemSettings
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.settings, p, nil
}

// GetSystemSettings returns the instance settings editable at runtime
// (super admin).
func (s *Server) GetSystemSettings(ctx context.Context, _ gen.GetSystemSettingsRequestObject) (gen.GetSystemSettingsResponseObject, error) {
	svc, p, err := s.settingsSession(ctx)
	if err != nil {
		return nil, err
	}
	v, err := svc.Get(ctx, p)
	if err != nil {
		return nil, systemError(err)
	}
	return gen.GetSystemSettings200JSONResponse(settingsBody(v)), nil
}

// UpdateSystemSettings applies a JSON merge patch to the instance settings
// (super admin): absent members are left unchanged, alertEmail null removes
// the address, and diskAlertThreshold null or an unknown member is refused
// with 400 validation-failed naming it. The role is checked before the
// body is decoded, so another administrator gets 403 whatever the body;
// the service checks it again.
func (s *Server) UpdateSystemSettings(ctx context.Context, req gen.UpdateSystemSettingsRequestObject) (gen.UpdateSystemSettingsResponseObject, error) {
	svc, p, err := s.settingsSession(ctx)
	if err != nil {
		return nil, err
	}
	if err := adminauth.RequireSuperAdmin(p.Admin); err != nil {
		return nil, serviceError(err)
	}
	if req.Body == nil {
		return nil, validationFailed("", fieldRequired)
	}
	patch, err := decodeSystemSettingsUpdate(*req.Body)
	if err != nil {
		return nil, err
	}
	v, err := svc.Update(ctx, p, patch, middleware.ClientIP(ctx))
	if err != nil {
		return nil, systemError(err)
	}
	return gen.UpdateSystemSettings200JSONResponse(settingsBody(v)), nil
}

// Members of a system settings merge patch.
const (
	memberDiskAlertThreshold = "diskAlertThreshold"
	memberAlertEmail         = "alertEmail"
)

// systemSettingsPatchFields lists the members of a system settings merge
// patch, in the order their errors are reported.
var systemSettingsPatchFields = []string{memberDiskAlertThreshold, memberAlertEmail}

// systemSettingsPatch is the OpenAPI SystemSettingsUpdate, decoded by the
// handler itself (the generated type is raw JSON) so that a null member
// can be told from an absent one.
type systemSettingsPatch struct {
	DiskAlertThreshold *float64 `json:"diskAlertThreshold"`
	AlertEmail         *string  `json:"alertEmail"`
}

// decodeSystemSettingsUpdate decodes a system settings merge patch, with
// the rules of decodeAPITokenUpdate: a body that is not an object answers
// invalid-format on the whole body (""), an unknown member invalid-format
// on its pointer, a null diskAlertThreshold not-nullable, and a member of
// the wrong type invalid-format on its pointer. A null alertEmail removes
// the address.
func decodeSystemSettingsUpdate(raw []byte) (systemsettings.Patch, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return systemsettings.Patch{}, validationFailed("", fieldInvalidFormat)
	}
	if err := rejectUnknownMembers(members, systemSettingsPatchFields); err != nil {
		return systemsettings.Patch{}, err
	}
	if isNull(members, memberDiskAlertThreshold) {
		return systemsettings.Patch{}, validationFailed(systemsettings.FieldDiskAlertThreshold, fieldNotNullable)
	}
	var b systemSettingsPatch
	if err := json.Unmarshal(raw, &b); err != nil {
		field := ""
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field = "/" + typeErr.Field
		}
		return systemsettings.Patch{}, validationFailed(field, fieldInvalidFormat)
	}
	_, emailSet := members[memberAlertEmail]
	return systemsettings.Patch{
		Threshold: b.DiskAlertThreshold,
		Email:     systemsettings.Field[string]{Set: emailSet, Value: b.AlertEmail},
	}, nil
}

// isNull reports whether members holds name with the JSON null.
func isNull(members map[string]json.RawMessage, name string) bool {
	v, ok := members[name]
	return ok && bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}

// settingsBody renders v as the OpenAPI SystemSettings: alertEmail null
// when none.
func settingsBody(v systemsettings.Settings) gen.SystemSettings {
	return gen.SystemSettings{DiskAlertThreshold: float32(v.DiskAlertThreshold), AlertEmail: optional(v.AlertEmail)}
}

// --- Master key ----------------------------------------------------------------

// rotationSession returns the key rotation service and the session of the
// request, or the error to answer.
func (s *Server) rotationSession(ctx context.Context) (KeyRotationService, adminauth.Principal, error) {
	if s.rotations == nil {
		return nil, adminauth.Principal{}, errNoKeyRotation
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, adminauth.Principal{}, err
	}
	return s.rotations, p, nil
}

// GetMasterKeyStatus returns the state of the master keys and the latest
// rotation (super admin).
func (s *Server) GetMasterKeyStatus(ctx context.Context, _ gen.GetMasterKeyStatusRequestObject) (gen.GetMasterKeyStatusResponseObject, error) {
	svc, p, err := s.rotationSession(ctx)
	if err != nil {
		return nil, err
	}
	st, err := svc.Status(ctx, p)
	if err != nil {
		return nil, systemError(err)
	}
	out := gen.GetMasterKeyStatus200JSONResponse{
		ActiveKeyId: st.ActiveKeyID, NewKeyId: optional(st.NewKeyID), RestartRequired: st.RestartRequired,
	}
	if st.LatestRotation != nil {
		r := rotationBody(*st.LatestRotation)
		out.LatestRotation = &r
	}
	return out, nil
}

// StartMasterKeyRotation starts, or resumes, a master key rotation (super
// admin re-confirming with a TOTP or recovery code): 202 with the rotation
// as it starts. A missing body is passed to the service as no code, so that
// the role, the new key and the rotation state are checked first (403, then
// 409 new-master-key-missing, then 409 state-conflict) and the service then
// refuses the missing code.
// A body that is not a TotpCode (see decodeTotpCode) answers 400 only after
// the same two checks, made through the status (which checks the role), so
// that it reveals nothing to another administrator and consumes no TOTP
// attempt. The codes are never logged: the service errors do not carry
// them.
func (s *Server) StartMasterKeyRotation(ctx context.Context, req gen.StartMasterKeyRotationRequestObject) (gen.StartMasterKeyRotationResponseObject, error) {
	svc, p, err := s.rotationSession(ctx)
	if err != nil {
		return nil, err
	}
	var code, recovery string
	if req.Body != nil {
		var invalid error
		code, recovery, invalid = decodeTotpCode(*req.Body)
		if invalid != nil {
			return nil, rotationBodyError(ctx, svc, p, invalid)
		}
	}
	r, err := svc.Start(ctx, p, code, recovery, middleware.ClientIP(ctx))
	if err != nil {
		return nil, systemError(err)
	}
	return gen.StartMasterKeyRotation202JSONResponse(rotationBody(r)), nil
}

// rotationBodyError returns the error to answer for a rotation start whose
// body is invalid: the 403 or 409 new-master-key-missing the service would
// answer first, else invalid.
func rotationBodyError(ctx context.Context, svc KeyRotationService, p adminauth.Principal, invalid error) error {
	st, err := svc.Status(ctx, p)
	switch {
	case err != nil:
		return systemError(err)
	case st.NewKeyID == "":
		return problem.New(problem.CodeNewMasterKeyMissing)
	default:
		return invalid
	}
}

// Members of the OpenAPI TotpCode.
const (
	memberCode         = "code"
	memberRecoveryCode = "recoveryCode"
)

// totpCodeFields lists the members of a TotpCode.
var totpCodeFields = []string{memberCode, memberRecoveryCode}

// decodeTotpCode decodes the OpenAPI TotpCode of a master key rotation
// start: a body that is not an object answers invalid-format on the whole
// body (""), an unknown member invalid-format on its pointer and a member
// that is not a string (null included) invalid-format on its pointer. The
// codes themselves (format, exactly one given) are checked by the TOTP
// re-confirmation.
func decodeTotpCode(raw []byte) (code, recoveryCode string, err error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return "", "", validationFailed("", fieldInvalidFormat)
	}
	if err := rejectUnknownMembers(members, totpCodeFields); err != nil {
		return "", "", err
	}
	values := make([]string, len(totpCodeFields))
	for i, name := range totpCodeFields {
		v, ok := members[name]
		if !ok {
			continue
		}
		var str *string
		if json.Unmarshal(v, &str) != nil || str == nil {
			return "", "", validationFailed("/"+name, fieldInvalidFormat)
		}
		values[i] = *str
	}
	return values[0], values[1], nil
}

// GetMasterKeyRotation returns the progress of a master key rotation
// (super admin); an unknown identifier answers 404.
func (s *Server) GetMasterKeyRotation(ctx context.Context, req gen.GetMasterKeyRotationRequestObject) (gen.GetMasterKeyRotationResponseObject, error) {
	svc, p, err := s.rotationSession(ctx)
	if err != nil {
		return nil, err
	}
	r, err := svc.Get(ctx, p, req.RotationId)
	if err != nil {
		return nil, systemError(err)
	}
	return gen.GetMasterKeyRotation200JSONResponse(rotationBody(r)), nil
}

// rotationBody renders r as the OpenAPI KeyRotation: completedAt and error
// absent when unset.
func rotationBody(r keyrotation.Rotation) gen.KeyRotation {
	return gen.KeyRotation{
		Id: r.ID, Status: gen.KeyRotationStatus(r.Status), FromKeyId: r.FromKeyID, ToKeyId: r.ToKeyID,
		TotalKeys: r.TotalKeys, RewrappedKeys: r.RewrappedKeys, StartedAt: r.StartedAt,
		CompletedAt: optionalTime(r.CompletedAt), Error: optional(r.Error),
	}
}
