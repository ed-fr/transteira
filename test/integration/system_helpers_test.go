package integration_test

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/diskalert"
)

// Helpers of the system tests (CLAUDE.md sections 4, 12.2, 16.1 and 19;
// api/openapi.yaml "Admin system"; threat model T-154 to T-158): the
// maintenance mode, the system settings, the disk alert and the master key
// rotation started from the administration.

// System API paths.
const (
	pathMaintenance    = "/api/v1/admin/system/maintenance"
	pathSystemSettings = "/api/v1/admin/system/settings"
	pathAntivirusTest  = "/api/v1/admin/system/antivirus/test"
	pathMasterKey      = "/api/v1/admin/system/master-key"
	pathRotations      = "/api/v1/admin/system/master-key/rotations"
)

// Audit actions of the system tests.
const (
	actMaintenanceEnabled  = "maintenance.enabled"
	actMaintenanceDisabled = "maintenance.disabled"
	actConfigUpdated       = "config.updated"
	actDiskAlertRaised     = "disk.alert_raised"
	actDiskAlertCleared    = "disk.alert_cleared"
	actRotationStarted     = "master_key.rotation_started"
	actRotationCompleted   = "master_key.rotation_completed"
	actRotationFailed      = "master_key.rotation_failed"
)

// Subject prefixes of the disk_alert mail (internal/mail/templates).
const (
	diskSubjectEN = "Disk alert: "
	diskSubjectFR = "Alerte disque : "
)

// maintenanceJSON is the Maintenance schema.
type maintenanceJSON struct {
	Enabled      bool              `json:"enabled"`
	Source       string            `json:"source"`
	AdminEnabled bool              `json:"adminEnabled"`
	Since        *string           `json:"since"`
	Message      map[string]string `json:"message"`
}

// settingsJSON is the SystemSettings schema.
type settingsJSON struct {
	DiskAlertThreshold float64 `json:"diskAlertThreshold"`
	AlertEmail         *string `json:"alertEmail"`
}

// rotationJSON is the KeyRotation schema.
type rotationJSON struct {
	ID            string  `json:"id"`
	Status        string  `json:"status"`
	FromKeyID     string  `json:"fromKeyId"`
	ToKeyID       string  `json:"toKeyId"`
	TotalKeys     int64   `json:"totalKeys"`
	RewrappedKeys int64   `json:"rewrappedKeys"`
	StartedAt     string  `json:"startedAt"`
	CompletedAt   *string `json:"completedAt"`
	Error         *string `json:"error"`
}

// masterKeyStatusJSON is the MasterKeyStatus schema.
type masterKeyStatusJSON struct {
	ActiveKeyID     string        `json:"activeKeyId"`
	NewKeyID        *string       `json:"newKeyId"`
	RestartRequired bool          `json:"restartRequired"`
	LatestRotation  *rotationJSON `json:"latestRotation"`
}

// globalDiskJSON is GlobalStats.disk.
type globalDiskJSON struct {
	Disk struct {
		AlertThreshold      float64 `json:"alertThreshold"`
		AlertActive         bool    `json:"alertActive"`
		AlertMailConfigured bool    `json:"alertMailConfigured"`
	} `json:"disk"`
}

// publicMaintenanceJSON is the maintenance part of the PublicTenant schema.
type publicMaintenanceJSON struct {
	Language                   string  `json:"language"`
	Maintenance                bool    `json:"maintenance"`
	MaintenanceMessage         *string `json:"maintenanceMessage"`
	MaintenanceMessageLanguage *string `json:"maintenanceMessageLanguage"`
}

// maintenance sends getMaintenance and expects 200.
func (c *adminClient) maintenance(t *testing.T) maintenanceJSON {
	t.Helper()
	resp := mustStatus(t, "getMaintenance", c.call(t, http.MethodGet, pathMaintenance, nil), http.StatusOK)
	var m maintenanceJSON
	mustJSON(t, resp.body, &m)
	return m
}

// setMaintenance sends setMaintenance with body.
func (c *adminClient) setMaintenance(t *testing.T, body any) response {
	t.Helper()
	return c.call(t, http.MethodPut, pathMaintenance, body)
}

// mustSetMaintenance sends setMaintenance and expects 200.
func (c *adminClient) mustSetMaintenance(t *testing.T, body any) maintenanceJSON {
	t.Helper()
	resp := mustStatus(t, "setMaintenance", c.setMaintenance(t, body), http.StatusOK)
	var m maintenanceJSON
	mustJSON(t, resp.body, &m)
	return m
}

// settings sends getSystemSettings and expects 200.
func (c *adminClient) settings(t *testing.T) settingsJSON {
	t.Helper()
	resp := mustStatus(t, "getSystemSettings", c.call(t, http.MethodGet, pathSystemSettings, nil), http.StatusOK)
	var s settingsJSON
	mustJSON(t, resp.body, &s)
	return s
}

// mustPatchSettings sends updateSystemSettings with the raw merge patch
// and expects 200.
func (c *adminClient) mustPatchSettings(t *testing.T, body string) settingsJSON {
	t.Helper()
	resp := mustStatus(t, "updateSystemSettings "+body, c.mergePatch(t, pathSystemSettings, body), http.StatusOK)
	var s settingsJSON
	mustJSON(t, resp.body, &s)
	return s
}

// globalDisk sends getGlobalStats and returns its disk part.
func (c *adminClient) globalDisk(t *testing.T) globalDiskJSON {
	t.Helper()
	resp := mustStatus(t, "getGlobalStats", c.call(t, http.MethodGet, pathGlobalStats, nil), http.StatusOK)
	var g globalDiskJSON
	mustJSON(t, resp.body, &g)
	return g
}

// globalEvents returns the global audit events of action (every tenant
// and the events without tenant), most recent first.
func (c *adminClient) globalEvents(t *testing.T, action string) []opsAuditEvent {
	t.Helper()
	return c.auditAll(t, pathGlobalAudit, url.Values{"action": {action}})
}

// expectGlobalEvent fails unless ev is a global event (no tenant) of the
// actor kind/id about the object kind/id ("" skips a check).
func expectGlobalEvent(t *testing.T, ev opsAuditEvent, actorKind, actorID, ip, objKind, objID string) {
	t.Helper()
	if ev.TenantID != nil {
		t.Errorf("%s: tenantId %q, want a global event", ev.Action, *ev.TenantID)
	}
	check := func(what, got, want string) {
		if want != "" && got != want {
			t.Errorf("%s %s: %s = %q, want %q", ev.Action, ev.ID, what, got, want)
		}
	}
	check("actor kind", ev.Actor.Kind, actorKind)
	check("actor", ev.Actor.ID, actorID)
	check("ip", ev.IP, ip)
	check("object kind", ev.Object.Kind, objKind)
	check("object", ev.Object.ID, objID)
}

// masterKeyStatus sends getMasterKeyStatus and expects 200.
func (c *adminClient) masterKeyStatus(t *testing.T) masterKeyStatusJSON {
	t.Helper()
	resp := mustStatus(t, "getMasterKeyStatus", c.call(t, http.MethodGet, pathMasterKey, nil), http.StatusOK)
	var s masterKeyStatusJSON
	mustJSON(t, resp.body, &s)
	return s
}

// startRotation sends startMasterKeyRotation with a TOTP code or a
// recovery code, both recorded as secrets.
func (c *adminClient) startRotation(t *testing.T, code, recovery string) response {
	t.Helper()
	body := map[string]string{}
	if code != "" {
		body["code"] = code
		c.a.secret(code)
	}
	if recovery != "" {
		body["recoveryCode"] = recovery
	}
	return c.call(t, http.MethodPost, pathRotations, body)
}

// mustStartRotation is startRotation expecting 202 with a running
// rotation.
func (c *adminClient) mustStartRotation(t *testing.T, code, recovery string) rotationJSON {
	t.Helper()
	resp := mustStatus(t, "startMasterKeyRotation", c.startRotation(t, code, recovery), http.StatusAccepted)
	var r rotationJSON
	mustJSON(t, resp.body, &r)
	if !rotationIDRE.MatchString(r.ID) || r.Status != "running" {
		t.Errorf("started rotation = %+v, want a running rot_ rotation", r)
	}
	return r
}

// rotation sends getMasterKeyRotation and expects 200.
func (c *adminClient) rotation(t *testing.T, id string) rotationJSON {
	t.Helper()
	resp := mustStatus(t, "getMasterKeyRotation", c.call(t, http.MethodGet, pathRotations+"/"+id, nil), http.StatusOK)
	var r rotationJSON
	mustJSON(t, resp.body, &r)
	return r
}

// waitRotation polls getMasterKeyRotation until the rotation id is no
// longer running, and returns it; it fails unless it completed.
func (c *adminClient) waitRotation(t *testing.T, id string) rotationJSON {
	t.Helper()
	var r rotationJSON
	eventually(t, "rotation "+id+" finished", func() bool {
		r = c.rotation(t, id)
		return r.Status != "running"
	})
	if r.Status != "completed" || r.CompletedAt == nil || r.Error != nil || r.RewrappedKeys != r.TotalKeys {
		t.Fatalf("rotation %s = %+v, want completed with every key re-wrapped\napp log:\n%s", id, r, c.a.appLog)
	}
	return r
}

// rotationIDRE is the format of a rotation identifier.
var rotationIDRE = regexp.MustCompile(`^rot_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// relaunch starts a new server on cfg (the stopped server's database and
// data directory, possibly other keys) with the options o, and makes it
// the server of a. The application log of the previous server is kept in
// logs.
func (a *adminEnv) relaunch(t *testing.T, cfg config.Config, o serverOptions, logs *[]*watchBuffer) {
	t.Helper()
	if !a.stopped.Load() {
		if err := a.stop(); err != nil {
			t.Fatalf("stop: %v\napp log:\n%s", err, a.appLog)
		}
	}
	if logs != nil {
		*logs = append(*logs, a.appLog)
	}
	a.server = launchServer(t, &cfg, a.tenantA, a.tenantB, o)
}

// refreshCSRF fetches the CSRF token of the client's session again
// (getAdminMe): it is a MAC under a key derived from the current master
// key, so it changes after a restart on a rotated master key.
func (c *adminClient) refreshCSRF(t *testing.T) {
	t.Helper()
	resp := mustStatus(t, "getAdminMe", c.send(t, http.MethodGet, pathAdminMe, nil, nil), http.StatusOK)
	var me meJSON
	mustJSON(t, resp.body, &me)
	c.csrf = me.CSRFToken
	c.a.secret(me.CSRFToken)
}

// promoteSuper creates, as the super admin c, a delegated admin of tenant A
// named username, promotes it to super admin and returns a new client of
// it signed in from ip (password and TOTP).
func (c *adminClient) promoteSuper(t *testing.T, username, ip string) *adminClient {
	t.Helper()
	d := c.createDelegatedOf(t, username, string(c.a.tenantA.ID), domainA, ip)
	mustStatus(t, "promote "+username, c.patch(t, d.acct.id, map[string]any{"role": "super_admin"}), http.StatusOK)
	s := c.a.client(d.acct, ip)
	s.signIn(t)
	if me := s.me(t); me.Role != "super_admin" {
		t.Fatalf("%s after the promotion: role %q, want super_admin", username, me.Role)
	}
	return s
}

// expectLogsClean fails when a secret of a (password, token, recovery
// code, TOTP secret) or a byte encoding of one of keys appears in the
// application logs (those of the stopped servers in logs and the current
// one), the security log or the global audit events. TOTP codes are
// checked in the security log and the audit events only (the application
// log holds arbitrary digit runs).
func (a *adminEnv) expectLogsClean(t *testing.T, logs []*watchBuffer, keys ...keyFile) {
	t.Helper()
	rows := a.auditRows(t)
	a.expectNoSecrets(t, rows)
	texts := map[string]string{"security log": strings.Join(a.securityLines(t), "\n")}
	for i, l := range append(logs, a.appLog) {
		texts["application log "+string(rune('A'+i))] = l.String()
	}
	for _, r := range rows {
		texts["audit event "+r.action] = strings.Join([]string{r.actor, r.ip, r.objectID, r.details}, " ")
	}
	for where, text := range texts {
		assertNoKeyMaterial(t, where, text, keys...)
		if !strings.HasPrefix(where, "application log") {
			continue
		}
		for _, s := range a.secrets {
			if len(s) >= 6 && !digitsRE.MatchString(s) && strings.Contains(text, s) {
				t.Errorf("%s contains the secret %.12s...", where, s)
			}
		}
	}
}

// errFeedClosed is the measure failure of a closed diskFeed.
var errFeedClosed = errors.New("disk feed closed")

// diskFeed is the fake disk measure of a disk alert monitor: every
// measure blocks until the test sends the share of the disk used, so that
// the test decides when each evaluation happens and what it sees. Closing
// the feed makes every later measure fail at once, so that the monitor
// stops at shutdown.
type diskFeed struct {
	ch   chan float64
	quit chan struct{}
	once sync.Once
}

// diskTotal is the size of the fake filesystem.
const diskTotal = 1_000_000_000

// newDiskFeed returns an open feed.
func newDiskFeed() *diskFeed {
	return &diskFeed{ch: make(chan float64), quit: make(chan struct{})}
}

// measure implements diskalert.Options.Measure.
func (f *diskFeed) measure(string) (total, free uint64, err error) {
	select {
	case r := <-f.ch:
		used := uint64(r * diskTotal)
		return diskTotal, diskTotal - used, nil
	case <-f.quit:
		return 0, 0, errFeedClosed
	}
}

// send hands the ratio r to the next measure, waiting for it.
func (f *diskFeed) send(t *testing.T, r float64) {
	t.Helper()
	select {
	case f.ch <- r:
	case <-f.quit:
		t.Fatal("disk feed closed")
	case <-t.Context().Done():
		t.Fatal("test canceled while feeding the disk measure")
	}
}

// step makes the monitor evaluate the ratio r to its end: the second send
// is taken by the next evaluation only once the first one is complete
// (Run evaluates sequentially); the second evaluation sees the same ratio
// and the level the first one left, so it changes nothing. It needs a
// short Interval.
func (f *diskFeed) step(t *testing.T, r float64) {
	t.Helper()
	f.send(t, r)
	f.send(t, r)
}

// close makes every later measure fail; it is idempotent.
func (f *diskFeed) close() { f.once.Do(func() { close(f.quit) }) }

// options returns the disk alert options of a server measured by f,
// evaluating every interval.
func (f *diskFeed) options(interval time.Duration) func(*diskalert.Options) {
	return func(o *diskalert.Options) {
		o.Measure = f.measure
		o.Interval = interval
	}
}
