package integration_test

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Helpers of the tenant operation tests (CLAUDE.md sections 5, 6.5, 8.5,
// 15.2, 20 and 21; api/openapi.yaml "Admin operations" and the global
// statistics and audit log of "Admin system"; threat model T-63, T-64,
// T-101, T-110).

// Admin API paths of the system operations.
const (
	pathGlobalAudit = "/api/v1/admin/system/audit-events"
	pathGlobalStats = "/api/v1/admin/system/stats"
)

// Audit actions of the tenant operations (api/openapi.yaml AuditAction).
const (
	actAddressVerified    = "address.verified"
	actTransferCreated    = "transfer.created"
	actTransferFinalized  = "transfer.finalized"
	actTransferDownloaded = "transfer.downloaded"
	actTransferDeleted    = "transfer.deleted"
	actTransferResent     = "transfer.notification_resent"
	actInvitationCreated  = "invitation.created"
	actInvitationUsed     = "invitation.used"
	actInvitationRevoked  = "invitation.revoked"
	actBlocklistUpdated   = "blocklist.updated"
	actQuotaWarning       = "quota.warning"
	actQuotaReached       = "quota.reached"
	actSubjectErased      = "data_subject.erased"
	actSubjectSearched    = "data_subject.searched"
)

// Subjects of the quota alert mails (internal/mail/templates/en).
const (
	quotaSubjectPrefix = "Storage quota of "
	quotaReachedWord   = "reached"
)

// pseudonymRE is the pseudonym that replaces an erased address.
var pseudonymRE = regexp.MustCompile(`^erased-[0-9a-f]{16}$`)

// opsEnv is a running server for the tenant operation tests: tenant A
// sends its mails to Mailpit, clamd is the fake of antivirustest, and the
// super admin, whose address is unique to the test, is signed in.
type opsEnv struct {
	*adminEnv
	av *antivirustest.Server
	sa *adminClient
	// tid is the identifier of tenant A.
	tid string
}

// startOps starts the server of a tenant operation test.
func startOps(t *testing.T, e storetest.Engine) *opsEnv {
	t.Helper()
	o, av := withScanner(t, serverOptions{})
	a := startAdmin(t, e, o, true)
	return &opsEnv{adminEnv: a, av: av, sa: a.bootstrapUnique(t, adminIP(10)), tid: string(a.tenantA.ID)}
}

// bootstrapUnique is bootstrap with a super admin address unique to the
// test: the quota alerts of a tenant without delegated admin are mailed to
// it, through the shared Mailpit.
func (a *adminEnv) bootstrapUnique(t *testing.T, ip string) *adminClient {
	t.Helper()
	acct := &adminAccount{username: superName, email: uniqueEmail(t, "root", domainA), password: superPassword}
	c := a.client(acct, ip)
	resp := mustStatus(t, "setup", c.setup(t, acct.username, acct.email, acct.password, adminSetupToken), http.StatusCreated)
	var enr enrollmentJSON
	mustJSON(t, resp.body, &enr)
	c.adopt(t, resp, enr.CSRFToken, stateEnrollRequired)
	acct.secret = decodeSecret(t, enr.Secret)
	a.secret(enr.Secret)
	if resp := c.confirm(t, acct.nextCode(t)); resp.status != http.StatusOK || c.state != stateAuthenticated {
		t.Fatalf("confirm the super admin enrollment: %d %s", resp.status, resp.body)
	}
	acct.id = c.me(t).ID
	return c
}

// restartServer stops the server, which flushes the usage counters and
// stops the quota monitor, and starts a new one on the same configuration;
// its quota monitor sweeps every tenant at start-up. The clients keep
// working: their sessions are in the database.
func (o *opsEnv) restartServer(t *testing.T) {
	t.Helper()
	if err := o.stop(); err != nil {
		t.Fatalf("stop: %v\napp log:\n%s", err, o.appLog)
	}
	o.server = o.restart(t)
}

// opsFile is a file of an AdminTransferDetail.
type opsFile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	MediaType  string `json:"mediaType"`
	Sha256     string `json:"sha256"`
	ScanStatus string `json:"scanStatus"`
}

// opsTransfer is the AdminTransfer and AdminTransferDetail schema.
type opsTransfer struct {
	ID                       string     `json:"id"`
	Status                   string     `json:"status"`
	Origin                   string     `json:"origin"`
	SenderEmail              string     `json:"senderEmail"`
	Recipients               []string   `json:"recipients"`
	InvitationID             string     `json:"invitationId"`
	FileCount                int        `json:"fileCount"`
	TotalBytes               int64      `json:"totalBytes"`
	PasswordProtected        bool       `json:"passwordProtected"`
	DeleteAfterFirstDownload bool       `json:"deleteAfterFirstDownload"`
	CreatedAt                time.Time  `json:"createdAt"`
	ExpiresAt                *time.Time `json:"expiresAt"`
	FirstDownloadedAt        *time.Time `json:"firstDownloadedAt"`
	DownloadCount            int64      `json:"downloadCount"`
	SenderIP                 *string    `json:"senderIp"`
	Files                    []opsFile  `json:"files"`
}

// opsTransferList is the AdminTransferList schema.
type opsTransferList struct {
	Items      []opsTransfer `json:"items"`
	NextCursor *string       `json:"nextCursor"`
}

// opsAuditEvent is the AuditEvent schema.
type opsAuditEvent struct {
	ID         string    `json:"id"`
	OccurredAt time.Time `json:"occurredAt"`
	TenantID   *string   `json:"tenantId"`
	Actor      struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"actor"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Object struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"object"`
	Details map[string]any `json:"details"`
}

// opsAuditList is the AuditEventList schema.
type opsAuditList struct {
	Items      []opsAuditEvent `json:"items"`
	NextCursor *string         `json:"nextCursor"`
}

// opsSeriesPoint is a point of TenantStats.series.
type opsSeriesPoint struct {
	Date          string `json:"date"`
	Transfers     int64  `json:"transfers"`
	BytesUploaded int64  `json:"bytesUploaded"`
}

// opsTenantStats is the TenantStats schema.
type opsTenantStats struct {
	Period            string           `json:"period"`
	TransferCount     int64            `json:"transferCount"`
	BytesUploaded     int64            `json:"bytesUploaded"`
	DownloadCount     int64            `json:"downloadCount"`
	BytesDownloaded   int64            `json:"bytesDownloaded"`
	VirusDetections   int64            `json:"virusDetections"`
	StorageUsedBytes  int64            `json:"storageUsedBytes"`
	StorageQuotaBytes int64            `json:"storageQuotaBytes"`
	StorageUsedRatio  float64          `json:"storageUsedRatio"`
	Series            []opsSeriesPoint `json:"series"`
}

// opsGlobalStats is the GlobalStats schema.
type opsGlobalStats struct {
	Period string `json:"period"`
	Disk   struct {
		TotalBytes     int64   `json:"totalBytes"`
		UsedBytes      int64   `json:"usedBytes"`
		UsedRatio      float64 `json:"usedRatio"`
		AlertThreshold float64 `json:"alertThreshold"`
	} `json:"disk"`
	Tenants []struct {
		TenantID          string  `json:"tenantId"`
		Name              string  `json:"name"`
		TransferCount     int64   `json:"transferCount"`
		BytesUploaded     int64   `json:"bytesUploaded"`
		StorageUsedBytes  int64   `json:"storageUsedBytes"`
		StorageQuotaBytes int64   `json:"storageQuotaBytes"`
		StorageUsedRatio  float64 `json:"storageUsedRatio"`
	} `json:"tenants"`
}

// opsInvitation is the Invitation schema.
type opsInvitation struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	InvitedBy  string     `json:"invitedBy"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

// opsInvitationList is the InvitationList schema.
type opsInvitationList struct {
	Items      []opsInvitation `json:"items"`
	NextCursor *string         `json:"nextCursor"`
}

// opsBlockEntry is the BlocklistEntry schema.
type opsBlockEntry struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Comment   *string   `json:"comment"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
}

// opsBlockList is the BlocklistList schema.
type opsBlockList struct {
	Items      []opsBlockEntry `json:"items"`
	NextCursor *string         `json:"nextCursor"`
}

// opsSubjectSummary is the DataSubjectSummary schema.
type opsSubjectSummary struct {
	Email                string `json:"email"`
	VerifiedAddress      bool   `json:"verifiedAddress"`
	TransfersAsSender    int    `json:"transfersAsSender"`
	TransfersAsRecipient int    `json:"transfersAsRecipient"`
	Invitations          int    `json:"invitations"`
	AuditEvents          int    `json:"auditEvents"`
	SecurityEvents       int    `json:"securityEvents"`
}

// opsEraseReport is the DataSubjectEraseReport schema.
type opsEraseReport struct {
	TransfersDeleted        int  `json:"transfersDeleted"`
	RecipientEntriesRemoved int  `json:"recipientEntriesRemoved"`
	VerifiedAddressDeleted  bool `json:"verifiedAddressDeleted"`
	InvitationsDeleted      int  `json:"invitationsDeleted"`
	LogEntriesPseudonymised int  `json:"logEntriesPseudonymised"`
	AccessLinks             int  `json:"accessLinks"`
}

// adminTransfer sends getTenantTransfer and decodes the 200 answer.
func (c *adminClient) adminTransfer(t *testing.T, tid, trfID string) opsTransfer {
	t.Helper()
	resp := mustStatus(t, "getTenantTransfer "+trfID, c.call(t, http.MethodGet, tenantPath(tid, "/transfers/"+trfID), nil), http.StatusOK)
	var out opsTransfer
	mustJSON(t, resp.body, &out)
	return out
}

// listTransfers sends listTenantTransfers with query and decodes the 200
// answer.
func (c *adminClient) listTransfers(t *testing.T, tid string, query url.Values) opsTransferList {
	t.Helper()
	resp := mustStatus(t, "listTenantTransfers", c.call(t, http.MethodGet, tenantPath(tid, "/transfers")+encodeQuery(query), nil), http.StatusOK)
	var out opsTransferList
	mustJSON(t, resp.body, &out)
	return out
}

// deleteTransfer sends deleteTenantTransfer, with the reason when it is
// not empty.
func (c *adminClient) deleteTransfer(t *testing.T, tid, trfID, reason string) response {
	t.Helper()
	var body any
	if reason != "" {
		body = map[string]string{"reason": reason}
	}
	return c.call(t, http.MethodDelete, tenantPath(tid, "/transfers/"+trfID), body)
}

// resend sends resendTransferNotification for recipients (no body when
// nil).
func (c *adminClient) resend(t *testing.T, tid, trfID string, recipients []string) response {
	t.Helper()
	var body any
	if recipients != nil {
		body = map[string][]string{"recipients": recipients}
	}
	return c.call(t, http.MethodPost, tenantPath(tid, "/transfers/"+trfID+"/resend"), body)
}

// invitations sends listTenantInvitations with query and decodes the 200
// answer.
func (c *adminClient) invitations(t *testing.T, tid string, query url.Values) opsInvitationList {
	t.Helper()
	resp := mustStatus(t, "listTenantInvitations", c.call(t, http.MethodGet, tenantPath(tid, "/invitations")+encodeQuery(query), nil), http.StatusOK)
	var out opsInvitationList
	mustJSON(t, resp.body, &out)
	return out
}

// revokeInvitation sends revokeInvitation.
func (c *adminClient) revokeInvitation(t *testing.T, tid, invID string) response {
	t.Helper()
	return c.call(t, http.MethodDelete, tenantPath(tid, "/invitations/"+invID), nil)
}

// searchSubject sends searchDataSubject and decodes the 200 answer.
func (c *adminClient) searchSubject(t *testing.T, tid, email string) opsSubjectSummary {
	t.Helper()
	resp := mustStatus(t, "searchDataSubject", c.call(t, http.MethodPost, tenantPath(tid, "/data-subjects/search"),
		map[string]string{"email": email}), http.StatusOK)
	var out opsSubjectSummary
	mustJSON(t, resp.body, &out)
	return out
}

// eraseSubject sends eraseDataSubject.
func (c *adminClient) eraseSubject(t *testing.T, tid, email string) response {
	t.Helper()
	return c.call(t, http.MethodPost, tenantPath(tid, "/data-subjects/erase"), map[string]string{"email": email})
}

// tenantStats sends getTenantStats for period and decodes the 200 answer.
func (c *adminClient) tenantStats(t *testing.T, tid, period string) opsTenantStats {
	t.Helper()
	resp := mustStatus(t, "getTenantStats "+period, c.call(t, http.MethodGet, tenantPath(tid, "/stats?period="+period), nil), http.StatusOK)
	var out opsTenantStats
	mustJSON(t, resp.body, &out)
	return out
}

// encodeQuery returns "?query" ("" for an empty query).
func encodeQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// auditPage sends one page of an audit list (path with its query).
func (c *adminClient) auditPage(t *testing.T, path string) opsAuditList {
	t.Helper()
	resp := mustStatus(t, "audit list "+path, c.call(t, http.MethodGet, path, nil), http.StatusOK)
	var out opsAuditList
	mustJSON(t, resp.body, &out)
	return out
}

// auditAll returns every event of the audit list base (the tenant or the
// global list) matching query, following the cursors, most recent first.
func (c *adminClient) auditAll(t *testing.T, base string, query url.Values) []opsAuditEvent {
	t.Helper()
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("limit", "200")
	var out []opsAuditEvent
	for range 1000 {
		page := c.auditPage(t, base+"?"+q.Encode())
		out = append(out, page.Items...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return out
		}
		q.Set("cursor", *page.NextCursor)
	}
	t.Fatalf("audit list %s: too many pages", base)
	return nil
}

// tenantEvents returns the events of tenant tid with the action (every
// action when empty), most recent first.
func (c *adminClient) tenantEvents(t *testing.T, tid, action string) []opsAuditEvent {
	t.Helper()
	q := url.Values{}
	if action != "" {
		q.Set("action", action)
	}
	return c.auditAll(t, tenantPath(tid, "/audit-events"), q)
}

// ofAction returns the events of action, in order.
func ofAction(events []opsAuditEvent, action string) []opsAuditEvent {
	var out []opsAuditEvent
	for _, ev := range events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// eventIDs returns the identifiers of events, in order.
func eventIDs(events []opsAuditEvent) []string {
	out := make([]string, len(events))
	for i, ev := range events {
		out[i] = ev.ID
	}
	return out
}

// detailNumber returns the number detail key of ev (-1 when absent or not
// a number).
func detailNumber(ev opsAuditEvent, key string) float64 {
	if v, ok := ev.Details[key].(float64); ok {
		return v
	}
	return -1
}

// expectNoAddressIn fails when the details of ev hold a mail address.
func expectNoAddressIn(t *testing.T, ev opsAuditEvent) {
	t.Helper()
	for k, v := range ev.Details {
		if s, ok := v.(string); ok && strings.Contains(s, "@") {
			t.Errorf("audit event %s detail %s = %q holds a mail address", ev.Action, k, s)
		}
	}
}

// expectEvent fails unless ev was recorded for tenant tid by the actor
// kind/id from ip about the object kind/id ("" skips a check).
func expectEvent(t *testing.T, ev opsAuditEvent, tid, actorKind, actorID, ip, objKind, objID string) {
	t.Helper()
	if ev.TenantID == nil || *ev.TenantID != tid {
		t.Errorf("%s: tenantId %v, want %s", ev.Action, ev.TenantID, tid)
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

// expectSeries checks a series of getTenantStats: n zero-filled points,
// oldest first, one per UTC day (monthly false) or per UTC month whose
// date is its first day (monthly true), ending with the current one; the
// point of the day (or month) of at holds count transfers of bytes, every
// other point zero.
func expectSeries(t *testing.T, label string, series []opsSeriesPoint, n int, monthly bool, at time.Time, count, bytes int64) {
	t.Helper()
	if len(series) != n {
		t.Fatalf("%s: %d points, want %d: %+v", label, len(series), n, series)
	}
	now := time.Now().UTC()
	at = at.UTC()
	for i, p := range series {
		var want, hit time.Time
		if monthly {
			want = time.Date(now.Year(), now.Month()-time.Month(n-1-i), 1, 0, 0, 0, 0, time.UTC)
			hit = time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		} else {
			want = time.Date(now.Year(), now.Month(), now.Day()-(n-1-i), 0, 0, 0, 0, time.UTC)
			hit = time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		}
		if p.Date != want.Format(time.DateOnly) {
			t.Errorf("%s: point %d date %q, want %q", label, i, p.Date, want.Format(time.DateOnly))
		}
		wc, wb := int64(0), int64(0)
		if want.Equal(hit) {
			wc, wb = count, bytes
		}
		if p.Transfers != wc || p.BytesUploaded != wb {
			t.Errorf("%s: point %s = %d transfers, %d bytes, want %d, %d", label, p.Date, p.Transfers, p.BytesUploaded, wc, wb)
		}
	}
}

// near reports whether a and b are equal within the precision of the
// float32 ratios of the API.
func near(a, b float64) bool { return math.Abs(a-b) <= 1e-6*math.Max(1, math.Abs(b)) }

// openSessionNth runs the code flow for email with invitation (or none),
// confirming with the newest code mail once the address has received n of
// them in total: it is openSession for an address that already received
// mails.
func (c *depositor) openSessionNth(t *testing.T, email, invitation string, n int) sessionJSON {
	t.Helper()
	ch := expectChallenge(t, c.start(t, email, invitation), email)
	code := c.d.waitCode(t, email, n)
	s, token, known := expectSessionWithKnown(t, c.confirm(t, ch.ChallengeID, code), email)
	c.cookie, c.csrf = token, s.CSRFToken
	if known != "" {
		c.known = known
	}
	return s
}

// inviteAndLink makes c invite email and returns the invitation identifier
// and the token of the link of the invitation mail.
func (c *depositor) inviteAndLink(t *testing.T, email string) (invID, token string) {
	t.Helper()
	resp := mustStatus(t, "createInvitation", c.invite(t, `{"email":"`+email+`"}`, c.withCSRF()), http.StatusCreated)
	var inv struct {
		ID string `json:"id"`
	}
	mustJSON(t, resp.body, &inv)
	msg := c.d.mp.find(t, email, func(m mpMessage) bool { return strings.Contains(m.Subject, "invite") })
	var full mpMessage
	c.d.mp.get(t, "/api/v1/message/"+url.PathEscape(msg.ID), &full)
	m := invitationLinkRE.FindStringSubmatch(full.Text)
	if m == nil {
		t.Fatalf("no invitation link in the mail to %s:\n%s", email, full.Text)
	}
	return inv.ID, m[1]
}

// invitedSession opens, from outside the ranges of tenant A, the external
// session of email with the invitation token; the address has received
// n-1 code mails before.
func (d *depositEnv) invitedSession(t *testing.T, email, token string, n int) *depositor {
	t.Helper()
	c := &depositor{d: d, host: hostA, ip: outside}
	if s := c.openSessionNth(t, email, token, n); s.Kind != "external" {
		t.Fatalf("invited session of %s is %q, want external", email, s.Kind)
	}
	return c
}

// setLimitsOf changes the per-transfer limit and the storage quota of
// tenant tid, as the super admin will.
func (d *depositEnv) setLimitsOf(t *testing.T, tid tenant.ID, maxTransfer, quota int64) {
	t.Helper()
	ctx := context.Background()
	tn, err := d.db.Tenants().Get(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	tn.MaxTransferBytes, tn.StorageQuotaBytes = maxTransfer, quota
	tn.MaxTransferCeiling = max(tn.MaxTransferCeiling, maxTransfer)
	if _, err := d.db.Tenants().Update(ctx, tn); err != nil {
		t.Fatalf("update tenant limits: %v", err)
	}
}

// quotaLevel returns the stored quota alert level of tenant tid (0 when no
// level was ever stored).
func quotaLevel(t *testing.T, e storetest.Engine, tid string) int {
	t.Helper()
	rows := sysQuery(t, e, `SELECT level FROM tenant_quota_alerts WHERE tenant_id = '`+tid+`'`)
	if len(rows) == 0 {
		return 0
	}
	n, err := strconv.Atoi(rows[0][0])
	if err != nil {
		t.Fatalf("quota level %q: %v", rows[0][0], err)
	}
	return n
}

// quotaMails returns the number of quota warning and quota reached mails
// to addr about the tenant name.
func (m *mailpit) quotaMails(t *testing.T, addr, name string) (warning, reached int) {
	t.Helper()
	for _, s := range m.subjects(t, addr) {
		if !strings.HasPrefix(s, quotaSubjectPrefix+name) {
			continue
		}
		if strings.Contains(s, quotaReachedWord) {
			reached++
		} else {
			warning++
		}
	}
	return warning, reached
}

// waitQuotaMails waits until addr has received at least the given numbers
// of quota mails about the tenant name.
func (m *mailpit) waitQuotaMails(t *testing.T, addr, name string, warning, reached int) {
	t.Helper()
	eventually(t, "quota mails to "+addr, func() bool {
		w, r := m.quotaMails(t, addr, name)
		return w >= warning && r >= reached
	})
}

// holdPatch starts a tus PATCH of c for the first half of data on the
// upload uploadURL of the transfer trfID, which must not have started
// (offset 0, no file on disk), and waits until the server holds the upload
// lock of that file; finish sends the rest and returns the response.
//
// The lock is observed through the encrypted file: the upload engine
// creates it, on the first byte of the body, while holding the lock, which
// it keeps until the PATCH ends. The wait must not probe with an operation
// that takes the upload lock itself (finalize, deletion): the PATCH that
// tries to lock during such a probe is refused with 409 (upload.ErrBusy),
// which is correct server behavior but not what this helper waits for.
func (c *depositor) holdPatch(t *testing.T, trfID, uploadURL string, data []byte) (finish func() response) {
	t.Helper()
	enc := c.d.encPath(c.d.storageNameOf(t, trfID, uploadURL))
	if exists(t, enc) {
		t.Fatalf("holdPatch: the upload %s has already started", uploadURL)
	}
	conn := c.rawPatch(t, uploadURL, 0, int64(len(data)))
	half := len(data) / 2
	if _, err := conn.Write(data[:half]); err != nil {
		t.Fatalf("write the first half of the PATCH: %v", err)
	}
	eventually(t, "upload lock held", func() bool {
		if exists(t, enc) {
			return true
		}
		failIfAnswered(t, conn)
		return false
	})
	// The file exists: the lock was taken. Make sure the PATCH is still
	// running, so that the lock is still held.
	failIfAnswered(t, conn)
	return func() response {
		if _, err := conn.Write(data[half:]); err != nil {
			t.Fatalf("write the rest of the PATCH: %v", err)
		}
		return readRawResponse(t, conn)
	}
}

// storageNameOf returns the storage name of the file of the transfer trfID
// of tenant A whose tus upload URL is uploadURL.
func (d *depositEnv) storageNameOf(t *testing.T, trfID, uploadURL string) string {
	t.Helper()
	for _, f := range d.files(t, trfID) {
		if strings.HasSuffix(uploadURL, "/"+f.UploadID) {
			return f.StorageName
		}
	}
	t.Fatalf("no file of %s has the upload URL %s", trfID, uploadURL)
	return ""
}

// failIfAnswered fails the test when the server already answered the
// half-sent PATCH on conn (an early refusal): waiting for its upload lock
// would otherwise run until the timeout without saying why. The answer
// itself may be lost: the server closes a refused PATCH with unread body
// bytes, and on Windows that close resets the connection, which discards
// the response not read yet; the read error then tells it.
func failIfAnswered(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	var first [1]byte
	n, err := conn.Read(first[:])
	_ = conn.SetReadDeadline(time.Time{})
	var ne net.Error
	if n == 0 && errors.As(err, &ne) && ne.Timeout() {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	rest, _ := io.ReadAll(conn)
	t.Fatalf("PATCH answered before its upload lock was seen (read error %v): %q", err, append(first[:n], rest...))
}

// expectRetryAfter checks a 409 state-conflict answer of an operation
// refused while an upload is in progress: Retry-After and
// retryAfterSeconds of want seconds.
func expectRetryAfter(t *testing.T, what string, resp response, want int) {
	t.Helper()
	p := expectProblem(t, resp, http.StatusConflict, "state-conflict")
	if got := resp.header.Get(hdrRetryAfter); got != strconv.Itoa(want) {
		t.Errorf("%s: Retry-After = %q, want %d", what, got, want)
	}
	if p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != want {
		t.Errorf("%s: retryAfterSeconds = %v, want %d", what, p.RetryAfterSeconds, want)
	}
}

// rowsWith returns, for each table and column holding a mail address, the
// number of rows of tenant tid whose column is addr.
func rowsWith(t *testing.T, e storetest.Engine, tid, addr string) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, tc := range []struct{ table, column string }{
		{"transfers", "sender_email"},
		{"transfer_recipients", "email"},
		{"invitations", "email"},
		{"invitations", "invited_by"},
		{"verified_addresses", "email"},
		{"verification_challenges", "email"},
		{"deposit_sessions", "email"},
		{"audit_events", "actor"},
	} {
		out[tc.table+"."+tc.column] = countSystem(t, e, `SELECT COUNT(*) FROM `+tc.table+` WHERE tenant_id = '`+tid+
			`' AND `+tc.column+` = '`+addr+`'`)
	}
	return out
}

// sortedKeys returns the keys of m, sorted.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
}
