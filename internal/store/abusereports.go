package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tenant"
)

// Limits of the abuse reports (spec 10, data model 2.5).
const (
	// MaxAbuseReportTextLen bounds the message of a report and the note of
	// an administrator, in characters.
	MaxAbuseReportTextLen = 1000
	// MaxAbuseReportClosedByLen bounds the name of the administrator who
	// closed a report, in characters.
	MaxAbuseReportClosedByLen = 64
	// AbuseReportRetentionMonths is how long a report is kept after its
	// creation, whatever its status (data model 5.1, same as the logs).
	AbuseReportRetentionMonths = 12
	// AbuseReportLinkWindow and AbuseReportIPWindow are the windows of the
	// rate limits of [AbuseReportLimits].
	AbuseReportLinkWindow = 24 * time.Hour
	AbuseReportIPWindow   = time.Hour
	// DefaultAbuseReportsPerLink and DefaultAbuseReportsPerIP are the rate
	// limits of decision D13.
	DefaultAbuseReportsPerLink = 3
	DefaultAbuseReportsPerIP   = 5
)

// Errors of [AbuseReports.Create]. Nothing is recorded.
var (
	// ErrAbuseReportLinkLimit reports a link that already carried
	// [AbuseReportLimits.PerLinkPerDay] reports over the last
	// AbuseReportLinkWindow.
	ErrAbuseReportLinkLimit = errors.New("store: too many abuse reports for this link")
	// ErrAbuseReportIPLimit reports an IP that already filed
	// [AbuseReportLimits.PerIPPerHour] reports over the last
	// AbuseReportIPWindow.
	ErrAbuseReportIPLimit = errors.New("store: too many abuse reports from this ip")
)

// AbuseCategory is the category of an abuse report (OpenAPI
// AbuseReportCategory).
type AbuseCategory string

// Abuse report categories.
const (
	AbuseCategoryMalware        AbuseCategory = "malware"
	AbuseCategoryPhishing       AbuseCategory = "phishing"
	AbuseCategoryIllegalContent AbuseCategory = "illegal_content"
	AbuseCategorySpam           AbuseCategory = "spam"
	AbuseCategoryUnknownSender  AbuseCategory = "unknown_sender"
	AbuseCategoryOther          AbuseCategory = "other"
)

// Valid reports whether c is a known category.
func (c AbuseCategory) Valid() bool {
	switch c {
	case AbuseCategoryMalware, AbuseCategoryPhishing, AbuseCategoryIllegalContent, AbuseCategorySpam,
		AbuseCategoryUnknownSender, AbuseCategoryOther:
		return true
	}
	return false
}

// AbuseReportStatus is the state of an abuse report (OpenAPI
// AbuseReportStatus).
type AbuseReportStatus string

// Abuse report states.
const (
	// AbuseReportOpen is a report waiting for an administrator.
	AbuseReportOpen AbuseReportStatus = "open"
	// AbuseReportClosed is a report an administrator closed.
	AbuseReportClosed AbuseReportStatus = "closed"
)

// Valid reports whether s is a known state.
func (s AbuseReportStatus) Valid() bool { return s == AbuseReportOpen || s == AbuseReportClosed }

// abuseReportColumns is the column list read by the abuse report queries.
const abuseReportColumns = `id, transfer_id, recipient_link_id, sender_email, recipient_position, reporter_email, ` +
	`reporter_verified, reporter_ip, category, message, status, closed_at, closed_by, note, created_at`

// Statements of the AbuseReports repository. All of them are single-table
// tenant queries.
var (
	qAbuseReportInsert = tenantQuery(
		`INSERT INTO abuse_reports (tenant_id, id, transfer_id, recipient_link_id, sender_email, recipient_position,
		reporter_email, reporter_verified, reporter_ip, category, message, status, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', '', ?)`)
	// The rate counts use abuse_reports_link_rate_idx,
	// abuse_reports_shared_rate_idx and abuse_reports_ip_rate_idx.
	qAbuseReportCountLink = tenantQuery(
		`SELECT count(*) FROM abuse_reports WHERE tenant_id = ? AND recipient_link_id = ? AND created_at >= ?`)
	qAbuseReportCountShared = tenantQuery(
		`SELECT count(*) FROM abuse_reports
		WHERE tenant_id = ? AND recipient_link_id IS NULL AND transfer_id = ? AND created_at >= ?`)
	qAbuseReportCountIP = tenantQuery(
		`SELECT count(*) FROM abuse_reports WHERE tenant_id = ? AND reporter_ip = ? AND created_at >= ?`)
	qAbuseReportGet = tenantQuery(
		`SELECT ` + abuseReportColumns + ` FROM abuse_reports WHERE tenant_id = ? AND id = ?`)
	// The lists go newest first after a keyset cursor (created_at, id),
	// through abuse_reports_list_idx when filtered by status.
	qAbuseReportList = tenantQuery(
		`SELECT ` + abuseReportColumns + ` FROM abuse_reports WHERE tenant_id = ? AND (created_at, id) < (?, ?)
		ORDER BY created_at DESC, id DESC LIMIT ?`)
	qAbuseReportListStatus = tenantQuery(
		`SELECT ` + abuseReportColumns + ` FROM abuse_reports WHERE tenant_id = ? AND status = ?
		AND (created_at, id) < (?, ?) ORDER BY created_at DESC, id DESC LIMIT ?`)
	// The status changes are guarded by the current status, so that a
	// concurrent change is detected.
	qAbuseReportClose = tenantQuery(
		`UPDATE abuse_reports SET status = 'closed', closed_at = ?, closed_by = ?
		WHERE tenant_id = ? AND id = ? AND status = 'open'`)
	qAbuseReportCloseNote = tenantQuery(
		`UPDATE abuse_reports SET status = 'closed', closed_at = ?, closed_by = ?, note = ?
		WHERE tenant_id = ? AND id = ? AND status = 'open'`)
	qAbuseReportReopen = tenantQuery(
		`UPDATE abuse_reports SET status = 'open', closed_at = NULL, closed_by = NULL
		WHERE tenant_id = ? AND id = ? AND status = 'closed'`)
	qAbuseReportReopenNote = tenantQuery(
		`UPDATE abuse_reports SET status = 'open', closed_at = NULL, closed_by = NULL, note = ?
		WHERE tenant_id = ? AND id = ? AND status = 'closed'`)
	// GDPR erasure (data model 5.2): the count runs first, so that a
	// report both sent and filed by the address counts once.
	qAbuseReportCountByEmail = tenantQuery(
		`SELECT count(*) FROM abuse_reports WHERE tenant_id = ? AND (sender_email = ? OR reporter_email = ?)`)
	qAbuseReportPseudonymiseSender = tenantQuery(
		`UPDATE abuse_reports SET sender_email = ? WHERE tenant_id = ? AND sender_email = ?`)
	qAbuseReportPseudonymiseReporter = tenantQuery(
		`UPDATE abuse_reports SET reporter_email = ? WHERE tenant_id = ? AND reporter_email = ?`)
	// The texts are scanned in id order, in batches, and rewritten in Go:
	// the case-insensitive whole-address match is not portable in SQL.
	qAbuseReportTexts = tenantQuery(
		`SELECT id, sender_email, reporter_email, message, note FROM abuse_reports
		WHERE tenant_id = ? AND id > ? AND (message <> '' OR note <> '') ORDER BY id LIMIT ?`)
	qAbuseReportPseudonymiseText = tenantQuery(
		`UPDATE abuse_reports SET message = ?, note = ? WHERE tenant_id = ? AND id = ?`)
	qAbuseReportPurgeList = tenantQuery(
		`SELECT id FROM abuse_reports WHERE tenant_id = ? AND created_at < ? AND id > ? ORDER BY id LIMIT ?`)
	qAbuseReportPurge = tenantQuery(
		`DELETE FROM abuse_reports WHERE tenant_id = ? AND id = ? AND created_at < ?`)
)

// AbuseReport is a report filed from a download page (spec 10, OpenAPI
// AbuseReport). It is a snapshot: it outlives the transfer it reports.
type AbuseReport struct {
	// ID is the identifier ("abr_" + ULID), assigned by the store when "".
	ID string
	// TransferID is the reported transfer.
	TransferID string
	// RecipientLinkID is the recipient link used ("rcl_" + ULID), "" for a
	// shared link (transfers created before 1.1).
	RecipientLinkID string
	// RecipientPosition is the position (0-based) of the recipient of
	// RecipientLinkID, nil exactly when RecipientLinkID is "": an
	// unverified hint ("via the link of recipient #n").
	RecipientPosition *int
	// SenderEmail is the sender of the transfer, normalized by the store;
	// the erasure pseudonym after a GDPR erasure.
	SenderEmail string
	// ReporterEmail is the address of the reporter, set only when a valid
	// recipient verification of the link proved it (ReporterVerified),
	// normalized by the store; the erasure pseudonym after a GDPR erasure.
	ReporterEmail string
	// ReporterVerified tells whether the reporter proved being the
	// recipient of the link; it is true exactly when ReporterEmail is set,
	// and needs a RecipientLinkID.
	ReporterVerified bool
	// ReporterIP is the client IP of the reporter.
	ReporterIP netip.Addr
	// Category is the category chosen by the reporter.
	Category AbuseCategory
	// Message is the plain-text message of the reporter (at most
	// MaxAbuseReportTextLen characters), sanitized by the caller.
	Message string
	// Status is the state; a new report is open.
	Status AbuseReportStatus
	// ClosedAt and ClosedBy are the time and the administrator of the
	// closing, zero and "" while the report is open.
	ClosedAt time.Time
	ClosedBy string
	// Note is the note of the administrators (at most
	// MaxAbuseReportTextLen characters).
	Note string
	// CreatedAt is the time of the report.
	CreatedAt time.Time
}

// AbuseReportLimits are the rate limits checked by [AbuseReports.Create].
// A limit of 0 or less disables its check.
type AbuseReportLimits struct {
	// PerLinkPerDay bounds the reports through one link (a recipient link,
	// or the shared link of a transfer) over AbuseReportLinkWindow.
	PerLinkPerDay int
	// PerIPPerHour bounds the reports of one client IP over
	// AbuseReportIPWindow.
	PerIPPerHour int
}

// DefaultAbuseReportLimits returns the limits of decision D13: 3 per link
// per day and 5 per IP per hour.
func DefaultAbuseReportLimits() AbuseReportLimits {
	return AbuseReportLimits{PerLinkPerDay: DefaultAbuseReportsPerLink, PerIPPerHour: DefaultAbuseReportsPerIP}
}

// AbuseReports is the tenant-scoped repository of the abuse reports.
// Obtain it with [DB.AbuseReports].
type AbuseReports struct {
	db *DB
}

// AbuseReports returns the abuse report repository.
func (db *DB) AbuseReports() *AbuseReports { return &AbuseReports{db: db} }

// validNote reports whether s is a message or a note: text of at most
// MaxAbuseReportTextLen characters without NUL.
func validNote(s string) bool { return validBody(s, MaxAbuseReportTextLen) }

// normalizeAbuseReport validates a new report and returns it normalized,
// open, created at now, with its ID assigned when empty, and its IP in
// text form.
func (r *AbuseReports) normalizeAbuseReport(rep AbuseReport, now time.Time) (AbuseReport, string, error) {
	sender, err := NormalizeEmail(rep.SenderEmail)
	if err != nil {
		return AbuseReport{}, "", err
	}
	rep.SenderEmail = sender
	if rep.ReporterEmail != "" {
		reporter, err := NormalizeEmail(rep.ReporterEmail)
		if err != nil {
			return AbuseReport{}, "", err
		}
		rep.ReporterEmail = reporter
	}
	ip, err := ipText(rep.ReporterIP)
	if err != nil {
		return AbuseReport{}, "", err
	}
	switch {
	case rep.ID != "" && !id.Valid(id.AbuseReport, rep.ID):
		return AbuseReport{}, "", invalid("malformed abuse report id")
	case !id.Valid(id.Transfer, rep.TransferID):
		return AbuseReport{}, "", invalid("malformed transfer id")
	case rep.RecipientLinkID != "" && !validLinkID(rep.RecipientLinkID):
		return AbuseReport{}, "", invalid("malformed recipient link id")
	case (rep.RecipientLinkID == "") != (rep.RecipientPosition == nil):
		return AbuseReport{}, "", invalid("a recipient link needs its recipient position, a shared link none")
	case rep.RecipientPosition != nil && *rep.RecipientPosition < 0:
		return AbuseReport{}, "", invalid("recipient position must not be negative")
	case rep.ReporterVerified != (rep.ReporterEmail != ""):
		return AbuseReport{}, "", invalid("a reporter address is recorded only when verified")
	case rep.ReporterVerified && rep.RecipientLinkID == "":
		return AbuseReport{}, "", invalid("only a recipient link proves the reporter")
	case !rep.Category.Valid():
		return AbuseReport{}, "", invalid("unknown abuse report category")
	case !validNote(rep.Message):
		return AbuseReport{}, "", invalid("message must be text of at most %d characters", MaxAbuseReportTextLen)
	case rep.Status != "" && rep.Status != AbuseReportOpen,
		!rep.ClosedAt.IsZero(), rep.ClosedBy != "", rep.Note != "":
		return AbuseReport{}, "", invalid("a new abuse report is open, without note")
	}
	if rep.ID == "" {
		rep.ID, err = r.db.newID(id.AbuseReport)
		if err != nil {
			return AbuseReport{}, "", err
		}
	}
	rep.Status = AbuseReportOpen
	rep.CreatedAt = now.UTC().Truncate(time.Millisecond)
	rep.ReporterIP = parseIP(ip)
	return rep, ip, nil
}

// Create records the report rep for tenant tid at now (the store's clock
// when zero) in its own transaction and returns the stored report (see
// [AbuseReports.CreateTx]).
func (r *AbuseReports) Create(ctx context.Context, tid tenant.ID, rep AbuseReport, limits AbuseReportLimits, now time.Time) (AbuseReport, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return AbuseReport{}, err
	}
	var out AbuseReport
	err := writeScoped(ctx, r.db, tid, "create abuse report", func(tx *ScopedTx) error {
		var err error
		out, err = r.create(ctx, tx, rep, limits, now)
		return err
	})
	if err != nil {
		return AbuseReport{}, err
	}
	return out, nil
}

// CreateTx records the report rep inside tx, for the tenant tx is bound
// to, at now (the store's clock when zero), and returns the stored report:
// open, without note, its addresses normalized and its ID assigned when
// empty. Under the tenant lock, it first counts the reports of the same
// link (rep.RecipientLinkID, or the shared link of rep.TransferID when it
// is "") created over the last AbuseReportLinkWindow and those of the same
// reporter IP over the last AbuseReportIPWindow, and returns
// ErrAbuseReportLinkLimit or ErrAbuseReportIPLimit (link first),
// recording nothing, when a count reached its limit. It returns
// ErrInvalid for a malformed field (see [AbuseReport]: unknown category, a
// message too long, a reporter address without verification or a verified
// reporter without a recipient link...), ErrNotFound when the tenant does
// not exist and ErrConflict when the ID is already used. After an error,
// the caller must abort the transaction.
func (r *AbuseReports) CreateTx(ctx context.Context, tx *ScopedTx, rep AbuseReport, limits AbuseReportLimits, now time.Time) (AbuseReport, error) {
	out, err := r.create(ctx, tx, rep, limits, now)
	if err != nil {
		return AbuseReport{}, wrap("create abuse report", err)
	}
	return out, nil
}

// create implements CreateTx, returning raw errors.
func (r *AbuseReports) create(ctx context.Context, tx *ScopedTx, rep AbuseReport, limits AbuseReportLimits, now time.Time) (AbuseReport, error) {
	now = r.db.orNow(now)
	rep, ip, err := r.normalizeAbuseReport(rep, now)
	if err != nil {
		return AbuseReport{}, err
	}
	if limits.PerLinkPerDay > 0 {
		q, key := qAbuseReportCountLink, rep.RecipientLinkID
		if key == "" {
			q, key = qAbuseReportCountShared, rep.TransferID
		}
		n, err := countTx(ctx, tx, q, key, now.Add(-AbuseReportLinkWindow), "count abuse reports")
		if err != nil {
			return AbuseReport{}, err
		}
		if n >= limits.PerLinkPerDay {
			return AbuseReport{}, ErrAbuseReportLinkLimit
		}
	}
	if limits.PerIPPerHour > 0 {
		n, err := countTx(ctx, tx, qAbuseReportCountIP, ip, now.Add(-AbuseReportIPWindow), "count abuse reports")
		if err != nil {
			return AbuseReport{}, err
		}
		if n >= limits.PerIPPerHour {
			return AbuseReport{}, ErrAbuseReportIPLimit
		}
	}
	_, err = tx.Exec(ctx, qAbuseReportInsert, rep.ID, rep.TransferID, nullText(rep.RecipientLinkID), rep.SenderEmail,
		nullInt(rep.RecipientPosition), nullText(rep.ReporterEmail), rep.ReporterVerified, ip, string(rep.Category),
		rep.Message, toMillis(rep.CreatedAt))
	if err != nil {
		return AbuseReport{}, err
	}
	return rep, nil
}

// scanAbuseReport reads one row of abuseReportColumns.
func scanAbuseReport(sc interface{ Scan(...any) error }) (AbuseReport, error) {
	var (
		rep                     AbuseReport
		link, reporter, closeBy sql.NullString
		pos, closed             sql.NullInt64
		ip, category, status    string
		created                 int64
	)
	err := sc.Scan(&rep.ID, &rep.TransferID, &link, &rep.SenderEmail, &pos, &reporter, &rep.ReporterVerified, &ip,
		&category, &rep.Message, &status, &closed, &closeBy, &rep.Note, &created)
	if err != nil {
		return AbuseReport{}, err
	}
	rep.RecipientLinkID, rep.RecipientPosition, rep.ReporterEmail = link.String, intPtr(pos), reporter.String
	rep.ReporterIP, rep.Category, rep.Status = parseIP(ip), AbuseCategory(category), AbuseReportStatus(status)
	rep.ClosedAt, rep.ClosedBy, rep.CreatedAt = nullMillis(closed), closeBy.String, fromMillis(created)
	return rep, nil
}

// Get returns the report repID of tenant tid, or ErrNotFound when it does
// not exist or belongs to another tenant.
func (r *AbuseReports) Get(ctx context.Context, tid tenant.ID, repID string) (AbuseReport, error) {
	return readScoped(ctx, r.db, tid, "get abuse report", func(tx *ScopedTx) (AbuseReport, error) {
		return scanAbuseReport(tx.QueryRow(ctx, qAbuseReportGet, repID))
	})
}

// List returns a page of the reports of tenant tid, newest first (by
// creation time, then ID), restricted to status unless it is "". The
// cursor is the NextCursor of the previous page ("" for the first) and
// limit the page size (DefaultPageSize when <= 0, at most MaxPageSize).
// It returns ErrInvalid for an unknown status or a malformed cursor.
func (r *AbuseReports) List(ctx context.Context, tid tenant.ID, status AbuseReportStatus, limit int, cursor string) (Page[AbuseReport], error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return Page[AbuseReport]{}, err
	}
	if status != "" && !status.Valid() {
		return Page[AbuseReport]{}, invalid("unknown abuse report status")
	}
	at, after, err := parseTimeCursor(cursor, id.AbuseReport)
	if err != nil {
		return Page[AbuseReport]{}, err
	}
	limit = pageLimit(limit)
	items, err := readScoped(ctx, r.db, tid, "list abuse reports", func(tx *ScopedTx) ([]AbuseReport, error) {
		var (
			rows *sql.Rows
			err  error
		)
		if status == "" {
			rows, err = tx.Query(ctx, qAbuseReportList, at, after, limit+1)
		} else {
			rows, err = tx.Query(ctx, qAbuseReportListStatus, string(status), at, after, limit+1)
		}
		if err != nil {
			return nil, err
		}
		return collect(rows, func(r *sql.Rows) (AbuseReport, error) { return scanAbuseReport(r) })
	})
	if err != nil {
		return Page[AbuseReport]{}, err
	}
	return paginate(items, limit, func(a AbuseReport) string { return timeCursor(a.CreatedAt, a.ID) }), nil
}

// SetStatus moves the report repID of tenant tid to status at now (the
// store's clock when zero) and returns the stored report and whether it
// changed. Closing sets ClosedAt and ClosedBy to by (the administrator, 1
// to MaxAbuseReportClosedByLen characters on one line); reopening clears
// them. In both directions, a non-nil note replaces the note, which is
// kept otherwise. A report already in status is returned unchanged
// (changed false), note included. It returns ErrInvalid for an unknown
// status, a malformed by when closing or a note too long; ErrNotFound when
// the report does not exist or belongs to another tenant; ErrConflict when
// its status changed concurrently.
func (r *AbuseReports) SetStatus(ctx context.Context, tid tenant.ID, repID string, status AbuseReportStatus, by string, note *string, now time.Time) (AbuseReport, bool, error) {
	if _, err := r.db.Scoped(tid); err != nil {
		return AbuseReport{}, false, err
	}
	switch {
	case !status.Valid():
		return AbuseReport{}, false, invalid("unknown abuse report status")
	case status == AbuseReportClosed && (by == "" || !validText(by, MaxAbuseReportClosedByLen, true)):
		return AbuseReport{}, false, invalid("closing needs an administrator of at most %d characters", MaxAbuseReportClosedByLen)
	case note != nil && !validNote(*note):
		return AbuseReport{}, false, invalid("note must be text of at most %d characters", MaxAbuseReportTextLen)
	}
	ms := toMillis(r.db.orNow(now))
	var (
		out     AbuseReport
		changed bool
	)
	err := writeScoped(ctx, r.db, tid, "set abuse report status", func(tx *ScopedTx) error {
		cur, err := scanAbuseReport(tx.QueryRow(ctx, qAbuseReportGet, repID))
		if err != nil {
			return err
		}
		if cur.Status == status {
			out = cur
			return nil
		}
		var res sql.Result
		switch {
		case status == AbuseReportClosed && note == nil:
			res, err = tx.Exec(ctx, qAbuseReportClose, ms, by, repID)
		case status == AbuseReportClosed:
			res, err = tx.Exec(ctx, qAbuseReportCloseNote, ms, by, *note, repID)
		case note == nil:
			res, err = tx.Exec(ctx, qAbuseReportReopen, repID)
		default:
			res, err = tx.Exec(ctx, qAbuseReportReopenNote, *note, repID)
		}
		if err != nil {
			return err
		}
		if err := expectOne(res); errors.Is(err, ErrNotFound) {
			return ErrConflict
		} else if err != nil {
			return err
		}
		changed = true
		out, err = scanAbuseReport(tx.QueryRow(ctx, qAbuseReportGet, repID))
		return err
	})
	if err != nil {
		return AbuseReport{}, false, err
	}
	return out, changed, nil
}

// PseudonymiseTx replaces, inside tx, the address email (normalized) by
// pseudonym in the reports of the tenant tx is bound to: as the reported
// sender, as the verified reporter (who stays marked verified), and in the
// message and the note, where every occurrence of the whole address is
// replaced whatever its case (a text that the pseudonym makes longer than
// MaxAbuseReportTextLen characters is cut). It returns how many reports it
// changed, each counted once (GDPR erasure, data model 5.2). It returns
// ErrInvalid for a malformed address or a pseudonym that [IsPseudonym]
// rejects. After an error, the caller must abort the transaction.
func (r *AbuseReports) PseudonymiseTx(ctx context.Context, tx *ScopedTx, email, pseudonym string) (int64, error) {
	n, err := func() (int64, error) {
		email, err := NormalizeEmail(email)
		if err != nil {
			return 0, err
		}
		if !IsPseudonym(pseudonym) {
			return 0, invalid("malformed pseudonym")
		}
		var n int64
		if err := tx.QueryRow(ctx, qAbuseReportCountByEmail, email, email).Scan(&n); err != nil {
			return 0, err
		}
		texts, err := pseudonymiseTexts(ctx, tx, email, pseudonym, PurgeBatchSize)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, qAbuseReportPseudonymiseSender, pseudonym, email); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, qAbuseReportPseudonymiseReporter, pseudonym, email); err != nil {
			return 0, err
		}
		return n + texts, nil
	}()
	if err != nil {
		return 0, wrap("pseudonymise abuse reports", err)
	}
	return n, nil
}

// abuseReportText is a report whose message or note is not empty, as read
// by pseudonymiseTexts.
type abuseReportText struct {
	id, sender    string
	reporter      sql.NullString
	message, note string
}

// pseudonymiseTexts replaces the address email (normalized) by pseudonym
// in the message and the note of the reports of the tenant tx is bound to,
// in batches of size, and returns how many reports it changed
// that neither were sent nor filed by email (those are counted by the
// caller). It runs before the sender and reporter columns change.
func pseudonymiseTexts(ctx context.Context, tx *ScopedTx, email, pseudonym string, size int) (int64, error) {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(email))
	var (
		changed int64
		after   string
	)
	for {
		rows, err := tx.Query(ctx, qAbuseReportTexts, after, size)
		if err != nil {
			return 0, err
		}
		batch, err := collect(rows, func(r *sql.Rows) (abuseReportText, error) {
			var t abuseReportText
			err := r.Scan(&t.id, &t.sender, &t.reporter, &t.message, &t.note)
			return t, err
		})
		if err != nil {
			return 0, err
		}
		for _, t := range batch {
			msg, m := replaceAddress(re, t.message, pseudonym)
			note, o := replaceAddress(re, t.note, pseudonym)
			if !m && !o {
				continue
			}
			if _, err := tx.Exec(ctx, qAbuseReportPseudonymiseText, msg, note, t.id); err != nil {
				return 0, err
			}
			if t.sender != email && t.reporter.String != email {
				changed++
			}
		}
		if len(batch) < size {
			return changed, nil
		}
		after = batch[len(batch)-1].id
	}
}

// replaceAddress replaces in text every match of re, an address compared
// case-insensitively, that is a whole address (not a part of a longer
// one), by repl, and reports whether it changed text. The result is cut to
// MaxAbuseReportTextLen characters.
func replaceAddress(re *regexp.Regexp, text, repl string) (string, bool) {
	var (
		b    strings.Builder
		last int
	)
	for _, m := range re.FindAllStringIndex(text, -1) {
		if !addressBoundary(text, m[0], m[1]) {
			continue
		}
		b.WriteString(text[last:m[0]])
		b.WriteString(repl)
		last = m[1]
	}
	if last == 0 {
		return text, false
	}
	b.WriteString(text[last:])
	out := b.String()
	if utf8.RuneCountInString(out) > MaxAbuseReportTextLen {
		out = string([]rune(out)[:MaxAbuseReportTextLen])
	}
	return out, true
}

// addressBoundary reports whether text[start:end] is a whole address: not
// preceded by a character of a local part, nor followed by a character of
// a domain (a final dot ends a sentence, a dot followed by a letter or a
// digit continues the domain).
func addressBoundary(text string, start, end int) bool {
	if r, _ := utf8.DecodeLastRuneInString(text[:start]); start > 0 && isLocalPartRune(r) {
		return false
	}
	r, size := utf8.DecodeRuneInString(text[end:])
	switch {
	case end == len(text):
		return true
	case r == '.':
		next, _ := utf8.DecodeRuneInString(text[end+size:])
		return !isAlnum(next)
	default:
		return !isAlnum(r) && r != '-' && r != '_'
	}
}

// isAlnum reports whether r is a letter or a digit.
func isAlnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// isLocalPartRune reports whether r may appear in the local part of an
// address (RFC 5322 atext and the dot, any letter or digit).
func isLocalPartRune(r rune) bool {
	return isAlnum(r) || strings.ContainsRune(".!#$%&'*+/=?^_`{|}~-", r)
}

// Purge deletes the reports of tenant tid created strictly before now
// minus AbuseReportRetentionMonths (calendar months, UTC), whatever their
// status (data model 5.1), in batches of PurgeBatchSize, and returns how
// many it deleted.
func (r *AbuseReports) Purge(ctx context.Context, tid tenant.ID, now time.Time) (int64, error) {
	cutoff := toMillis(now.UTC().AddDate(0, -AbuseReportRetentionMonths, 0))
	return r.db.purge(ctx, tid, "purge abuse reports", false, func(ctx context.Context, tx *ScopedTx, after string, size int) (int64, string, bool, error) {
		return deleteEach(ctx, tx, qAbuseReportPurgeList, []any{cutoff}, after, size, qAbuseReportPurge,
			func(k string) []any { return []any{k, cutoff} })
	})
}
