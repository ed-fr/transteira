-- 0010_operations (SQLite): operation of a tenant from the administration
-- (spec 8.5, 20 and 21): administrator view of the transfers, daily usage
-- counters, quota alert levels and the indexes of the GDPR searches. Keep
-- in sync with migrations/postgres/0010_operations.sql. Timestamps are
-- Unix milliseconds (UTC).

-- sender_ip is the client IP of the sender when the transfer was created
-- (canonical text form), NULL for the transfers created before 0010.
-- download_count counts the download starts of a file or of the archive.
ALTER TABLE transfers ADD COLUMN sender_ip TEXT;
ALTER TABLE transfers ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0);

-- Daily usage counters of a tenant (statistics, spec 21.2). day is 00:00
-- UTC of the day. The counters hold no personal data, so the GDPR erasure
-- never touches them; the cleanup task purges them after 13 months.
CREATE TABLE tenant_daily_stats (
    tenant_id        TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    day              INTEGER NOT NULL CHECK (day % 86400000 = 0),
    transfers        INTEGER NOT NULL DEFAULT 0 CHECK (transfers >= 0),
    bytes_uploaded   INTEGER NOT NULL DEFAULT 0 CHECK (bytes_uploaded >= 0),
    downloads        INTEGER NOT NULL DEFAULT 0 CHECK (downloads >= 0),
    bytes_downloaded INTEGER NOT NULL DEFAULT 0 CHECK (bytes_downloaded >= 0),
    virus_detections INTEGER NOT NULL DEFAULT 0 CHECK (virus_detections >= 0),
    PRIMARY KEY (tenant_id, day)
) STRICT, WITHOUT ROWID;

-- Last quota alert level of a tenant (spec 8.5): 0 (none), 80 (warning)
-- or 100 (reached). Without a row, the level is 0.
CREATE TABLE tenant_quota_alerts (
    tenant_id  TEXT    NOT NULL PRIMARY KEY REFERENCES tenants (id) ON DELETE CASCADE,
    level      INTEGER NOT NULL CHECK (level IN (0, 80, 100)),
    changed_at INTEGER NOT NULL
) STRICT;

-- Backfill: the transfers already finalized feed the upload counters of
-- their finalization day. The past downloads are not known: they start
-- from zero.
INSERT INTO tenant_daily_stats (tenant_id, day, transfers, bytes_uploaded)
SELECT tenant_id, (finalized_at / 86400000) * 86400000, count(*), sum(total_bytes)
FROM transfers
WHERE finalized_at IS NOT NULL
GROUP BY tenant_id, (finalized_at / 86400000) * 86400000;

-- Administrator list of the transfers, newest first.
CREATE INDEX transfers_tenant_created_idx ON transfers (tenant_id, created_at, id);
-- GDPR searches by address.
CREATE INDEX transfer_recipients_email_idx ON transfer_recipients (tenant_id, email);
CREATE INDEX invitations_email_idx ON invitations (tenant_id, email);
CREATE INDEX deposit_sessions_email_idx ON deposit_sessions (tenant_id, email);
CREATE INDEX audit_events_tenant_actor_idx ON audit_events (tenant_id, actor);
-- Administrator list of the invitations, newest first.
CREATE INDEX invitations_created_idx ON invitations (tenant_id, created_at, id);
