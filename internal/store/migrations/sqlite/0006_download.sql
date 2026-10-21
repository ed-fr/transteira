-- 0006_download (SQLite): first download, deletion after the first
-- download and transfer password failures (spec 8.2, 10 and 16.2). Keep in
-- sync with migrations/postgres/0006_download.sql. Timestamps are Unix
-- milliseconds (UTC). SQLite cannot add a table constraint to an existing
-- table: the check added to transfers is a column check referencing other
-- columns, as in 0005.

-- first_downloaded_at is set once, by a conditional update, when every
-- byte of every deliverable file of an available transfer was served at
-- least once (or the whole archive was sent). delete_after is set with it
-- for a transfer with the "delete after the first download" option only:
-- the first download time plus a short grace, so that an interrupted last
-- range can resume. Once delete_after is past, the sweep erases the
-- transfer: the file keys are destroyed, then the files removed from disk,
-- then the served range state file removed; last, in one transaction that
-- re-checks the transfer is still due, the download token key is destroyed
-- and the status set to deleted.
ALTER TABLE transfers ADD COLUMN first_downloaded_at INTEGER;
ALTER TABLE transfers ADD COLUMN delete_after INTEGER
    CHECK (delete_after IS NULL OR (first_downloaded_at IS NOT NULL AND delete_after_first_download = 1));

-- Sweep of the transfers due for deletion after their first download,
-- across tenants (system query), earliest first.
CREATE INDEX transfers_delete_after_idx ON transfers (delete_after, id) WHERE delete_after IS NOT NULL;

-- Wrong transfer passwords (spec 10: 3 failures, then a 15-minute lock),
-- counted in two independent scopes per tenant: 'transfer' (key = the
-- transfer ID, all client IPs together) and 'ip' (key = the client IP, all
-- transfers of the tenant together). An IPv4 client (or IPv4-mapped IPv6)
-- is keyed by its address ("192.0.2.1"); an IPv6 client by its /64 prefix
-- ("2001:db8:1:2::/64"), the smallest block usually given to one site, so
-- that rotating addresses within it does not reset the count.
--
-- fail_1 to fail_3 are the times of the latest failures, oldest first
-- (NULL when fewer): 3 failures within any 15-minute span lock the key (a
-- sliding window) until locked_until (compared with the caller's clock).
-- An attempt is counted before the password is verified; a right password
-- refunds it on the IP key and deletes the transfer key. A row is stale 15
-- minutes after its latest failure once its lock is over: the cleanup task
-- purges stale rows. The primary key doubles as the tenant_id index.
CREATE TABLE password_failures (
    tenant_id    TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    scope        TEXT    NOT NULL CHECK (scope IN ('transfer', 'ip')),
    key          TEXT    NOT NULL CHECK (key <> ''),
    fail_1       INTEGER,
    fail_2       INTEGER,
    fail_3       INTEGER,
    locked_until INTEGER,
    PRIMARY KEY (tenant_id, scope, key)
) STRICT, WITHOUT ROWID;
