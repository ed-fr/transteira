-- 0031_drop_link_challenges (SQLite): verification codes sent for a
-- permanent drop link (V2, feature F5). Keep in sync with
-- migrations/postgres/0031_drop_link_challenges.sql. Timestamps are Unix
-- milliseconds (UTC). See docs/architecture/data-model-v2.md, section 2.6.
--
-- drop_link_id binds a deposit code to the drop link it was requested
-- through: the confirmation receives the challenge ID and the code only,
-- never the drop token, so the link (and the recheck that it is still
-- enabled and not revoked) is found through the challenge, exactly like
-- invitation_id for an invitation. A code is sent for an invitation or for
-- a drop link, never both (check), and only for a deposit (purpose
-- 'deposit'). The composite foreign key keeps the link in the tenant and
-- removes the codes with the link (a link is only deleted by the purge of
-- revoked links or with its tenant).
--
-- SQLite cannot add a composite foreign key with ALTER TABLE: the table is
-- rebuilt (create, copy, drop, rename), as in 0015. No table references
-- verification_challenges; the migrator disables foreign keys for every
-- SQLite migration and runs PRAGMA foreign_key_check before committing.
-- Dropping the table drops its indexes: every one is recreated. No trigger
-- or view references it.
CREATE TABLE verification_challenges_0031 (
    id                 TEXT    NOT NULL PRIMARY KEY,
    tenant_id          TEXT    NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email              TEXT    NOT NULL,
    code_mac           BLOB    NOT NULL,
    attempts_remaining INTEGER NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 2),
    invitation_id      TEXT,
    client_ip          TEXT    NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    consumed_at        INTEGER,
    purpose            TEXT    NOT NULL DEFAULT 'deposit' CHECK (purpose IN ('deposit', 'recipient')),
    recipient_link_id  TEXT,
    recipient_intent   TEXT    CHECK (recipient_intent IN ('download', 'reply')),
    drop_link_id       TEXT,
    CHECK (purpose = 'deposit' OR invitation_id IS NULL),
    CHECK ((recipient_link_id IS NOT NULL) = (purpose = 'recipient')),
    CHECK ((recipient_intent IS NULL) = (purpose = 'deposit')),
    CHECK (invitation_id IS NULL OR drop_link_id IS NULL),
    CHECK (purpose = 'deposit' OR drop_link_id IS NULL),
    FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, recipient_link_id) REFERENCES recipient_links (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, drop_link_id) REFERENCES drop_links (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO verification_challenges_0031 (id, tenant_id, email, code_mac, attempts_remaining, invitation_id,
    client_ip, created_at, expires_at, consumed_at, purpose, recipient_link_id, recipient_intent)
SELECT id, tenant_id, email, code_mac, attempts_remaining, invitation_id,
    client_ip, created_at, expires_at, consumed_at, purpose, recipient_link_id, recipient_intent
FROM verification_challenges;

DROP TABLE verification_challenges;
ALTER TABLE verification_challenges_0031 RENAME TO verification_challenges;

-- Indexes of verification_challenges (state after 0015), then the new one.
CREATE INDEX verification_challenges_email_idx ON verification_challenges (tenant_id, email, created_at);
CREATE INDEX verification_challenges_ip_idx ON verification_challenges (tenant_id, client_ip, created_at);
CREATE INDEX verification_challenges_created_idx ON verification_challenges (tenant_id, created_at);
CREATE INDEX verification_challenges_link_idx ON verification_challenges (tenant_id, recipient_link_id, created_at)
    WHERE recipient_link_id IS NOT NULL;
-- Cascade lookups from a drop link.
CREATE INDEX verification_challenges_drop_link_idx ON verification_challenges (tenant_id, drop_link_id)
    WHERE drop_link_id IS NOT NULL;
