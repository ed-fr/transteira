-- 0024_admin_activation_delivery (SQLite): how an activation link of an
-- administrator was delivered and in which language (V1.2, feature F4).
-- Keep in sync with migrations/postgres/0024_admin_activation_delivery.sql.
-- See docs/architecture/data-model-v1.2.md, section 2.3.
--
-- delivery is 'copy' (the link is shown to the super admin, V1 behaviour,
-- hence the default for existing rows) or 'mail' (the link is mailed by the
-- system SMTP and never returned). language is the language of the mail
-- (NULL for a copied link). The link token itself is still stored as its
-- SHA-256 only.
ALTER TABLE admin_activations ADD COLUMN delivery TEXT NOT NULL DEFAULT 'copy'
    CHECK (delivery IN ('copy', 'mail'));
ALTER TABLE admin_activations ADD COLUMN language TEXT
    CHECK (language IS NULL OR length(language) BETWEEN 2 AND 16);
