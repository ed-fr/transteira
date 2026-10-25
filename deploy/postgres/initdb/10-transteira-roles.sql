-- Creates the TransTeira database and its three roles (docs/install/postgresql.md).
--
-- Run once by the official postgres image (psql, as POSTGRES_USER), on the
-- first start with an empty data volume (/docker-entrypoint-initdb.d). The
-- passwords are read from Docker secret files, never written here or passed
-- through the environment:
--   /run/secrets/pg_owner_password   owner role, applies the migrations
--   /run/secrets/pg_app_password     runtime role used by the application
--   /run/secrets/pg_backup_password  read-only role of the db-backup container
--
-- transteira_owner owns the database and the application schema.
-- transteira_app gets CONNECT only; the owner grants it USAGE and DML after
-- each migration. None of the three is superuser nor BYPASSRLS, so row-level
-- security applies to all of them. transteira_app has no TEMPORARY (a
-- temporary table could shadow an application table) and no CREATE anywhere.
-- Never grant transteira_owner to transteira_app.
--
-- transteira_backup (pg_dump in db-backup) gets CONNECT, USAGE on the schema
-- and SELECT only, through default privileges: every table and sequence the
-- owner creates in a migration is readable by it, without any grant in the
-- application. It has no TEMPORARY and no CREATE either. The dump sets
-- app.system_scope=on, which the row-level security policies honour for any
-- role, so it still holds the rows of every tenant.

\set ON_ERROR_STOP on
-- Backquotes run the command; its trailing newline is removed.
\set owner_pw `cat /run/secrets/pg_owner_password`
\set app_pw `cat /run/secrets/pg_app_password`
\set backup_pw `cat /run/secrets/pg_backup_password`

SELECT (:'owner_pw' <> '' AND :'app_pw' <> '' AND :'backup_pw' <> ''
        AND :'owner_pw' <> :'app_pw' AND :'owner_pw' <> :'backup_pw'
        AND :'app_pw' <> :'backup_pw') AS secrets_ok \gset
\if :secrets_ok
\else
DO $$ BEGIN
  RAISE EXCEPTION 'transteira init: the pg_owner_password, pg_app_password and pg_backup_password secrets must be non-empty and different';
END $$;
\endif

-- :'var' is quoted by psql itself, so a password never breaks out of its literal.
CREATE ROLE transteira_owner LOGIN PASSWORD :'owner_pw'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE transteira_app LOGIN PASSWORD :'app_pw'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE transteira_backup LOGIN PASSWORD :'backup_pw'
  NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
\unset owner_pw
\unset app_pw
\unset backup_pw

CREATE DATABASE transteira OWNER transteira_owner;
\connect transteira

-- Remove the permissive PUBLIC defaults: every privilege below is explicit.
REVOKE ALL ON DATABASE transteira FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA transteira AUTHORIZATION transteira_owner;
GRANT CONNECT ON DATABASE transteira TO transteira_app;
GRANT CONNECT ON DATABASE transteira TO transteira_backup;

-- Read-only access of the backup role to the tables and sequences that the
-- migrations (run as transteira_owner) will create.
GRANT USAGE ON SCHEMA transteira TO transteira_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE transteira_owner IN SCHEMA transteira
  GRANT SELECT ON TABLES TO transteira_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE transteira_owner IN SCHEMA transteira
  GRANT SELECT ON SEQUENCES TO transteira_backup;

-- The owner and runtime roles work in the application schema.
ALTER ROLE transteira_owner IN DATABASE transteira SET search_path = transteira;
ALTER ROLE transteira_app IN DATABASE transteira SET search_path = transteira;
