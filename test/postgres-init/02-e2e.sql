-- TransTeira end-to-end tests: dedicated database transteira_e2e (TEST-ONLY).
--
-- Same model as the production setup (docs/install/postgresql.md): the owner role owns the
-- database and the application schema "transteira" and runs the migrations; the app role only
-- gets CONNECT here, plus the DML the owner grants after each migration. Neither role is a
-- superuser nor BYPASSRLS (01-roles.sql), so row-level security applies to the server under
-- test exactly as in production.
--
-- The end-to-end global setup (test/e2e/support/postgres.ts) runs this file itself when the
-- database is missing (a cluster started before this file existed), then drops and recreates
-- the "transteira" schema at the start of every run.

CREATE DATABASE transteira_e2e OWNER transteira_owner;

\connect transteira_e2e

-- Remove the permissive PUBLIC defaults (TEMPORARY, CONNECT, CREATE on "public").
REVOKE ALL ON DATABASE transteira_e2e FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT CONNECT ON DATABASE transteira_e2e TO transteira_app;

CREATE SCHEMA transteira AUTHORIZATION transteira_owner;
