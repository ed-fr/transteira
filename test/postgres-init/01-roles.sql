-- TransTeira test environment: application roles (TEST-ONLY credentials).
--
-- Two roles, neither a superuser nor BYPASSRLS, because PostgreSQL does not
-- apply row-level security to such roles: isolation tests run as one of them
-- would pass even with broken policies.
--
-- transteira_owner runs the migrations and owns every schema object. Table
-- owners also bypass RLS unless the table uses FORCE ROW LEVEL SECURITY, so
-- the application never connects as the owner. Ownership alone lets it GRANT
-- USAGE on its schemas and DML on its tables to transteira_app; no extra
-- privilege is needed for that.
--
-- transteira_app is what the application (and the tests) connect as: CONNECT
-- only, plus whatever the owner grants it. It cannot create or alter objects,
-- so it cannot drop or weaken the RLS policies it is subject to. It has no
-- TEMPORARY either: pg_temp comes first in search_path, so a temporary table
-- could shadow an application table.

CREATE ROLE transteira_owner
    LOGIN
    PASSWORD 'transteira_owner'
    NOSUPERUSER
    NOBYPASSRLS
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION;

CREATE ROLE transteira_app
    LOGIN
    PASSWORD 'transteira_app'
    NOSUPERUSER
    NOBYPASSRLS
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION;

-- Drop the defaults every role inherits through PUBLIC, so that each
-- privilege below is explicit. (CONNECT stays granted to PUBLIC by default;
-- it is granted explicitly too for clarity.)
REVOKE TEMPORARY ON DATABASE transteira_test FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- CREATE on the database lets the owner create one schema per test.
GRANT CONNECT, CREATE ON DATABASE transteira_test TO transteira_owner;
GRANT CONNECT ON DATABASE transteira_test TO transteira_app;

-- Only the owner may create objects in "public"; transteira_app gets nothing.
GRANT USAGE, CREATE ON SCHEMA public TO transteira_owner;
