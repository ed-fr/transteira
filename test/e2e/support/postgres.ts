// Reset of the PostgreSQL database of the end-to-end tests (transteira_e2e), through psql in
// the test container, as its superuser: no PostgreSQL driver is needed on the Node side.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { COMPOSE_FILE, PG, REPO_ROOT } from './env';

const INIT_SCRIPT = path.join(REPO_ROOT, 'test', 'postgres-init', '02-e2e.sql');

function psql(database: string, sql: string): string {
  return execFileSync(
    'docker',
    [
      'compose',
      '-f',
      COMPOSE_FILE,
      'exec',
      '-T',
      'postgres',
      'psql',
      '-X',
      '-q',
      '-t',
      '-A',
      '-v',
      'ON_ERROR_STOP=1',
      '-U',
      PG.superuser,
      '-d',
      database,
    ],
    { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
  ).trim();
}

/**
 * Empties transteira_e2e: creates the database when the running cluster predates
 * test/postgres-init/02-e2e.sql, then drops and recreates the application schema so that the
 * server migrates a blank schema. The server must not be running.
 */
export function resetE2EDatabase(): void {
  const exists = psql('postgres', `SELECT 1 FROM pg_database WHERE datname = '${PG.database}';`);
  if (exists !== '1') psql('postgres', fs.readFileSync(INIT_SCRIPT, 'utf8'));
  psql(
    PG.database,
    [
      // Connections left by a crashed earlier run would block DROP SCHEMA.
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${PG.database}' AND pid <> pg_backend_pid();`,
      `DROP SCHEMA IF EXISTS ${PG.schema} CASCADE;`,
      `CREATE SCHEMA ${PG.schema} AUTHORIZATION transteira_owner;`,
    ].join('\n'),
  );
}
