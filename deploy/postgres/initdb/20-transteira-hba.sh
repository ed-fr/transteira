#!/bin/sh
# Rejects the superuser "postgres" over TCP (docs/install/postgresql.md).
#
# Sourced once by the official postgres image, on the first start with an
# empty data volume, after 10-transteira-roles.sql. The image has written
# pg_hba.conf already (local: peer, host: scram-sha-256 for every role); the
# reject rules are put first, since the first matching line wins. The
# superuser keeps the local Unix socket with peer authentication:
#   docker exec -it -u postgres transteira-postgres psql
# TransTeira, migrate and db-backup connect over TCP with their own roles.
#
# The image sources this file (it is not executable) in its own shell, which
# runs with errexit: no `set` here, it would leak into the entrypoint.
hba="$PGDATA/pg_hba.conf"
{
	echo '# TransTeira: the superuser may only use the local socket (peer).'
	echo 'host all postgres all reject'
	echo 'host replication postgres all reject'
	cat "$hba"
} >"$hba.transteira"
mv "$hba.transteira" "$hba"
chmod 0600 "$hba"
echo "transteira init: pg_hba.conf rejects the postgres superuser over TCP"
