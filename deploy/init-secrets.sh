#!/bin/sh
# Creates the secret files of the TransTeira deployment, with random values.
#
#   sudo sh deploy/init-secrets.sh [--postgres] [directory]
#
# directory defaults to deploy/secrets (SECRETS_DIR in deploy/.env must match
# for the PostgreSQL files; MASTER_KEY_FILE for the master key). Existing files
# are never overwritten, and symbolic links are refused (the directory and the
# files alike). Run it as root so that each file gets the owner of the
# container that reads it:
#   master_key, db_dsn, db_migrate_dsn, pgpass      UID 10001 (TransTeira, db-backup)
#   pg_superuser_password, pg_owner_password,
#   pg_app_password, pg_backup_password             UID 70 (postgres)
#
# Afterwards, copy master_key into your password vault (outside the VM):
# without it, the files and the backups cannot be decrypted
# (docs/operations/master-key.md).
set -eu

postgres=no
dir=""
for arg in "$@"; do
	case "$arg" in
	--postgres) postgres=yes ;;
	-h | --help)
		sed -n '2,17p' "$0"
		exit 0
		;;
	-*)
		echo "init-secrets: unknown option $arg" >&2
		exit 2
		;;
	*) dir=$arg ;;
	esac
done
[ -n "$dir" ] || dir="$(dirname "$0")/secrets"

die() {
	echo "init-secrets: $*" >&2
	exit 1
}

umask 077
# Files are created with noclobber: a file that appears between the check and
# the write (or a dangling symbolic link) makes the script fail, never write
# through it.
set -C

[ -L "$dir" ] && die "$dir is a symbolic link: refused"
mkdir -p "$dir"
[ -L "$dir" ] && die "$dir is a symbolic link: refused"
[ -d "$dir" ] || die "$dir is not a directory"
if [ "$(id -u)" = 0 ]; then
	# Another owner could swap the files under us.
	[ "$(stat -c %u "$dir")" = 0 ] || die "$dir is not owned by root: refused (chown root $dir)"
fi
chmod 0700 "$dir"

# random_hex N prints 2N hexadecimal characters (safe in a URL, no escaping).
random_hex() {
	head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# write NAME UID CONTENT creates the file once, mode 0400, owned by UID when
# run as root.
write() {
	f="$dir/$1"
	[ -L "$f" ] && die "$f is a symbolic link: refused"
	if [ -e "$f" ]; then
		[ -f "$f" ] || die "$f is not a regular file"
		echo "kept     $f (already exists)"
		return
	fi
	printf '%s\n' "$3" >"$f" || die "cannot create $f"
	chmod 0400 "$f"
	if [ "$(id -u)" = 0 ]; then
		chown "$2:$2" "$f"
	else
		echo "warning: not root, $f is owned by $(id -u); run: chown $2:$2 $f" >&2
	fi
	echo "created  $f"
}

# The master key: 32 random bytes, standard base64.
write master_key 10001 "$(head -c 32 /dev/urandom | base64)"

if [ "$postgres" = yes ]; then
	write pg_superuser_password 70 "$(random_hex 24)"
	write pg_owner_password 70 "$(random_hex 24)"
	write pg_app_password 70 "$(random_hex 24)"
	write pg_backup_password 70 "$(random_hex 24)"
	# Read the passwords back from the files so that a rerun after a partial
	# run stays consistent.
	owner_pw=$(cat "$dir/pg_owner_password")
	app_pw=$(cat "$dir/pg_app_password")
	backup_pw=$(cat "$dir/pg_backup_password")
	write db_dsn 10001 "postgres://transteira_app:${app_pw}@postgres:5432/transteira?sslmode=disable"
	write db_migrate_dsn 10001 "postgres://transteira_owner:${owner_pw}@postgres:5432/transteira?sslmode=disable"
	# db-backup connects with the read-only backup role. libpq ignores a
	# password file readable by group or others: mode 0400.
	write pgpass 10001 "postgres:5432:transteira:transteira_backup:${backup_pw}"
fi

echo "Done. Store a copy of $dir/master_key in your password vault."
