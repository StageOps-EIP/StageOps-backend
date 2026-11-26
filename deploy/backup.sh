#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env.production"}
COMPOSE_FILE="$ROOT_DIR/docker-compose.prod.yml"
BACKUP_DIR=${BACKUP_DIR:-"$ROOT_DIR/backups"}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE="stageops-couchdb-$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"
archive_path="$BACKUP_DIR/$ARCHIVE"
temporary_archive=$(mktemp "$BACKUP_DIR/.$ARCHIVE.XXXXXX")

restart_services() {
  if [ "${RESTART_SERVICES:-true}" != "true" ]; then
    return
  fi

  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" start couchdb backend >/dev/null 2>&1 || true
}
cleanup() {
  rm -f -- "$temporary_archive"
  restart_services
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Stopping the backend and CouchDB for a consistent volume snapshot..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" stop backend couchdb

docker run --rm \
  -v stageops_couchdb_data:/data:ro \
  alpine:3.22 \
  tar -czf - -C /data . >"$temporary_archive"

mv -- "$temporary_archive" "$archive_path"
echo "Backup created (not encrypted): $archive_path"
