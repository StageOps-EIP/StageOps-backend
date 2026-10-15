#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env.production"}
COMPOSE_FILE="$ROOT_DIR/docker-compose.prod.yml"
BACKUP_DIR=${BACKUP_DIR:-"$ROOT_DIR/backups"}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ARCHIVE="stageops-couchdb-$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"

restart_services() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" start couchdb backend >/dev/null 2>&1 || true
}
trap restart_services EXIT INT TERM

echo "Stopping the backend and CouchDB for a consistent volume snapshot..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" stop backend couchdb

docker run --rm \
  -v stageops_couchdb_data:/data:ro \
  -v "$BACKUP_DIR":/backup \
  alpine:3.22 \
  tar -czf "/backup/$ARCHIVE" -C /data .

chmod 600 "$BACKUP_DIR/$ARCHIVE"
echo "Backup created (not encrypted): $BACKUP_DIR/$ARCHIVE"
