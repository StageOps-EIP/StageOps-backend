#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ "$2" != "--confirm" ]; then
  echo "Usage: $0 /absolute/path/to/stageops-couchdb-backup.tar.gz --confirm" >&2
  echo "This replaces the current CouchDB volume. Take a backup first." >&2
  exit 1
fi

ARCHIVE=$1
case "$ARCHIVE" in
  /*) ;;
  *)
    echo "The backup path must be absolute." >&2
    exit 1
    ;;
esac

if [ ! -f "$ARCHIVE" ]; then
  echo "Backup not found: $ARCHIVE" >&2
  exit 1
fi

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env.production"}
COMPOSE_FILE="$ROOT_DIR/docker-compose.prod.yml"
ARCHIVE_DIR=$(dirname -- "$ARCHIVE")
ARCHIVE_NAME=$(basename -- "$ARCHIVE")

restart_services() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" start couchdb backend >/dev/null 2>&1 || true
}
trap restart_services EXIT INT TERM

echo "Stopping the backend and CouchDB..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" stop backend couchdb

docker run --rm \
  -v stageops_couchdb_data:/data \
  alpine:3.22 \
  sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'

docker run --rm \
  -v stageops_couchdb_data:/data \
  -v "$ARCHIVE_DIR":/backup:ro \
  alpine:3.22 \
  tar -xzf "/backup/$ARCHIVE_NAME" -C /data

echo "Restore completed from $ARCHIVE"
