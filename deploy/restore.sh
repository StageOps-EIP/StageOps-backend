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
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESTORE_VOLUME="stageops_couchdb_restore_$STAMP"
ROLLBACK_VOLUME="stageops_couchdb_rollback_$STAMP"
RESTORE_SUCCEEDED=false

echo "Validating backup archive..."
if ! archive_entries=$(docker run --rm \
  -v "$ARCHIVE_DIR":/backup:ro \
  alpine:3.22 \
  tar -tzf "/backup/$ARCHIVE_NAME"); then
  echo "Invalid or corrupted backup archive: $ARCHIVE" >&2
  exit 1
fi

while IFS= read -r entry; do
  case "$entry" in
    /* | ../* | */../* | */..)
      echo "Unsafe path in backup archive: $entry" >&2
      exit 1
      ;;
  esac
done <<EOF
$archive_entries
EOF

docker volume create "$RESTORE_VOLUME" >/dev/null
docker run --rm \
  -v "$RESTORE_VOLUME":/data \
  -v "$ARCHIVE_DIR":/backup:ro \
  alpine:3.22 \
  tar -xzf "/backup/$ARCHIVE_NAME" -C /data

restart_services() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" start couchdb backend >/dev/null 2>&1 || true
}

cleanup() {
  trap - EXIT INT TERM
  docker volume rm "$RESTORE_VOLUME" >/dev/null 2>&1 || true
  if [ "$RESTORE_SUCCEEDED" = "true" ]; then
    docker volume rm "$ROLLBACK_VOLUME" >/dev/null 2>&1 || true
  elif docker volume inspect "$ROLLBACK_VOLUME" >/dev/null 2>&1; then
    echo "Rollback volume retained for recovery: $ROLLBACK_VOLUME" >&2
  fi
  restart_services
}
trap cleanup EXIT INT TERM

echo "Stopping the backend and CouchDB..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" stop backend couchdb

docker volume create "$ROLLBACK_VOLUME" >/dev/null
docker run --rm \
  -v stageops_couchdb_data:/source:ro \
  -v "$ROLLBACK_VOLUME":/data \
  alpine:3.22 \
  sh -c 'cp -a /source/. /data/'

docker run --rm \
  -v stageops_couchdb_data:/data \
  alpine:3.22 \
  sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'

if ! docker run --rm \
  -v "$RESTORE_VOLUME":/source:ro \
  -v stageops_couchdb_data:/data \
  alpine:3.22 \
  sh -c 'cp -a /source/. /data/'; then
  echo "Restore copy failed; restoring the rollback snapshot." >&2
  docker run --rm \
    -v stageops_couchdb_data:/data \
    alpine:3.22 \
    sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +'
  docker run --rm \
    -v "$ROLLBACK_VOLUME":/source:ro \
    -v stageops_couchdb_data:/data \
    alpine:3.22 \
    sh -c 'cp -a /source/. /data/'
  exit 1
fi

RESTORE_SUCCEEDED=true
echo "Restore completed from $ARCHIVE"
