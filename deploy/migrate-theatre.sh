#!/bin/sh
set -eu

if [ "${1:-}" != "--confirm" ]; then
  echo "Usage: sh ./deploy/migrate-theatre.sh --confirm" >&2
  echo "This assigns every legacy StageOps document without theatre_id to DEFAULT_THEATRE_ID." >&2
  exit 1
fi

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE=${ENV_FILE:-"$ROOT_DIR/.env.production"}
COMPOSE_FILE="$ROOT_DIR/docker-compose.prod.yml"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing environment file: $ENV_FILE" >&2
  exit 1
fi

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet

echo "Building the migration image without replacing the running services..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" build --pull couchdb backend

echo "Creating a CouchDB backup before tenant migration..."
RESTART_SERVICES=false ENV_FILE="$ENV_FILE" sh "$ROOT_DIR/deploy/backup.sh"

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --wait couchdb
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" run --rm \
  --no-deps --entrypoint /app/migrate-theatre.sh backend --confirm

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --remove-orphans
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps
echo "Tenant migration completed."
