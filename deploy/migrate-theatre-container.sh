#!/bin/sh
set -eu

if [ "${1:-}" != "--confirm" ]; then
  echo "Usage: migrate-theatre.sh --confirm" >&2
  exit 1
fi

: "${COUCHDB_URL:?COUCHDB_URL is required}"
: "${COUCHDB_DB:?COUCHDB_DB is required}"
: "${COUCHDB_USER:?COUCHDB_USER is required}"
: "${COUCHDB_PASSWORD:?COUCHDB_PASSWORD is required}"
: "${DEFAULT_THEATRE_ID:?DEFAULT_THEATRE_ID is required}"

COUCH=${COUCHDB_URL%/}
AUTH_DB=${COUCHDB_AUTH_DB:-stageops_auth}
AUTH="${COUCHDB_USER}:${COUCHDB_PASSWORD}"

migrate_database() {
  db=$1
  types=$2
  source_file=$(mktemp)
  docs_file=$(mktemp)
  payload_file=$(mktemp)
  trap 'rm -f "$source_file" "$docs_file" "$payload_file"' EXIT INT TERM

  curl --fail --silent --show-error --user "$AUTH" \
    "$COUCH/$db/_all_docs?include_docs=true" >"$source_file"

  jq --arg theatre "$DEFAULT_THEATRE_ID" --argjson types "$types" '
    [
      .rows[].doc
      | select((._deleted // false) == false)
      | select((._id | startswith("_design/")) == false)
      | select((.theatre_id // "") == "")
      | select(.type as $type | $types | index($type))
      | . + {theatre_id: $theatre}
    ]
  ' "$source_file" >"$docs_file"

  count=$(jq 'length' "$docs_file")
  if [ "$count" -eq 0 ]; then
    echo "$db: no legacy documents to migrate."
    rm -f "$source_file" "$docs_file" "$payload_file"
    trap - EXIT INT TERM
    return
  fi

  jq '{docs: .}' "$docs_file" >"$payload_file"
  curl --fail --silent --show-error --user "$AUTH" \
    --request POST --header "Content-Type: application/json" \
    --data-binary "@$payload_file" "$COUCH/$db/_bulk_docs" \
    | jq -e 'all(.[]; has("ok"))' >/dev/null

  echo "$db: migrated $count documents to theatre $DEFAULT_THEATRE_ID."
  rm -f "$source_file" "$docs_file" "$payload_file"
  trap - EXIT INT TERM
}

migrate_database "$AUTH_DB" '["user", "session", "device", "audit"]'
migrate_database "$COUCHDB_DB" '["project", "equipment", "incident", "event", "member", "audit"]'
