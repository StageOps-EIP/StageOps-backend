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
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT INT TERM

ensure_database() {
  db=$1
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' --user "$AUTH" "$COUCH/$db")

  case "$status" in
    200)
      ;;
    404)
      curl --fail --silent --show-error --request PUT --user "$AUTH" "$COUCH/$db" >/dev/null
      ;;
    *)
      echo "Unable to inspect CouchDB database $db: HTTP $status" >&2
      exit 1
      ;;
  esac
}

fetch_database() {
  db=$1
  destination=$2
  curl --fail --silent --show-error --user "$AUTH" \
    "$COUCH/$db/_all_docs?include_docs=true" >"$destination"
}

bulk_write() {
  db=$1
  docs_file=$2
  label=$3
  count=$(jq 'length' "$docs_file")

  if [ "$count" -eq 0 ]; then
    echo "$db: no $label to migrate."
    return
  fi

  payload_file="$TEMP_DIR/payload.json"
  jq '{docs: .}' "$docs_file" >"$payload_file"
  curl --fail --silent --show-error --user "$AUTH" \
    --request POST --header "Content-Type: application/json" \
    --data-binary "@$payload_file" "$COUCH/$db/_bulk_docs" \
    | jq -e 'all(.[]; has("ok"))' >/dev/null

  echo "$db: migrated $count $label."
}

copy_legacy_users() {
  source_file="$TEMP_DIR/data-before-users.json"
  destination_file="$TEMP_DIR/auth-before-users.json"
  docs_file="$TEMP_DIR/users-to-copy.json"

  fetch_database "$COUCHDB_DB" "$source_file"
  fetch_database "$AUTH_DB" "$destination_file"

  conflicts=$(jq -n \
    --slurpfile source "$source_file" \
    --slurpfile destination "$destination_file" '
      def normalized_email:
        (. // "" | tostring | ascii_downcase | gsub("^\\s+|\\s+$"; ""));
      ($destination[0].rows | map({key: .id, value: .doc}) | from_entries) as $existing
      | (
          reduce (
            $destination[0].rows[].doc
            | select((._deleted // false) == false and .type == "user")
          ) as $destination_user (
            {};
            ($destination_user.email | normalized_email) as $email
            | .[$email] = ((.[$email] // []) + [$destination_user._id])
          )
        ) as $ids_by_email
      | [
          $source[0].rows[].doc
          | select((._deleted // false) == false and .type == "user")
          | . as $source_user
          | select(
              (
                $existing[$source_user._id] != null
                and (
                  ($existing[$source_user._id].email | normalized_email) != ($source_user.email | normalized_email)
                  or $existing[$source_user._id].password_hash != $source_user.password_hash
                )
              )
              or (
                ($ids_by_email[($source_user.email | normalized_email)] // [])
                | map(select(. != $source_user._id))
                | length
              ) > 0
            )
        ]
      | length
    ')

  if [ "$conflicts" -ne 0 ]; then
    echo "Refusing migration: $conflicts legacy user documents conflict with the authentication database." >&2
    exit 1
  fi

  jq -n \
    --arg theatre "$DEFAULT_THEATRE_ID" \
    --slurpfile source "$source_file" \
    --slurpfile destination "$destination_file" '
      def normalized_email:
        (. // "" | tostring | ascii_downcase | gsub("^\\s+|\\s+$"; ""));
      ($destination[0].rows | map({key: .id, value: .doc}) | from_entries) as $existing
      | [
          $source[0].rows[].doc
          | select((._deleted // false) == false and .type == "user")
          | select($existing[._id] == null)
          | del(._rev)
          | .email = (.email | normalized_email)
          | .theatre_id = if (.theatre_id // "") == "" then $theatre else .theatre_id end
        ]
    ' >"$docs_file"

  bulk_write "$AUTH_DB" "$docs_file" "legacy user documents"
}

copy_legacy_modules() {
  source_file="$TEMP_DIR/data-before-modules.json"
  docs_file="$TEMP_DIR/modules-to-copy.json"

  fetch_database "$COUCHDB_DB" "$source_file"
  jq --arg theatre "$DEFAULT_THEATRE_ID" '
    (.rows | map({key: .id, value: .doc}) | from_entries) as $existing
    | [
        .rows[].doc
        | select((._deleted // false) == false and .type == "module")
        | select((.theatre_id // "") == "")
        | . as $legacy
        | ("module::" + $theatre + "::" + $legacy.name) as $new_id
        | ($existing[$new_id] // null) as $target
        | (
            $legacy
            | del(._rev)
            | ._id = $new_id
            | .theatre_id = $theatre
            | .updated_at = if ($legacy.updated_at // "") != "" then
                $legacy.updated_at
              elif ($target.updated_at // "") != "" then
                $target.updated_at
              else
                (now | todateiso8601)
              end
          ) as $desired
        | select($target == null or (($target | del(._rev)) != $desired))
        | if $target == null then $desired else $desired + {_rev: $target._rev} end
      ]
  ' "$source_file" >"$docs_file"

  bulk_write "$COUCHDB_DB" "$docs_file" "legacy module documents"
}

backfill_theatre() {
  db=$1
  types=$2
  source_file="$TEMP_DIR/$db-before-backfill.json"
  docs_file="$TEMP_DIR/$db-backfill.json"

  fetch_database "$db" "$source_file"
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

  bulk_write "$db" "$docs_file" "documents missing theatre_id"
}

# Users historically lived in the operational database. Copy them before the
# backend starts reading identities exclusively from the authentication DB.
ensure_database "$COUCHDB_DB"
ensure_database "$AUTH_DB"
copy_legacy_users
copy_legacy_modules
backfill_theatre "$AUTH_DB" '["user", "session", "device", "audit"]'
backfill_theatre "$COUCHDB_DB" '["project", "equipment", "incident", "event", "member", "audit"]'
