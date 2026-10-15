#!/bin/sh
set -eu

: "${COUCHDB_URL:?COUCHDB_URL is required}"
: "${COUCHDB_DB:?COUCHDB_DB is required}"
: "${COUCHDB_USER:?COUCHDB_USER is required}"
: "${COUCHDB_PASSWORD:?COUCHDB_PASSWORD is required}"

COUCH=${COUCHDB_URL%/}
DATA_DB=$COUCHDB_DB
AUTH_DB=${COUCHDB_AUTH_DB:-stageops_auth}
AUTH="${COUCHDB_USER}:${COUCHDB_PASSWORD}"
MAX_ATTEMPTS=${COUCHDB_STARTUP_ATTEMPTS:-60}

attempt=1
echo "Waiting for CouchDB..."
until curl --fail --silent --user "$AUTH" "$COUCH/_up" >/dev/null 2>&1; do
  if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
    echo "CouchDB did not become ready after $MAX_ATTEMPTS attempts." >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 2
done

ensure_db() {
  db=$1
  db_status=$(curl --silent --output /dev/null --write-out '%{http_code}' --user "$AUTH" "$COUCH/$db")
  case "$db_status" in
    200)
      ;;
    404)
      curl --fail --silent --show-error --request PUT --user "$AUTH" "$COUCH/$db" >/dev/null
      ;;
    *)
      echo "Unable to inspect CouchDB database $db: HTTP $db_status" >&2
      exit 1
      ;;
  esac
}

ensure_db "$DATA_DB"
ensure_db "$AUTH_DB"

upsert_design() {
  db=$1
  design=$2
  desired=$3
  url="$COUCH/$db/_design/$design"
  response=$(curl --silent --show-error --user "$AUTH" --write-out '\n%{http_code}' "$url")
  status=$(printf '%s\n' "$response" | tail -n 1)
  current=$(printf '%s\n' "$response" | sed '$d')

  case "$status" in
    200)
      current_without_rev=$(printf '%s' "$current" | jq -cS 'del(._rev)')
      normalized_desired=$(printf '%s' "$desired" | jq -cS .)
      if [ "$current_without_rev" = "$normalized_desired" ]; then
        return
      fi
      rev=$(printf '%s' "$current" | jq -r '._rev')
      payload=$(printf '%s' "$desired" | jq -c --arg rev "$rev" '. + {_rev: $rev}')
      ;;
    404)
      payload=$desired
      ;;
    *)
      echo "Unable to inspect design document $design: HTTP $status" >&2
      exit 1
      ;;
  esac

  curl --fail --silent --show-error --request PUT --user "$AUTH" \
    --header "Content-Type: application/json" --data "$payload" "$url" >/dev/null
}

upsert_design "$AUTH_DB" "users" '{
  "_id": "_design/users",
  "views": {
    "by_email": {
      "map": "function(doc) { if (doc.type === \"user\" && doc.email) emit(doc.email, null); }"
    },
    "by_role": {
      "map": "function(doc) { if (doc.type === \"user\" && doc.role) emit(doc.role, null); }"
    },
    "by_verification_hash": {
      "map": "function(doc) { if (doc.type === \"user\" && doc.verification_token_hash) emit(doc.verification_token_hash, null); }"
    }
  }
}'

upsert_design "$AUTH_DB" "sessions" '{
  "_id": "_design/sessions",
  "views": {
    "by_refresh_hash": {
      "map": "function(doc) { if (doc.type === \"session\") { if (doc.refresh_token_hash) emit(doc.refresh_token_hash, null); if (doc.previous_refresh_hash) emit(doc.previous_refresh_hash, null); } }"
    },
    "by_user": {
      "map": "function(doc) { if (doc.type === \"session\" && doc.user_id) emit(doc.user_id, null); }"
    }
  }
}'

upsert_design "$AUTH_DB" "devices" '{
  "_id": "_design/devices",
  "views": {
    "by_user": {
      "map": "function(doc) { if (doc.type === \"device\" && doc.user_id) emit(doc.user_id, null); }"
    }
  }
}'

upsert_design "$DATA_DB" "equipment" '{
  "_id": "_design/equipment",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"equipment\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "$DATA_DB" "events" '{
  "_id": "_design/events",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"event\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "$DATA_DB" "incidents" '{
  "_id": "_design/incidents",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"incident\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "$DATA_DB" "team" '{
  "_id": "_design/team",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"member\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "$DATA_DB" "projects" '{
  "_id": "_design/projects",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"project\") emit(doc._id, null); }"
    }
  }
}'

echo "CouchDB is ready; starting StageOps backend."
exec ./server
