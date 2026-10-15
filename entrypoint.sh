#!/bin/sh
set -eu

: "${COUCHDB_URL:?COUCHDB_URL is required}"
: "${COUCHDB_DB:?COUCHDB_DB is required}"
: "${COUCHDB_USER:?COUCHDB_USER is required}"
: "${COUCHDB_PASSWORD:?COUCHDB_PASSWORD is required}"

COUCH=${COUCHDB_URL%/}
DB=$COUCHDB_DB
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

db_status=$(curl --silent --output /dev/null --write-out '%{http_code}' --user "$AUTH" "$COUCH/$DB")
case "$db_status" in
  200)
    ;;
  404)
    curl --fail --silent --show-error --request PUT --user "$AUTH" "$COUCH/$DB" >/dev/null
    ;;
  *)
    echo "Unable to inspect CouchDB database: HTTP $db_status" >&2
    exit 1
    ;;
esac

upsert_design() {
  design=$1
  desired=$2
  url="$COUCH/$DB/_design/$design"
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

upsert_design "users" '{
  "_id": "_design/users",
  "views": {
    "by_email": {
      "map": "function(doc) { if (doc.type === \"user\" && doc.email) emit(doc.email, null); }"
    }
  }
}'

upsert_design "equipment" '{
  "_id": "_design/equipment",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"equipment\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "events" '{
  "_id": "_design/events",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"event\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "incidents" '{
  "_id": "_design/incidents",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"incident\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "team" '{
  "_id": "_design/team",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"member\") emit(doc._id, null); }"
    }
  }
}'

upsert_design "projects" '{
  "_id": "_design/projects",
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"project\") emit(doc._id, null); }"
    }
  }
}'

echo "CouchDB is ready; starting StageOps backend."
exec ./server
