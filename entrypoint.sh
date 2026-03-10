#!/bin/sh
set -e

COUCH="${COUCHDB_URL}"
DB="${COUCHDB_DB}"
AUTH="${COUCHDB_USER}:${COUCHDB_PASSWORD}"

echo "⏳ Attente de CouchDB..."
until curl -sf -u "${AUTH}" "${COUCH}/_up" > /dev/null 2>&1; do
  sleep 2
done
echo "✅ CouchDB est prêt."

# Créer la base de données si elle n'existe pas
HTTP=$(curl -s -o /dev/null -w "%{http_code}" -u "${AUTH}" "${COUCH}/${DB}")
if [ "$HTTP" = "404" ]; then
  echo "📦 Création de la base '${DB}'..."
  curl -sf -X PUT -u "${AUTH}" "${COUCH}/${DB}"
  echo "✅ Base '${DB}' créée."
else
  echo "✅ Base '${DB}' existe déjà."
fi

# Fonction pour créer un design document si absent
create_design() {
  DESIGN=$1
  BODY=$2
  HTTP=$(curl -s -o /dev/null -w "%{http_code}" -u "${AUTH}" "${COUCH}/${DB}/_design/${DESIGN}")
  if [ "$HTTP" = "404" ]; then
    echo "🔍 Création de _design/${DESIGN}..."
    curl -sf -X PUT -u "${AUTH}" "${COUCH}/${DB}/_design/${DESIGN}" \
      -H "Content-Type: application/json" \
      -d "${BODY}"
    echo "✅ _design/${DESIGN} créé."
  else
    echo "✅ _design/${DESIGN} existe déjà."
  fi
}

# Vue by_email pour l'auth
create_design "users" '{
  "views": {
    "by_email": {
      "map": "function(doc) { if (doc.type === \"user\" && doc.email) emit(doc.email, null); }"
    }
  }
}'

# Vue all pour l'équipement
create_design "equipment" '{
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"equipment\") emit(doc._id, null); }"
    }
  }
}'

# Vue all pour les événements
create_design "events" '{
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"event\") emit(doc._id, null); }"
    }
  }
}'

# Vue all pour les incidents
create_design "incidents" '{
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"incident\") emit(doc._id, null); }"
    }
  }
}'

# Vue all pour l'équipe
create_design "team" '{
  "views": {
    "all": {
      "map": "function(doc) { if (doc.type === \"member\") emit(doc._id, null); }"
    }
  }
}'

echo "🚀 Démarrage du serveur..."
exec ./server
