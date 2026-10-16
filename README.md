# StageOps Backend

API REST de StageOps pour la gestion des projets scéniques, des équipes, du matériel et des incidents.

## Stack

- Go 1.27
- Fiber v2
- CouchDB via son API HTTP
- JWT HS256, grants Ed25519, bcrypt et SMTP/TLS
- Docker
- PouchDB côté client pour le mode offline-first (intégration frontend)

## Fonctionnalités disponibles

- inscription avec vérification email, connexion, sessions rotatives et révocation ;
- grants Ed25519 pour l'accès contrôlé à PouchDB hors réseau ;
- isolation des identités et données par théâtre ;
- rôles `rg`, `lumiere`, `son` et `plateau` ;
- attribution de plusieurs modules à un utilisateur ;
- projets avec modules `lighting`, `audio` et `stage` activables séparément ;
- inventaire matériel par projet et module ;
- positions 3D et adressage DMX avec détection de conflits ;
- incidents lumière et son rattachés à un projet ;
- journal d'audit des opérations sensibles.

## Architecture

```text
cmd/server/             démarrage et câblage HTTP
internal/auth/          authentification et autorisations
internal/projects/      cycle de vie des projets
internal/equipment/     matériel et patch DMX
internal/incidents/     suivi des incidents
internal/modules/       configuration par théâtre
internal/audit/         journal append-only
internal/couch/         client HTTP CouchDB partagé
```

Chaque domaine sépare les handlers HTTP, les services métier et les repositories CouchDB.

## Configuration

Copier l'exemple puis remplacer les valeurs locales :

```bash
cp .env.example .env
```

Variables requises :

| Variable | Description |
|---|---|
| `COUCHDB_URL` | URL de CouchDB, par exemple `http://localhost:5984` |
| `COUCHDB_DB` | Base des données opérationnelles |
| `COUCHDB_AUTH_DB` | Base séparée des identités et sessions |
| `COUCHDB_USER` | Utilisateur CouchDB |
| `COUCHDB_PASSWORD` | Mot de passe CouchDB |
| `JWT_SECRET` | Secret de signature JWT long et aléatoire |
| `USER_ID_SECRET` | Secret HMAC distinct pour les identifiants utilisateurs |
| `OFFLINE_SIGNING_KEY` | Graine Ed25519 de 32 octets encodée en base64 |
| `DEFAULT_THEATRE_ID` | Théâtre attribué aux comptes publics et au bootstrap |
| `SMTP_*` | Paramètres d'envoi des emails de vérification |
| `APP_PORT` | Port HTTP, `3000` par défaut |
| `CORS_ORIGINS` | Origines autorisées, séparées par des virgules |
| `TLS_CERT` | Chemin facultatif du certificat TLS |
| `TLS_KEY` | Chemin facultatif de la clé TLS |

Ne jamais committer le fichier `.env` ni des certificats.

## Démarrage

Avec l'infrastructure Docker locale déjà configurée :

```bash
docker compose -f docker-compose.dev.yml up --build
```

Sans Docker :

```bash
go mod download
go run ./cmd/server
```

Le script `entrypoint.sh` attend CouchDB, crée la base et applique les versions courantes des vues avant de lancer le serveur.

## Déploiement sur un VPS

Le déploiement de production fournit :

- CouchDB persistant sur un réseau Docker privé ;
- le backend exécuté par un utilisateur non-root ;
- Caddy comme reverse proxy avec HTTPS automatique ;
- des healthchecks distincts pour le processus et CouchDB ;
- une rotation des logs et des limites CPU/RAM ;
- un script de sauvegarde cohérente du volume CouchDB.

```bash
cp .env.production.example .env.production
# Remplacer les domaines et secrets, puis :
sh ./deploy/deploy.sh
```

La procédure complète se trouve dans [`docs/vps-deployment.md`](docs/vps-deployment.md). CouchDB n'est volontairement pas exposé publiquement : la réplication PouchDB devra utiliser une authentification dédiée et un scope par théâtre/projet, jamais le compte administrateur du backend.

Le choix Go Fiber + PouchDB/CouchDB est consigné dans [`docs/adr/0001-go-fiber-pouchdb-couchdb.md`](docs/adr/0001-go-fiber-pouchdb-couchdb.md).

## API principale

Toutes les routes protégées attendent `Authorization: Bearer <token>`.

| Méthode | Route | Accès |
|---|---|---|
| `POST` | `/api/auth/register` | public |
| `POST` | `/api/auth/login` | public |
| `POST` | `/api/auth/verify-email` | public |
| `POST` | `/api/auth/refresh` | refresh token |
| `POST` | `/api/auth/logout` | refresh token |
| `POST` | `/api/auth/logout-all` | authentifié |
| `GET` | `/api/auth/me` | authentifié |
| `GET, DELETE` | `/api/auth/devices[/:id]` | authentifié |
| `POST` | `/api/auth/offline-grants` | authentifié |
| `GET` | `/.well-known/jwks.json` | public |
| `PATCH` | `/api/users/:id/role` | RG |
| `PATCH` | `/api/users/:id/modules` | RG |
| `GET, POST` | `/api/projects/` | lecture authentifiée, création RG |
| `GET, PATCH, DELETE` | `/api/projects/:id` | lecture authentifiée, mutation RG |
| `GET, POST` | `/api/projects/:projectId/equipment/:module/` | module attribué |
| `GET, PATCH, DELETE` | `/api/projects/:projectId/equipment/:module/:id` | module attribué |
| `GET, POST` | `/api/projects/:projectId/incidents/:module/` | module attribué |
| `GET, PATCH, DELETE` | `/api/projects/:projectId/incidents/:module/:id` | module attribué |
| `GET` | `/api/health/live` | public, processus HTTP |
| `GET` | `/api/health/ready` | public, processus et CouchDB |

Les mutations de matériel et d'incidents sont bloquées quand le module correspondant est inactif dans le projet. Les erreurs suivent cette enveloppe :

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Description lisible de l'erreur."
  }
}
```

## Vérifications locales

```bash
gofmt -w .
go test ./...
go vet ./...
```

La CI exécute automatiquement le contrôle du formatage, les tests avec le détecteur de courses, `go vet`, `govulncheck` et un test d'intégration contre un vrai CouchDB.

Le flux complet est documenté dans [`docs/authentication.md`](docs/authentication.md), avec le mapping RNCP backend dans [`docs/rncp-block-2.md`](docs/rncp-block-2.md).

## Licence

Projet académique EIP.
