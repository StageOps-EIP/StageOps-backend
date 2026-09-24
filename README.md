# StageOps Backend

API REST de StageOps pour la gestion des projets scéniques, des équipes, du matériel et des incidents.

## Stack

- Go 1.21
- Fiber v2
- CouchDB via son API HTTP
- JWT HS256 et bcrypt
- Docker

## Fonctionnalités disponibles

- inscription, connexion, verrouillage après échecs répétés et endpoint utilisateur courant ;
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
internal/modules/       configuration globale historique
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
| `COUCHDB_DB` | Nom de la base |
| `COUCHDB_USER` | Utilisateur CouchDB |
| `COUCHDB_PASSWORD` | Mot de passe CouchDB |
| `JWT_SECRET` | Secret de signature JWT long et aléatoire |
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

Le script `entrypoint.sh` attend CouchDB, crée la base et initialise les vues nécessaires avant de lancer le serveur.

## API principale

Toutes les routes protégées attendent `Authorization: Bearer <token>`.

| Méthode | Route | Accès |
|---|---|---|
| `POST` | `/api/auth/register` | public |
| `POST` | `/api/auth/login` | public |
| `GET` | `/api/auth/me` | authentifié |
| `PATCH` | `/api/users/:id/role` | RG |
| `PATCH` | `/api/users/:id/modules` | RG |
| `GET, POST` | `/api/projects/` | lecture authentifiée, création RG |
| `GET, PATCH, DELETE` | `/api/projects/:id` | lecture authentifiée, mutation RG |
| `GET, POST` | `/api/projects/:projectId/equipment/:module/` | module attribué |
| `GET, PATCH, DELETE` | `/api/projects/:projectId/equipment/:module/:id` | module attribué |
| `GET, POST` | `/api/projects/:projectId/incidents/:module/` | module attribué |
| `GET, PATCH, DELETE` | `/api/projects/:projectId/incidents/:module/:id` | module attribué |

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

La CI exécute automatiquement le contrôle du formatage, les tests avec le détecteur de courses et `go vet` sur les branches et pull requests.

## Licence

Projet académique EIP.
