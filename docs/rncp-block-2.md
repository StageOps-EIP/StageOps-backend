# Mapping RNCP — Bloc 2

Éléments backend contribuant au bloc « Concevoir une architecture logicielle » :

| Compétence démontrée | Preuve dans le repository |
|---|---|
| Séparation des responsabilités | handlers → services → repositories dans `internal/` |
| Choix d'architecture documenté | `docs/adr/0001-go-fiber-pouchdb-couchdb.md` |
| Protection des identités | base `COUCHDB_AUTH_DB` distincte de `COUCHDB_DB` |
| Isolation multi-théâtres | claim et contexte `theatre_id`, vues CouchDB filtrées, contrôles lecture/écriture |
| Gestion du cycle d'authentification | access tokens courts, refresh rotatifs, révocation, vérification email |
| Continuité offline-first | grants Ed25519 vérifiables localement et JWKS public |
| Sécurité en production | Caddy TLS 1.3, secrets hors image, réseaux Docker privés, conteneurs non-root |
| Qualité et preuve | tests unitaires, tests de concurrence sur CouchDB réel, race detector, `go vet`, `govulncheck` |
| Exploitabilité | healthchecks, sauvegarde/restauration, migration tenant et documentation VPS |

Cette page peut être reprise dans le Wiki GitHub du projet. La mise à jour du Wiki lui-même appartient au repository Wiki et n'est pas réalisée depuis le backend.
