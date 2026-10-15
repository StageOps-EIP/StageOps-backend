# ADR-0001 — Go Fiber et PouchDB/CouchDB

- Statut : accepté
- Date : 2026-10-15

## Contexte

Les benchmarks StageOps ont comparé les frameworks backend et les solutions de synchronisation offline-first. Go Fiber a obtenu le meilleur compromis débit, latence et mémoire. PouchDB/CouchDB a été retenu pour le stockage local et la réplication offline-first.

## Décision

- Go Fiber porte les routes HTTP, les règles métier, les autorisations et l'audit.
- CouchDB est la base serveur persistante.
- PouchDB est la base locale des applications web/mobile.
- Supabase n'est pas une dépendance de l'architecture principale.
- CouchDB reste privé sur le VPS tant qu'un accès de réplication distinct, authentifié et isolé par théâtre/projet n'est pas implémenté.

## Conséquences

- Les documents synchronisables doivent être séparés des secrets, utilisateurs et entrées d'audit.
- Les contraintes sensibles, notamment les permissions et conflits DMX, restent validées par Go.
- La réplication doit être testée sur les scénarios hors ligne, reconnexion, concurrence, retry et idempotence.
- Le déploiement doit sauvegarder le volume CouchDB et tester régulièrement sa restauration.
