# ADR-0001 — Go Fiber et PouchDB/CouchDB

- Statut : accepté
- Date : 2026-10-15

## Contexte

Le benchmark backend StageOps (M4) a comparé les frameworks à charge égale : Go Fiber a obtenu le meilleur compromis latence et mémoire, sans échec ; la capacité maximale n'a pas été mesurée. PouchDB/CouchDB a été retenu pour le stockage local et la réplication offline-first ; le benchmark de synchronisation (M3) doit encore valider ce choix par des mesures.

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

## État d'implémentation

Constat du 15 octobre 2026 :

- CouchDB est la base serveur de l'API Go : conforme.
- Le frontend Web stocke son workspace en `localStorage` derrière un contrat de repository ; l'adaptateur PouchDB reste à écrire.
- L'application mobile utilise un prototype SQLite (`expo-sqlite`) avec une synchronisation maison vers `/sync/push` et `/sync/pull`, routes absentes de l'API ; elle doit migrer vers PouchDB.
- Aucune réplication PouchDB ↔ CouchDB n'est encore en place ; CouchDB reste donc privé, conformément à cette décision.

Le plan de mise en conformité est suivi dans le wiki : [Migration PouchDB / CouchDB](https://github.com/StageOps-EIP/StageOps/wiki/Migration-PouchDB-CouchDB).
