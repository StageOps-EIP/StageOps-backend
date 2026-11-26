# ADR-0002 — Contrat de synchronisation du matériel et des incidents

- Statut : proposé
- Portée : premier parcours hors ligne Web et mobile
- Décision de référence : [ADR-0001](0001-go-fiber-pouchdb-couchdb.md)

## Périmètre du premier parcours

Le premier parcours permet de consulter le matériel d’un projet et de signaler,
modifier ou résoudre un incident pendant une coupure. Seuls les incidents
lumière et son sont modifiables hors ligne dans ce premier lot. Le patch DMX
et les modifications du parc continuent de passer par les routes REST. Ce
périmètre permet de tester les règles liant incidents et états du matériel avant
d’ouvrir davantage d’écritures.

Les clients répliquent dans PouchDB le registre opérationnel mis à disposition
par le backend. Pour une écriture hors ligne, ils conservent une opération
locale et la soumettent à l’API Go au retour du réseau. L’API applique les
validations existantes, écrit dans CouchDB et répercute le résultat vers le
registre répliqué. L’opération reçoit un résultat après validation côté serveur.
Une saisie en attente conserve cet état dans le client tant que le serveur ne
l’a pas acceptée.

## Format partagé

- Le document porte `schema_version: 1`, `type`, `_id`, `project_id` et
  `module`. Le format des identifiants est `equipment::<uuid>` ou
  `incident::<uuid>`, identique à l’`id` REST. Le client génère l’identifiant
  d’un incident créé hors ligne. Le serveur valide le format et le rattachement
  au périmètre authentifié avant de l’accepter.
- L’API reste propriétaire des horodatages d’écriture et de l’identité du
  déclarant. Les horodatages partagés utilisent RFC 3339 UTC. Le `date` d’un
  incident est le jour d’exploitation choisi par le technicien, en
  `YYYY-MM-DD`. Le serveur le valide dans la plage du projet.
- Les valeurs communes sont celles du [modèle opérationnel](../domain-model.md).
  Le matériel contient son nom, son type, son état et sa fenêtre de disponibilité.
  L’incident contient son titre, sa description, sa gravité, son état, son
  jour d’exploitation et éventuellement son `equipment_id`. Le lien vise un
  équipement du même projet et module.
- La révision CouchDB `_rev` représente la copie répliquée. Le jeton opaque de
  version métier utilisé lors d’une modification provient du document répliqué
  et permet au serveur de détecter une mise à jour faite depuis sa lecture.
- Les utilisateurs, sessions, appareils, autorisations, journaux d’audit et
  champs DMX restent dans le périmètre REST.

| Écart client | Traitement proposé |
|---|---|
| Mobile, états matériel en majuscules | `OK → ok`, `A_VERIFIER → to-check`, `HS → hs`, `EN_REPARATION → repair`. |
| Mobile, états et gravités des incidents | `OPEN → open`, `IN_PROGRESS → in-progress`, `RESOLVED → resolved`. `FAIBLE → low`, `MOYENNE → medium`, `ELEVEE → high`. Ajouter les valeurs `closed` et `critical` au modèle cible sans les rabattre sur une autre valeur. |
| Web et mobile, catégories métier | Garder la catégorie de présentation distincte de `module` et `kind`. Le rattachement d’une catégorie ambiguë, notamment vidéo, est à valider lors de l’import. |
| Mobile, anciennes dates SQLite | Convertir les horodatages techniques ISO UTC. Demander le projet, le module et le jour d’exploitation à l’import des fiches dépourvues de ces informations. |
| Mobile, anciennes routes `/sync/push` et `/sync/pull` | Le parcours PouchDB nécessite un adaptateur mobile. Les événements SQLite déjà enregistrés nécessitent un choix de reprise avant la transition. |

## Autorisations et cohérence

- Le backend vérifie la session, le théâtre, le projet et l’accès au module
  pour toute demande, y compris la lecture des mises à jour. Une partition
  répliquée ne peut contenir que des documents ayant les mêmes droits de
  lecture. Prévoir une partition par projet et module, ou démontrer un filtrage
  équivalent avant une partition plus large.
- L’autorisation hors ligne permet d’ouvrir la copie locale. La reconnexion
  exige une session serveur valide. Lorsque les droits sont retirés, le client
  purge les partitions concernées à la prochaine connexion. Hors réseau,
  l’accès local est borné par l’expiration de l’autorisation.
- Chaque opération porte un identifiant stable, réutilisé après un délai réseau
  ou une coupure. Une opération acceptée et rejouée renvoie le même résultat.
  Le backend doit conserver ce résultat durablement ou pouvoir le reconstruire
  après une réponse perdue. La création utilise l’identifiant définitif du
  document pour éviter les doublons.
- Si la version métier a changé depuis la lecture, le client reçoit un conflit
  explicite. La première version présente les deux états au technicien et garde
  sa modification locale jusqu’à décision. Les transitions d’incident et les
  changements d’état du matériel sont arbitrés par les services Go.
- La publication vers les partitions répliquées doit pouvoir reprendre après
  une interruption. Elle propage aussi les suppressions. Un rejeu ne doit
  ni ressusciter une fiche supprimée ni republier une version ancienne.

## Vérifications avant exposition aux clients

1. Comparer les exemples d’inventaire et d’incident des trois dépôts, puis
   valider les champs et valeurs communes dans les tests de contrat.
2. Tester la reprise après écriture acceptée mais réponse perdue, et après
   écriture métier validée mais publication interrompue.
3. Modifier le même incident sur deux appareils hors ligne. Après reconnexion,
   vérifier que la seconde écriture voit un conflit, puis que la résolution
   retenue converge sur les deux appareils.
4. Tester la révocation d’un appareil et les demandes hors théâtre, hors projet
   et hors module. Vérifier que les suppressions sont propagées et que les
   documents réservés au serveur ne sont jamais retournés.
5. Vérifier l’adaptateur PouchDB sur un appareil Expo réel avant de remplacer
   le prototype SQLite.
