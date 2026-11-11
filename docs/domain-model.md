# Modèle de données opérationnel

Documents CouchDB de la base `COUCHDB_DB`. Chaque document porte `type` et
`theatre_id`. L'API ne renvoie jamais `_id`/`_rev` : elle expose `id`.
Les dates « jour » sont au format `YYYY-MM-DD` ; les horodatages sont en RFC 3339 UTC.

## Projet (`type: "project"`)

| Champ | Description |
|---|---|
| `name`, `venue` | Obligatoires, espaces superflus retirés |
| `start_date`, `end_date` | Obligatoires, `end_date >= start_date` ; bornes inclusives des jours d'exploitation |
| `modules_config` | `{ "lighting", "audio", "stage" }` ; tous actifs si absent à la création |

Création, modification et suppression sont réservées au rôle `rg`.

## Matériel (`type: "equipment"`)

Route : `/api/projects/:projectId/equipment/:module` avec `module` ∈ `lighting`, `audio`, `stage`.

| Champ | Description |
|---|---|
| `id` | `equipment::<uuid>` généré par le serveur |
| `name` | Obligatoire, unique (insensible à la casse) dans le projet et le module |
| `kind` | `lighting` : `moving-head`, `fixed`, `laser`, `other` ; `audio` : `microphone`, `wireless`, `console`, `speaker`, `other` ; `stage` : `set`, `safety`, `rigging`, `other` |
| `status` | `ok` (défaut), `to-check`, `hs`, `repair` |
| `position` | `{x, y, z}` facultatif ; absente tant que le matériel n'est pas placé (à distinguer de « placé à l'origine »), conservée à la modification si absente |
| `available_from`, `available_to` | Facultatifs ; fenêtre de disponibilité incluse dans les dates du projet. À la modification, un champ absent est conservé et `""` l'efface |
| `dmx_universe`, `dmx_address`, `dmx_channels` | Module `lighting` uniquement ; adresse 1–512 ; chevauchement refusé (`409 DMX_CONFLICT`) |
| `created_at`, `updated_at` | Horodatage serveur |

`GET …/equipment/:module?date=YYYY-MM-DD` ne renvoie que le matériel visible ce
jour-là : la date est dans les dates du projet et dans la fenêtre de disponibilité
(une borne absente est ouverte). Hors des dates du projet, la liste est vide.

La fenêtre n'est validée contre les dates du projet que lorsqu'elle change : un
matériel dont la fenêtre est devenue invalide après une modification des dates du
projet reste modifiable.

## Incident (`type: "incident"`)

Route : `/api/projects/:projectId/incidents/:module` avec `module` ∈ `lighting`, `audio`.

| Champ | Description |
|---|---|
| `id` | `incident::<uuid>` généré par le serveur |
| `title`, `description` | Obligatoires (texte libre) |
| `severity` | `low`, `medium`, `high`, `critical` |
| `status` | `open` (défaut), `in-progress`, `resolved`, `closed` |
| `date` | Jour d'exploitation concerné, **obligatoire à la création** et compris dans les dates du projet ; conservé à la modification si absent |
| `equipment_id` | Facultatif ; doit désigner un matériel du même projet et du même module |
| `reported_by` | Identifiant de l'utilisateur authentifié |
| `resolved_at` | Renseigné automatiquement à `resolved`/`closed`, conservé aux modifications suivantes s'il est absent, effacé à la réouverture |
| `created_at`, `updated_at` | Horodatage serveur |

`GET …/incidents/:module?date=YYYY-MM-DD` renvoie les incidents de ce jour. Les
incidents créés avant l'ajout de `date` utilisent le jour UTC de `created_at`.

Le serveur ne devine pas le jour d'exploitation (fuseau du théâtre, représentation
qui dépasse minuit) : le client l'envoie toujours à la création. La date n'est
validée contre les dates du projet qu'à la création ou lorsqu'elle change ; un
incident dont le jour est hors des dates du projet reste modifiable et clôturable.

### Statut du matériel lié

Même règle que le workspace Web (`StageOps_Web/src/domain/workspace.ts`) :

- un incident actif (`open`, `in-progress`) fait passer le matériel `ok` à `to-check` ;
- quand le dernier incident actif est résolu, clos, supprimé ou détaché, le matériel `to-check` redevient `ok` ;
- un matériel `hs` ou `repair` n'est jamais modifié automatiquement.

La mise à jour du matériel est tracée dans l'audit (`MATERIAL_UPDATED`). Elle est
faite au mieux après l'enregistrement de l'incident : les incidents sont relus
après l'écriture, un conflit CouchDB sur le matériel est rejoué (3 tentatives),
et en cas d'échec l'erreur est journalisée et l'incident reste enregistré.
