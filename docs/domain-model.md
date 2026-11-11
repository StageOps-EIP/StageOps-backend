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
| `position` | `{x, y, z}` ; `{0, 0, 0}` à la création si absente, conservée à la modification si absente |
| `available_from`, `available_to` | Facultatifs ; fenêtre de disponibilité incluse dans les dates du projet |
| `dmx_universe`, `dmx_address`, `dmx_channels` | Module `lighting` uniquement ; adresse 1–512 ; chevauchement refusé (`409 DMX_CONFLICT`) |
| `created_at`, `updated_at` | Horodatage serveur |

`GET …/equipment/:module?date=YYYY-MM-DD` ne renvoie que le matériel visible ce
jour-là : la date est dans les dates du projet et dans la fenêtre de disponibilité
(une borne absente est ouverte). Hors des dates du projet, la liste est vide.

## Incident (`type: "incident"`)

Route : `/api/projects/:projectId/incidents/:module` avec `module` ∈ `lighting`, `audio`.

| Champ | Description |
|---|---|
| `id` | `incident::<uuid>` généré par le serveur |
| `title`, `description` | Obligatoires (texte libre) |
| `severity` | `low`, `medium`, `high`, `critical` |
| `status` | `open` (défaut), `in-progress`, `resolved`, `closed` |
| `date` | Jour d'exploitation concerné, compris dans les dates du projet ; aujourd'hui (UTC) par défaut, conservé à la modification si absent |
| `equipment_id` | Facultatif ; doit désigner un matériel du même projet et du même module |
| `reported_by` | Identifiant de l'utilisateur authentifié |
| `resolved_at` | Renseigné automatiquement à `resolved`/`closed`, effacé à la réouverture |
| `created_at`, `updated_at` | Horodatage serveur |

`GET …/incidents/:module?date=YYYY-MM-DD` renvoie les incidents de ce jour. Les
incidents créés avant l'ajout de `date` utilisent le jour UTC de `created_at`.

### Statut du matériel lié

Même règle que le workspace Web (`StageOps_Web/src/domain/workspace.ts`) :

- un incident actif (`open`, `in-progress`) fait passer le matériel `ok` à `to-check` ;
- quand le dernier incident actif est résolu, clos, supprimé ou détaché, le matériel `to-check` redevient `ok` ;
- un matériel `hs` ou `repair` n'est jamais modifié automatiquement.

La mise à jour du matériel est tracée dans l'audit (`MATERIAL_UPDATED`). Elle est
faite au mieux après l'enregistrement de l'incident : en cas d'échec, l'erreur est
journalisée et l'incident reste enregistré.
