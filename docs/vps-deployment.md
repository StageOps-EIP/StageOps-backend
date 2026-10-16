# Déploiement VPS

Cette procédure déploie l'API Go Fiber derrière Caddy et conserve CouchDB sur un réseau Docker privé. Seuls les ports `80` et `443` sont publiés.

## Prérequis

- un VPS Linux avec au moins 2 vCPU, 2 Go de RAM et 20 Go de stockage ;
- Docker Engine et le plugin Docker Compose ;
- un domaine dont l'enregistrement A/AAAA pointe vers le VPS ;
- les ports TCP 22, 80 et 443 ouverts, ainsi que UDP 443 pour HTTP/3 ;
- un pare-feu qui refuse le port CouchDB 5984 depuis Internet.

## Installation

```bash
git clone <repository-url> /opt/stageops/backend
cd /opt/stageops/backend
cp .env.production.example .env.production
chmod 600 .env.production
```

Remplacer toutes les valeurs de `.env.production`. Générer les secrets avec :

```bash
openssl rand -base64 48
```

Générer séparément la graine Ed25519 utilisée pour les autorisations offline :

```bash
openssl rand -base64 32
```

`JWT_SECRET`, `USER_ID_SECRET`, `OFFLINE_SIGNING_KEY` et le mot de passe CouchDB doivent être distincts. Configurer également le serveur SMTP, l'URL HTTPS de vérification d'email et un identifiant stable dans `DEFAULT_THEATRE_ID`.

`BOOTSTRAP_ADMIN_EMAIL` et `BOOTSTRAP_ADMIN_PASSWORD` créent le premier régisseur général uniquement lorsqu'aucun compte `rg` n'existe. Après le premier déploiement réussi, retirer ces deux variables de `.env.production`, puis relancer le déploiement. L'inscription publique reste désactivée par défaut.

Déployer ensuite :

```bash
sh ./deploy/deploy.sh
```

Caddy demande et renouvelle automatiquement le certificat TLS lorsque `API_DOMAIN` pointe vers le VPS et que les ports 80/443 sont accessibles.

Cette configuration force TLS 1.3. Les identités, sessions, appareils, modules et données opérationnelles sont isolés par `theatre_id`. L'inscription publique affecte les nouveaux comptes au `DEFAULT_THEATRE_ID`; laisser cette inscription désactivée si l'instance ne doit accepter que des comptes administrés.

### Mise à niveau d'une base existante

Après la mise à jour du code et avant de remettre l'instance en service, affecter les anciens documents sans `theatre_id` au théâtre par défaut :

```bash
sh ./deploy/migrate-theatre.sh --confirm
```

Le script crée automatiquement une sauvegarde cohérente avant la migration. Vérifier `DEFAULT_THEATRE_ID` avant de confirmer : l'opération ne peut pas deviner le théâtre d'origine d'un document historique.

## Vérifications

```bash
docker compose --env-file .env.production -f docker-compose.prod.yml ps
curl --fail https://api.example.com/api/health/live
curl --fail https://api.example.com/api/health/ready
docker compose --env-file .env.production -f docker-compose.prod.yml logs --tail=200 backend
```

`live` vérifie le processus HTTP. `ready` vérifie également CouchDB. Le trafic ne doit être envoyé vers le backend que lorsque `ready` répond `200`.

## Sauvegarde

```bash
sh ./deploy/backup.sh
```

La sauvegarde arrête brièvement CouchDB et le backend afin d'obtenir un snapshot cohérent du volume. L'archive produite n'est pas chiffrée. La chiffrer avant de la copier vers un stockage extérieur au VPS, par exemple avec :

```bash
openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in backups/stageops-couchdb-YYYYMMDDTHHMMSSZ.tar.gz \
  -out backups/stageops-couchdb-YYYYMMDDTHHMMSSZ.tar.gz.enc
```

Une sauvegarde laissée uniquement sur le VPS ne protège pas d'une perte de machine. Configurer ensuite une exécution planifiée et une politique de rétention adaptées à l'exploitation.

Tester régulièrement une restauration sur un environnement séparé. Ne jamais restaurer directement en production sans sauvegarde préalable et fenêtre de maintenance.

La restauration valide d'abord l'archive dans un volume temporaire, conserve un volume de rollback pendant l'opération, puis remplace le volume CouchDB. Elle exige une confirmation explicite :

```bash
sh ./deploy/restore.sh /chemin/absolu/stageops-couchdb-YYYYMMDDTHHMMSSZ.tar.gz --confirm
```

## Mise à jour

```bash
git pull --ff-only
sh ./deploy/deploy.sh
```

Le volume `stageops_couchdb_data` est conservé entre les reconstructions du backend.

## PouchDB et synchronisation

CouchDB n'est volontairement pas publié par ce Compose. L'identifiant administrateur utilisé par le backend ne doit jamais être envoyé à une application web ou mobile.

Les clients peuvent vérifier un grant offline Ed25519 et ouvrir leur base PouchDB locale sans réseau. La clé publique est exposée par `/.well-known/jwks.json`. Cette autorisation locale ne constitue pas encore une passerelle de réplication CouchDB.

Avant d'activer la réplication PouchDB, ajouter un accès de synchronisation distinct avec :

- authentification propre aux clients ;
- isolation par théâtre/projet ;
- interdiction de répliquer les utilisateurs, rôles et entrées d'audit ;
- validation serveur des contraintes DMX et des mutations sensibles ;
- tests de conflits, reconnexion et idempotence.
