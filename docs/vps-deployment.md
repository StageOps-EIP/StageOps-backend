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

Le secret JWT et le mot de passe CouchDB doivent être différents.

Déployer ensuite :

```bash
sh ./deploy/deploy.sh
```

Caddy demande et renouvelle automatiquement le certificat TLS lorsque `API_DOMAIN` pointe vers le VPS et que les ports 80/443 sont accessibles.

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

La sauvegarde arrête brièvement CouchDB et le backend afin d'obtenir un snapshot cohérent du volume. Copier ensuite l'archive chiffrée vers un stockage extérieur au VPS. Une sauvegarde laissée uniquement sur le VPS ne protège pas d'une perte de machine.

Tester régulièrement une restauration sur un environnement séparé. Ne jamais restaurer directement en production sans sauvegarde préalable et fenêtre de maintenance.

La restauration remplace entièrement le volume CouchDB et exige une confirmation explicite :

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

Avant d'activer la réplication PouchDB, ajouter un accès de synchronisation distinct avec :

- authentification propre aux clients ;
- isolation par théâtre/projet ;
- interdiction de répliquer les utilisateurs, rôles et entrées d'audit ;
- validation serveur des contraintes DMX et des mutations sensibles ;
- tests de conflits, reconnexion et idempotence.
