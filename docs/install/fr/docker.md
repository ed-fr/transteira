# Installer TransTeira avec Docker

> Version anglaise de référence : [../docker.md](../docker.md). En cas de différence, la version anglaise fait foi.

Ce guide installe TransTeira sur une VM exécutant Docker, derrière un reverse proxy
partagé avec d’autres services (CLAUDE.md section 18). Il utilise les fichiers compose
de production de [`deploy/`](../../../deploy/README.md), avec SQLite par défaut ;
la [variante PostgreSQL](#variante-postgresql) est décrite à la fin.

Les noms d’exemple sont fictifs : `admin.transfer.example.com` est l’hôte
d’administration, `transfer.entity-a.example.com` et
`transfer.entity-b.example.com` sont deux entités. Remplacez-les par les vôtres.

```
Internet ──► reverse proxy (own compose, ports 80/443) ──► network "proxy" ──► transteira:8080
                                                                                  │ network "internal"
                                                                               clamav (clamd)
```

Sommaire :

1. [Prérequis](#1-prérequis)
2. [DNS](#2-dns)
3. [Le réseau `proxy`](#3-le-réseau-proxy)
4. [Reverse proxy](#4-reverse-proxy)
5. [Image](#5-image)
6. [Secrets et clé maître](#6-secrets-et-clé-maître)
7. [Configuration (`.env`)](#7-configuration-env)
8. [Démarrage](#8-démarrage)
9. [Premier lancement : le super administrateur](#9-premier-lancement--le-super-administrateur)
10. [Entités](#10-entités)
11. [Contrôles et supervision](#11-contrôles-et-supervision)
12. [Journal de sécurité, fail2ban et CrowdSec](#12-journal-de-sécurité-fail2ban-et-crowdsec)
13. [Sauvegardes](#13-sauvegardes)

## 1. Prérequis

- **Docker Engine 25 ou plus récent** (les health checks utilisent `start_interval`)
  avec le **plugin Compose v2 en version 2.24 ou plus récente** (`docker compose`, et non l’ancien
  `docker-compose` ; la version 2.24 est nécessaire pour `env_file` avec `required:`, et la
  commande `make deploy-smoke` du projet exige la version 2.24.4 pour `!override`). Vérifiez avec
  `docker version` et `docker compose version`. Les commandes ci-dessous s’exécutent sur
  l’hôte Docker, en root (ou avec `sudo`), depuis un clone du dépôt :

  ```sh
  git clone https://github.com/ed-fr/transteira.git /opt/transteira
  cd /opt/transteira
  ```

- **Mémoire.** Le fichier compose fixe ces limites : TransTeira 1 Gio
  (tout est traité en flux, rien n’est conservé en mémoire), clamd **4 Gio** (environ
  1 à 1,5 Gio de signatures, plus son spool : clamd écrit chaque flux
  déchiffré, jusqu’à 2 Gio, dans un tmpfs en mémoire, pour que le texte en clair n’atteigne jamais
  un disque ; [Antivirus, le spool de clamd](../../operations/antivirus.md#the-clamd-spool)),
  freshclam 1,5 Gio (il charge à titre d’essai les nouvelles signatures avant de les installer).
  Cela fait 6,5 Gio au pire, plus 1,5 Gio avec PostgreSQL (serveur et conteneur
  de sauvegarde) : prévoyez une VM avec **au moins 8 Gio de RAM** (10 Gio avec
  PostgreSQL) et 2 processeurs ou plus.
- **Swap.** Faites tourner la VM **sans swap, ou avec un swap chiffré** : en cas de
  manque de mémoire, le noyau peut écrire les pages du spool de clamd (le
  texte en clair du fichier en cours d’analyse) sur le périphérique de swap.
- **Disque.** Tous les volumes Docker résident sous le répertoire de données de Docker
  (`/var/lib/docker` par défaut). Dimensionnez-le pour :
  - les fichiers chiffrés (`transteira_data`) : la somme des quotas des entités,
    plus les envois en cours, qui comptent jusqu’à ce qu’ils soient terminés ou
    expirent. Un transfert peut atteindre **20 Go**, et le chiffrement ajoute moins
    de 0,1 % ;
  - la base de données, ses copies nocturnes (`transteira_backups`), le journal de
    sécurité, les signatures ClamAV (environ 1 Gio) et les images.

  TransTeira alerte le super administrateur lorsque le disque qui contient les données atteint
  85 % (réglable dans l’administration). Le test de 20 Go du projet
  nécessite 60 à 80 Go d’espace libre ; une VM de production en demande généralement davantage.
- **Réseau.** Ports **80 et 443** accessibles par les utilisateurs (et depuis
  Internet si le proxy obtient ses certificats avec les challenges ACME HTTP-01 ou
  TLS-ALPN-01). TransTeira lui-même ne publie aucun port. Le conteneur `clamav-update`
  a besoin d’un accès HTTPS sortant vers `database.clamav.net`.

## 2. DNS

Créez un enregistrement DNS (A, et AAAA si vous servez en IPv6) pointant vers la VM pour :

- l’**hôte d’administration** (`admin.transfer.example.com`) : un nom
  dédié, jamais le FQDN d’une entité. Vous pouvez le restreindre à vos réseaux internes
  ou à un VPN au niveau du proxy ;
- **le FQDN de chaque entité** (`transfer.entity-a.example.com`, …). Vous pouvez ajouter
  des entités plus tard : chaque nouveau FQDN nécessite alors un enregistrement DNS et une entrée dans la
  configuration du proxy.

Chaque domaine d’envoi a aussi besoin d’enregistrements SPF, DKIM et DMARC : voir
[SMTP](smtp.md#spf-dkim-et-dmarc).

## 3. Le réseau `proxy`

Le reverse proxy et TransTeira partagent un réseau Docker externe nommé
`proxy`. Créez-le une fois par hôte, **avec un sous-réseau fixe**, pour que le proxy
puisse obtenir une adresse fixe à laquelle TransTeira fait confiance :

```sh
docker network create --subnet 172.30.0.0/24 proxy
```

`172.30.0.0/24` est un exemple : choisissez un sous-réseau qui ne chevauche ni votre réseau local
ni les plages d’adresses IP internes d’aucune entité. Pourquoi c’est important :
[le réseau `proxy` et `TT_TRUSTED_PROXIES`](../reverse-proxy.md#tt_trusted_proxies).

## 4. Reverse proxy

Choisissez un proxy et démarrez-le dans **son propre projet compose**, comme décrit dans
[Reverse proxy](../reverse-proxy.md). Caddy est la référence : il obtient les
certificats automatiquement et sa configuration est la plus courte.

Pour Caddy, copiez [`integrations/reverse-proxy/caddy/`](../../../integrations/reverse-proxy/caddy/README.md)
dans le dossier du proxy (par exemple `/opt/reverse-proxy`), renseignez l’adresse de contact
ACME et les noms d’hôte dans le `Caddyfile`, puis :

```sh
cd /opt/reverse-proxy
docker compose up -d
```

Les fichiers compose de proxy fournis donnent au proxy l’adresse fixe
`172.30.0.10` sur le réseau `proxy`. Si le proxy tourne déjà pour
d’autres services, ajoutez le bloc de site TransTeira à sa configuration et assurez-vous
qu’il a une adresse fixe sur le réseau `proxy`.

Les certificats ne peuvent être émis qu’une fois que les enregistrements DNS se résolvent ; tant que
TransTeira ne tourne pas, le proxy répond `502` pour ses noms.

## 5. Image

Construisez l’image depuis le dépôt (Docker avec BuildKit, le comportement par défaut) :

```sh
make docker
```

Cette commande construit `transteira:<version>` et `transteira:local`, la valeur par défaut de
`TRANSTEIRA_IMAGE` dans `deploy/.env`. Sans `make`, l’équivalent est :

```sh
docker build -t transteira:local .
```

(`make docker` inscrit aussi la version, le commit et la date dans le binaire.)
Une image publiée sur un registre viendra plus tard ; `TRANSTEIRA_IMAGE`
pointera alors vers elle, épinglée sur une version (jamais `latest`).

L’image est construite `FROM scratch` : le binaire statique, les certificats des autorités de certification et
les fichiers minimaux de l’utilisateur `transteira` (UID et GID **10001**), rien
d’autre (pas de shell). Elle n’écrit que dans ses volumes : `/data` (fichiers chiffrés),
`/var/lib/transteira/db` (SQLite), `/backups` (copies de la base) et `/logs`
(journal de sécurité).

## 6. Secrets et clé maître

La **clé maître** chiffre la clé de chaque fichier. Créez-la, avec le bon
propriétaire, à l’aide du script fourni :

```sh
sh deploy/init-secrets.sh
```

Il écrit `deploy/secrets/master_key` (32 octets aléatoires en base64, mode
`0400`, appartenant à l’UID 10001 pour que le conteneur puisse le lire), en dehors de tout
volume Docker, et n’écrase jamais un fichier existant. Avec PostgreSQL, ajoutez
`--postgres` (voir [Variante PostgreSQL](#variante-postgresql)).

> **Copiez dès maintenant la clé maître dans un coffre de mots de passe hors de la VM, avant
> le premier démarrage. C’est obligatoire.** Une sauvegarde de la VM ne contient pas la clé,
> à dessein : sans elle, les fichiers et les sauvegardes ne pourront jamais être déchiffrés.
> Notez son identifiant de clé à côté une fois TransTeira démarré. Détails,
> rotation et restauration : [Clé maître](../../operations/master-key.md).

```sh
cat deploy/secrets/master_key     # copy the value into the vault entry
```

Gardez le dossier `deploy/secrets/` lisible par root uniquement, et ne le commitez jamais
(il est ignoré par git).

## 7. Configuration (`.env`)

Copiez le modèle de déploiement et modifiez-le :

```sh
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
```

`deploy/.env` est lu deux fois : par Docker Compose (nom de l’image, réseau, chemins
des secrets) et par le conteneur TransTeira (ses variables `TT_*`). Il liste les
réglages utiles à un déploiement Docker ; chaque variable, avec sa
valeur par défaut et ses limites, est documentée dans le [`.env.example` racine](../../../.env.example).
Ne définissez pas `TT_DATA_DIR`, `TT_BACKUP_DIR`, `TT_LOG_DIR`, `TT_LISTEN_ADDR`,
`TT_CLAMAV_ADDR`, `TT_MASTER_KEY_FILE` ni `TT_DB_*` : les fichiers compose les fixent
pour qu’ils correspondent aux volumes, aux secrets et aux services.

Les variables essentielles :

| Variable | Valeur |
|---|---|
| `TT_ADMIN_HOSTS` | L’hôte d’administration, par exemple `admin.transfer.example.com` (obligatoire, jamais le FQDN d’une entité). |
| `TT_TRUSTED_PROXIES` | L’adresse **exacte** du proxy sur le réseau `proxy`, `172.30.0.10` avec les fichiers de proxy fournis. Vide, chaque client est vu comme le proxy et le filtrage IP des entités ne peut pas fonctionner. |
| `TT_SYSTEM_SMTP_HOST`, `TT_SYSTEM_SMTP_PORT`, `TT_SYSTEM_SMTP_SECURITY`, `TT_SYSTEM_SMTP_FROM` | Le serveur SMTP système, qui envoie l’alerte d’espace disque aux super administrateurs. Sans lui, l’alerte n’apparaît que dans l’administration et les journaux. Voir [SMTP](smtp.md#smtp-système-pour-les-alertes). |
| `TRANSTEIRA_IMAGE` | `transteira:local` après `make docker`, ou une image publiée épinglée. |
| `INTERNAL_SUBNET`, `DB_SUBNET`, `TT_SMTP_DENY_NETWORKS` | Sous-réseaux fixes des réseaux `internal` (clamd) et `db` (PostgreSQL), `172.31.10.0/24` et `172.31.11.0/24` par défaut, et les réseaux que le serveur SMTP d’une entité ne peut jamais atteindre : la liste par défaut plus ces deux sous-réseaux et le sous-réseau `proxy`. Changez les sous-réseaux s’ils chevauchent votre réseau local ou un autre réseau Docker, et la liste en même temps ([SMTP](smtp.md#relais-sans-authentification-sur-le-réseau-docker-interne)). |
| `TT_SCAN_WORKERS` | `1` : un seul fichier analysé à la fois, car le spool de clamd (en mémoire) contient un seul flux ([Antivirus](../../operations/antivirus.md#the-clamd-spool)). |
| `TT_SETUP_TOKEN` | Facultatif : le jeton d’initialisation du premier super administrateur (voir ci-dessous). |
| `TT_DEPOSIT_SESSION_TTL` | Facultatif, `4h` par défaut (de 15 min à 24 h) : durée de vie de la session d’un déposant à partir de la vérification de son adresse électronique, **non prolongée par l’activité**. Chaque requête d’envoi exige une session valide, donc un envoi encore en cours lorsqu’elle prend fin s’arrête avec « session expirée ». À 4 h, un transfert de 20 Go demande environ 11 Mbit/s de bande passante montante ; pour les liaisons lentes (sites distants, invités externes), augmentez-la, par exemple à `12h`. |

Les serveurs SMTP des entités ne se règlent pas ici : chaque entité a le sien,
configuré dans l’administration ([SMTP](smtp.md)).

## 8. Démarrage

```sh
docker compose -f deploy/docker-compose.yml up -d
```

Compose prend `deploy/` comme dossier du projet : il y lit donc `deploy/.env`
et les chemins relatifs des secrets, quel que soit le dossier courant.

À chaque démarrage, clamd a besoin d’une à deux minutes pour charger ses signatures ;
TransTeira démarre une fois clamd en bonne santé, et applique les migrations de la base
automatiquement. Suivez le démarrage :

```sh
docker compose -f deploy/docker-compose.yml ps
docker compose -f deploy/docker-compose.yml logs -f transteira
```

`ps` doit afficher `transteira` et `clamav` à l’état `healthy`, et `clamav-update`
en cours d’exécution (`clamav-init` se termine une fois qu’il a défini les propriétaires des volumes). Si
TransTeira refuse de démarrer, son journal nomme la variable ou le fichier en cause
(par exemple un fichier de clé maître au mauvais format ou situé dans un volume).

Le fichier compose durcit chaque conteneur : utilisateurs non root, systèmes de fichiers
racine en lecture seule, aucune capability, `no-new-privileges`, limites de mémoire et de processus.
La seule exception est le conteneur ponctuel `clamav-init`, qui s’exécute en
root, sans aucun réseau, avec uniquement les capabilities `CHOWN` et `DAC_READ_SEARCH`,
pour attribuer le volume des signatures à l’utilisateur `clamav`, puis
se termine. clamd n’a pas accès à Internet ; les mises à jour des signatures s’exécutent dans le conteneur
séparé `clamav-update` ([Antivirus](../../operations/antivirus.md#signatures)).

### Désactiver l’antivirus (facultatif)

Pour fonctionner sans ClamAV, ajoutez en dernier la surcharge `docker-compose.no-antivirus.yml` :

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.no-antivirus.yml up -d
```

(avec PostgreSQL : `-f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml -f deploy/docker-compose.no-antivirus.yml`).
Elle fixe `TT_ANTIVIRUS_ENGINE=none` et ne démarre pas les conteneurs ClamAV. Chaque fichier est alors
remis sans analyse et signalé, `/healthz` ne vérifie plus l’antivirus, et un avertissement (WARN) est écrit
au démarrage. **Avertissement de sécurité** : l’instance peut alors distribuer des logiciels malveillants
(modèle de menaces T-236) ; ne le faites que par un choix explicite. Conséquences et interrupteur par entité :
[Antivirus](../../operations/antivirus.md#disabling-the-antivirus).

### Un autre moteur antivirus (facultatif)

À la place de ClamAV, l’analyse peut être confiée à un serveur ICAP (`TT_ANTIVIRUS_ENGINE=icap`) ou à
une API HTTP générique (`TT_ANTIVIRUS_ENGINE=http`). Variables, règles de verdict, déploiement avec un
moteur distant, avertissements (le clair de chaque fichier quitte la VM ; le clair seulement sur un
réseau interne de confiance) et auto-test EICAR au démarrage : [Antivirus](../../operations/antivirus.md#choosing-the-engine)
(page en anglais).

## 9. Premier lancement : le super administrateur

Tant qu’aucun administrateur n’existe, TransTeira écrit un **jeton d’initialisation** dans son
journal, une fois par démarrage, au niveau `WARN` :

```sh
docker compose -f deploy/docker-compose.yml logs transteira | grep "Setup token"
```

La ligne est `No admin exists yet. Setup token: stp_… (valid until
restart). Open https://admin.transfer.example.com/admin/setup`. Un nouveau jeton
est généré à chaque redémarrage. Pour choisir vous-même le jeton, définissez
`TT_SETUP_TOKEN` (16 à 128 caractères) dans `deploy/.env` avant le démarrage,
ou `TT_SETUP_TOKEN_FILE` avec un secret Docker ; rien n’est alors écrit dans le journal.

Ensuite :

1. ouvrez `https://admin.transfer.example.com/admin/setup` ;
2. saisissez le jeton d’initialisation, un identifiant, une adresse électronique (elle reçoit les alertes
   du super administrateur) et un mot de passe ;
3. scannez le QR code avec une application d’authentification et confirmez un code à 6 chiffres :
   **la double authentification TOTP est obligatoire pour le super administrateur**, et rien d’autre dans
   l’administration n’est utilisable avant sa confirmation (confirmez dans les
   5 minutes) ;
4. rangez les 8 codes de secours dans votre coffre de mots de passe : ils ne s’affichent qu’une fois.

Dès que le super administrateur existe, l’initialisation est fermée définitivement et plus aucun jeton
n’est écrit dans le journal. Détails : [Administration, initialisation au premier lancement](../../operations/admin.md#first-run-setup)
et le [guide du super administrateur](../../user/fr/super-admin.md#premier-lancement).

Retirez ensuite `TT_SETUP_TOKEN` de `deploy/.env` si vous l’aviez défini.

## 10. Entités

Créez les entités dans l’administration (**Entités**, super administrateur uniquement) :
nom, FQDN, langue par défaut, quota de stockage. Configurez ensuite, ou laissez leurs
administrateurs délégués configurer, l’habillage, les plages d’adresses IP et les domaines de messagerie internes,
les réglages SMTP et les modèles de mails.

Pour chaque entité :

1. son FQDN a un enregistrement DNS pointant vers la VM (section 2) ;
2. le FQDN est ajouté à la configuration du reverse proxy (et au
   certificat avec Nginx ou Apache), puis le proxy est rechargé, par
   exemple avec Caddy :

   ```sh
   docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```

3. ses réglages SMTP fonctionnent (bouton **Envoyer un mail de test**) et son domaine d’envoi dispose de SPF,
   DKIM et DMARC ([SMTP](smtp.md)).

Références : [Entités](../../operations/tenants.md) (chaque réglage et qui peut
le modifier), le [guide du super administrateur](../../user/fr/super-admin.md#entités)
et le [guide de l’administrateur délégué](../../user/fr/delegated-admin.md).

## 11. Contrôles et supervision

**Health check.** `/healthz` est servi sur chaque hôte qui atteint
TransTeira, l’hôte d’administration comme le FQDN de chaque entité, sans
authentification :

```sh
curl -s https://admin.transfer.example.com/healthz
```

```json
{"status":"ok","version":"1.0.0","maintenance":false,"checks":{"database":"ok","antivirus":"ok","storage":"ok"}}
```

Il répond **200** avec `"status":"ok"` lorsque la base de données, clamd et le volume
de données répondent tous, et **503** avec `"status":"degraded"` (et le composant
défaillant à `unavailable`) dans le cas contraire. Le mode maintenance ne change pas le
statut : il apparaît sous la forme `"maintenance":true`. La réponse ne contient jamais de détails
d’erreur (ils figurent dans le journal de l’application). Le `HEALTHCHECK` Docker de
l’image interroge le même endpoint depuis l’intérieur du conteneur.

**Uptime Kuma.** Ajoutez une sonde HTTP(s) sur
`https://admin.transfer.example.com/healthz` (ou sur le FQDN d’une entité, pour contrôler aussi
son DNS, son certificat et sa route dans le proxy) : tout statut autre que 200 est un
échec. En option, une sonde « HTTP(s) - Json Query » sur `$.status` égal à
`ok`, et une seconde sur `$.maintenance` pour être prévenu lorsque le mode
maintenance est actif. Un intervalle de contrôle d’une minute suffit largement : le résultat est mis en cache
pendant 3 secondes et l’endpoint est soumis à la limitation de débit comme n’importe quel autre chemin.

**Version.** Le health check indique la version ; le binaire l’affiche aussi :

```sh
docker exec transteira /transteira version
```

**IP du client.** Après le premier dépôt, vérifiez dans le journal d’audit de l’entité
(administration) que les adresses IP sont celles des clients, et non
`172.30.0.10` : sinon, `TT_TRUSTED_PROXIES` ou la transmission par le proxy est
incorrecte ([Reverse proxy](../reverse-proxy.md#tt_trusted_proxies)).

## 12. Journal de sécurité, fail2ban et CrowdSec

TransTeira écrit un journal de sécurité dédié (codes erronés, mauvais mots de passe
de transfert, échecs de connexion admin, jetons d’API invalides, FQDN inconnus, dépôts
refusés, limitation de débit) avec l’IP réelle du client, dans
`/var/lib/docker/volumes/transteira_logs/_data/security.log` sur l’hôte.

- Format et rotation (logrotate avec `create 0640 10001 10001`) :
  [Journal de sécurité](../../operations/security-log.md).
- Bannissement au niveau du pare-feu de l’hôte, sur la chaîne `DOCKER-USER` :
  [fail2ban](../../../integrations/fail2ban/README.md).
- Ou CrowdSec, avec le bouncer Caddy pour bloquer au niveau du proxy :
  [CrowdSec](../../../integrations/crowdsec/README.md).

Excluez vos propres réseaux des bannissements (voir « Never ban your own users » dans les deux
intégrations). Les noms d’hôte inconnus sont pour la plupart refusés par le proxy avant
d’atteindre TransTeira ([Reverse proxy](../reverse-proxy.md#unknown-host-names)).

## 13. Sauvegardes

- **La sauvegarde de la VM** (par exemple Veeam) capture les volumes Docker :
  fichiers chiffrés, base de données, copies de la base et journaux.
- **Une copie propre de la base de données** est écrite chaque nuit par TransTeira
  (SQLite, `VACUUM INTO` à `TT_BACKUP_TIME`, 02:30 UTC par défaut, 7 copies
  conservées) dans le volume `transteira_backups`, pour que la sauvegarde de la VM ne
  dépende jamais d’un fichier de base surpris au milieu d’une écriture. Avec
  PostgreSQL, le conteneur `db-backup` exécute `pg_dump` à la place.
- **La clé maître est sauvegardée séparément**, dans le coffre de mots de passe (section
  6) : elle n’est jamais dans la sauvegarde de la VM.

Faites une copie manuelle avant une mise à jour avec
`docker exec transteira /transteira backup`. Détails et procédure de
restauration : [Sauvegarde et restauration](../../operations/backup.md) ; mises à jour :
[Mise à jour](../../operations/upgrade.md).

## Variante PostgreSQL

SQLite convient à la plupart des installations (une seule instance, faible concurrence). Pour utiliser
PostgreSQL à la place, choisissez-le **à l’installation** : la surcouche compose
[`deploy/docker-compose.postgres.yml`](../../../deploy/docker-compose.postgres.yml)
ajoute :

- `postgres`, sur son propre réseau interne `db` (jamais partagé avec ClamAV ni
  le proxy) ;
- `migrate`, un conteneur ponctuel qui applique les migrations avec le rôle
  propriétaire à chaque `up`, pour que le serveur en fonctionnement ne détienne que le rôle d’exécution,
  qui ne peut ni modifier le schéma ni contourner la row-level security ;
- `db-backup`, le `pg_dump` nocturne dans le volume `transteira_backups`
  (`TT_BACKUP_TIME`, `TT_BACKUP_KEEP`), avec le rôle en lecture seule
  `transteira_backup`.

Les étapes 1 à 5 et 7 sont inchangées. Remplacez les étapes 6 et 8 par :

```sh
sh deploy/init-secrets.sh --postgres
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.postgres.yml up -d
```

`init-secrets.sh --postgres` ajoute des mots de passe de base de données aléatoires (rôles superutilisateur,
propriétaire, d’exécution et de sauvegarde), les deux chaînes de connexion et le
fichier `pgpass` du conteneur de sauvegarde, chacun appartenant au conteneur qui
le lit. Le superutilisateur ne peut se connecter que par le socket local du
conteneur `postgres`, jamais par le réseau. Les mots de passe ne sont lus qu’au premier
démarrage, lorsque le volume de la base de données est vide. Pour éviter de répéter les deux options
`-f`, définissez `COMPOSE_FILE=docker-compose.yml:docker-compose.postgres.yml` dans
`deploy/.env` et lancez `docker compose` depuis `deploy/`.

Les rôles et les contrôles effectués par TransTeira au démarrage sont décrits dans
[Rôles PostgreSQL](../postgresql.md).
