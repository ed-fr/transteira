# Installation rapide (`install.sh`)

> Version anglaise de référence : [../quick-install.md](../quick-install.md). En cas de différence, la version anglaise fait foi.

`install.sh` installe TransTeira, ClamAV et le reverse proxy Caddy de référence,
le tout dans Docker, sur un **serveur Debian 12 ou 13 vierge**, en quelques
minutes. C'est un fichier joint à chaque release GitHub, signé avec la même clé
que l'image, et il installe l'image signée de **sa propre version**, épinglée par
condensé (digest). Pour un serveur existant, un reverse proxy partagé ou un autre
système, suivez le [guide manuel](docker.md), qui reste la référence.

Les noms d'exemple sont fictifs : `admin.transfer.example.com` est l'hôte
d'administration et `transfer.entity-a.example.com` une entité. Remplacez-les par
les vôtres.

Sommaire :

1. [Prérequis](#1-prérequis)
2. [Télécharger et vérifier l'installeur](#2-télécharger-et-vérifier-linstalleur)
3. [Le lancer](#3-le-lancer)
4. [Ce qu'il installe et modifie](#4-ce-quil-installe-et-modifie)
5. [Premier lancement](#5-premier-lancement)
6. [Mise à jour](#6-mise-à-jour)
7. [Désinstallation et retour arrière](#7-désinstallation-et-retour-arrière)
8. [Dépannage](#8-dépannage)

## 1. Prérequis

- Un **serveur vierge** : Debian 12 (bookworm) ou 13 (trixie), amd64 ou arm64, et
  un accès root (`sudo`). Le script refuse tout autre système, et refuse un
  serveur qui contient déjà une installation de TransTeira qu'il n'a pas faite
  (un `deploy/.env`, un Caddyfile dans `/opt/reverse-proxy` ou un conteneur
  nommé `transteira`).
- **Mémoire** : au moins 8 Gio de RAM (10 Gio avec PostgreSQL), comme dans le
  [guide manuel](docker.md#1-prérequis). En dessous, le script avertit seulement,
  mais ClamAV peut être tué. Fonctionnez sans swap, ou avec un swap chiffré.
- **Disque** : le script s'arrête sous 10 Gio libres pour `/var/lib/docker` et
  avertit sous 30 Gio. Les fichiers transférés y sont stockés : prévoyez la somme
  des quotas de vos entités.
- **Ports 80/tcp, 443/tcp et 443/udp libres** sur le serveur, et joignables depuis
  Internet (Let's Encrypt valide par eux).
- **DNS** : un enregistrement `A` (IPv4) pour l'hôte d'administration, pointant
  vers le serveur, **avant** de lancer le script. **Pas d'enregistrement
  `AAAA`** : l'installation ne sert que l'IPv4, car le réseau Docker de Caddy n'a
  pas d'IPv6 et les clients IPv6 arriveraient sinon tous chez TransTeira avec une
  seule adresse de passerelle (limites de débit partagées, aucun bannissement,
  voire une plage interne). Le pare-feu et Docker refusent l'IPv6 sur 80 et 443,
  et le script avertit en cas d'enregistrement `AAAA`. Chaque
  entité a le sien, à créer en même temps que l'entité (section 5). Sans DNS, le
  script avertit seulement, mais Caddy ne peut pas obtenir de certificat pour ce
  nom tant que l'enregistrement n'existe pas.
- **Accès sortant** sur le port 443 vers le registre des images Docker,
  `download.docker.com` (sauf si Docker est déjà installé), `github.com`,
  `deb.debian.org`, `tuf-repo-cdn.sigstore.dev`, `rekor.sigstore.dev`,
  `acme-v02.api.letsencrypt.org` et `database.clamav.net`. Le script avertit pour chacun qu'il ne peut pas joindre.
- Un **coffre de mots de passe hors du serveur**, pour la clé maître (section 5).

## 2. Télécharger et vérifier l'installeur

Le script s'exécute en root : vérifiez-le d'abord. La release contient quatre
fichiers : `install.sh`, `SHA256SUMS` (qui liste `install.sh`), sa signature
`SHA256SUMS.sigstore.json` et la clé publique `cosign.pub`.

```sh
VERSION=2.2.0
BASE=https://github.com/ed-fr/transteira/releases/download/v$VERSION
mkdir transteira-install && cd transteira-install
curl -fsSLO "$BASE/install.sh" -O "$BASE/SHA256SUMS" \
  -O "$BASE/SHA256SUMS.sigstore.json" -O "$BASE/cosign.pub"

# 1. La clé : comparez avec la ligne « cosign.pub SHA-256 fingerprint » du README
#    et de SECURITY.md du projet, lus sur GitHub, pas dans ce téléchargement.
sha256sum cosign.pub

# 2. La signature des sommes (obligatoire) : c'est elle qui relie le script à la
#    clé du projet. Pas encore de cosign sur le serveur ? Voir ci-dessous.
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS

# 3. Le script lui-même :
sha256sum -c --ignore-missing SHA256SUMS
```

L'étape 2 doit afficher `Verified OK` et l'étape 3 `install.sh: OK`. **Ne sautez
pas l'étape 2** : seules, les étapes 1 et 3 ne détectent qu'un téléchargement
corrompu, puisque `SHA256SUMS` vient du même endroit qu'`install.sh`.

Un serveur vierge n'a pas cosign. Soit vous faites les trois étapes sur votre poste
(cosign 3.0 ou plus) et copiez l'`install.sh` vérifié sur le serveur, soit vous
récupérez la release de cosign qu'utilise l'installeur lui-même, contrôlée par le
SHA-256 écrit ici (lisez ce guide sur GitHub, comme l'empreinte de l'étape 1) :

```sh
# cosign v3.1.4, Linux amd64 (pour arm64 : cosign-linux-arm64 et
# ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2).
curl -fsSLo cosign https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  cosign" | sha256sum -c -
chmod 0755 cosign
./cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
```

L'installeur refait lui-même les contrôles qui comptent pour ce qu'il installe : il
embarque `cosign.pub` et en vérifie l'empreinte, télécharge cosign épinglé par
SHA-256, et vérifie la signature et l'attestation SBOM de l'image par son condensé
avant de la tirer ([Politique de sécurité](../../../SECURITY.md#verifying-releases)).

`--version` affiche la version que le script installe, et `--help` liste les
options. Le script doit être lancé depuis un fichier, pas par un tube depuis `curl`.

## 3. Le lancer

En interactif, en root : le script pose quelques questions, chacune avec une valeur
par défaut.

```sh
sudo bash install.sh
```

| Question | Option | Défaut |
|---|---|---|
| Nom d'hôte de l'administration | `--admin-host FQDN` | `hostname -f` si c'est un nom complet |
| Adresse de contact Let's Encrypt | `--acme-email ADRESSE` | aucune (avertissement : pas d'avis d'expiration) |
| PostgreSQL au lieu de SQLite | `--postgres` | SQLite, qui convient à la plupart des installations |
| SMTP système (alertes d'espace disque) | `--smtp-*` | aucun |

Sans surveillance (Ansible, cloud-init) : `--yes` ne pose aucune question et prend
les valeurs par défaut. `--admin-host` est alors obligatoire, sauf si `hostname -f`
donne un nom complet.

```sh
sudo bash install.sh --yes \
  --admin-host admin.transfer.example.com \
  --acme-email ops@example.com
```

Toutes les options :

| Option | Signification |
|---|---|
| `--admin-host FQDN` | Nom d'hôte de l'administration (mis en minuscules, validé). |
| `--acme-email ADRESSE` | Contact du compte Let's Encrypt. `--acme-email ""` signifie aucun, sans question. |
| `--postgres` | PostgreSQL au lieu de SQLite. Voir [PostgreSQL](../postgresql.md). |
| `--smtp-host HÔTE` | Serveur SMTP système (`TT_SYSTEM_SMTP_*`), utilisé pour les alertes d'espace disque aux super admins. Les entités ont leur propre SMTP, réglé ensuite ([SMTP](smtp.md)). |
| `--smtp-security none\|starttls\|tls` | Par défaut `starttls`. |
| `--smtp-port PORT` | Par défaut 25 avec `none`, 587 avec `starttls`, 465 avec `tls`. |
| `--smtp-from ADRESSE` | Adresse d'expédition. Obligatoire avec `--smtp-host`. |
| `--smtp-user NOM` | Nom d'utilisateur. Refusé avec `--smtp-security none` ; exige `--smtp-password-file`. |
| `--smtp-password-file FICHIER` | Fichier contenant le mot de passe ; exige `--smtp-user`. Il est copié dans un secret Docker (`deploy/secrets/system_smtp_password`, propriétaire UID 10001, mode 0400), jamais dans `.env` ni dans le journal. |
| `--no-firewall` | N'installe pas la table du pare-feu. |
| `--no-fail2ban` | N'installe pas fail2ban ni ses jails. |
| `--no-auto-updates` | N'active pas les mises à jour automatiques de sécurité de Debian. |
| `--yes`, `-y` | Aucune question. Le rappel de la clé maître est affiché mais n'attend pas. |
| `--dry-run` | Affiche le plan, les réglages ajoutés à `.env` et les lignes modifiées du Caddyfile. N'exige pas root et ne change rien. |
| `--upgrade` | Met à jour une installation faite par le script (section 6). Refuse `--admin-host`, `--acme-email`, `--smtp-*` et `--postgres`. |
| `--version`, `--help` | Affiche la version, l'aide. |

Exemple avec PostgreSQL et un SMTP système authentifié :

```sh
sudo bash install.sh --yes --postgres \
  --admin-host admin.transfer.example.com --acme-email ops@example.com \
  --smtp-host smtp.example.com --smtp-from transteira@example.com \
  --smtp-user transteira --smtp-password-file /root/smtp-password
```

Essayez d'abord `--dry-run`. L'installation prend quelques minutes ; le premier
téléchargement des signatures de ClamAV est l'étape la plus longue. On peut la
relancer après une interruption : l'état est conservé dans
`/opt/transteira/install.conf` et l'exécution reprend. Dès que l'exécution
interrompue a écrit son Caddyfile ou son `.env`, la suivante reprend ses réponses
(nom d'hôte, adresse ACME, moteur, SMTP système) et refuse une option différente. Tout est journalisé dans
`/var/log/transteira-install.log` (mode 0600, aucun secret n'y est écrit).

## 4. Ce qu'il installe et modifie

Tout ce que le script change sur le serveur, dans l'ordre :

1. **Paquets** : `ca-certificates`, `curl`, `gpg`, `iproute2`, `tar`, `gzip`,
   `coreutils`, puis, sauf désactivation, `nftables`, `fail2ban` avec
   `python3-systemd`, et `unattended-upgrades`.
2. **Docker CE** (`docker-ce`, `docker-ce-cli`, `containerd.io`,
   `docker-compose-plugin`) depuis le dépôt APT officiel de Docker, après
   vérification de l'empreinte de sa clé (le fichier ne doit contenir que cette
   clé). Avant cela, `/etc/docker/daemon.json` est écrit avec
   `"userland-proxy": false`, pour qu'une connexion IPv6 vers 80 ou 443 soit
   refusée au lieu d'être relayée vers Caddy avec l'adresse de la passerelle. Si
   `docker compose` fonctionne déjà, Docker est laissé tel quel et le dépôt n'est
   pas ajouté, mais Docker Engine 25 et Compose 2.24 ou plus sont exigés ; un
   `daemon.json` existant n'est jamais modifié (un avertissement signale s'il lui
   manque ce réglage). Tant que cloud-init ou `apt-daily` tient le verrou d'apt
   après le premier démarrage, le script attend (jusqu'à 10 minutes).
3. **cosign**, épinglé par une version et un SHA-256 gravés dans le script, dans
   `/opt/transteira/bin/cosign`, puis la **vérification de l'image** par son
   condensé (signature de l'index, attestation SBOM de votre plateforme).
4. **`/opt/transteira/deploy`** : les fichiers compose de production, les secrets
   (générés par `init-secrets.sh`, dont `secrets/master_key`) et `.env` (mode
   0600). `.env` fixe l'image épinglée par condensé, `TT_ADMIN_HOSTS`,
   `TT_TRUSTED_PROXIES` (Caddy seul), `TT_TLS_ASK_ALLOWED_IPS` et `COMPOSE_FILE`,
   si bien qu'un simple `docker compose` lancé depuis ce dossier fonctionne. Avec
   `--smtp-user`, une surcharge compose monte le secret du mot de passe.
5. **`/opt/reverse-proxy`** : Caddy et son Caddyfile, en mode TLS à la demande (le
   certificat de chaque nouvelle entité est obtenu à la première requête, aucun
   fichier à modifier), et le réseau Docker `proxy` (172.30.0.0/24). Caddy est le
   seul conteneur qui publie des ports (80, 443 et 443/udp).
6. **Conteneurs** : le projet compose `transteira` (TransTeira, ClamAV, freshclam,
   et PostgreSQL avec son conteneur de sauvegarde si choisi) et le projet
   `reverse-proxy`, attendus jusqu'à ce qu'ils soient sains.
7. **Pare-feu de l'hôte** (sauf `--no-firewall`) : une table nftables dédiée
   `inet transteira_fw`, chargée par l'unité `transteira-firewall.service` depuis
   `/etc/transteira/firewall.nft`. Le trafic entrant est refusé sauf la boucle
   locale, les connexions établies, l'ICMP essentiel, SSH, et 80/tcp, 443/tcp et
   443/udp en IPv4 (l'IPv6 est refusé sur ces ports, voir le prérequis DNS). Le
   script ne vide jamais le jeu de règles : les tables de Docker et de fail2ban ne
   sont pas touchées. Les ports SSH laissés ouverts sont rassemblés depuis
   `sshd -T` (`port` et `listenaddress`), les sockets sur lesquels sshd écoute ou
   est connecté (`ss`), un `ssh.socket` actif, et la session SSH quand ses
   variables parviennent au script (`sudo` les retire en général), ou 22 si aucun
   n'est trouvé. La question de confirmation les liste : vérifiez que le port par
   lequel vous vous connectez y figure avant de répondre, sinon utilisez
   `--no-firewall`. Si SSH change ensuite de port, modifiez-le dans
   `/etc/transteira/firewall.nft` puis lancez
   `systemctl reload transteira-firewall`.
8. **fail2ban** (sauf `--no-fail2ban`) : les filtres et les jails `transteira` et
   `transteira-sso` dans `/etc/fail2ban/jail.d/transteira.local`, qui lisent
   `security.log` du volume `transteira_logs` (les bannissements passent par la
   chaîne `DOCKER-USER`, sur 80/tcp, 443/tcp et 443/udp pour bannir aussi
   l'HTTP/3, voir [Reverse proxy](../reverse-proxy.md) et
   [`integrations/fail2ban/`](../../../integrations/fail2ban/README.md)). Ajoutez
   vos plages internes et vos sondes de supervision à `ignoreip` dans ce fichier,
   sinon elles peuvent être bannies. Sans `/var/log/auth.log` (pas de rsyslog), le
   jail sshd de Debian est basculé sur le journal systemd dans
   `jail.d/transteira-sshd-journal.local`, faute de quoi fail2ban ne démarrerait pas.
9. **Mises à jour automatiques** (sauf `--no-auto-updates`) : `unattended-upgrades`
   limité à l'archive de sécurité de Debian, sans redémarrage automatique. Docker CE
   et les images (ClamAV, PostgreSQL, Caddy, épinglées par condensé) ne sont pas
   mis à jour automatiquement.

Ce que le script laisse en place : `/opt/transteira` (`deploy/`, `bin/cosign`,
`cosign.pub`, `install.conf`), `/opt/reverse-proxy`, `/etc/transteira`, le journal
`/var/log/transteira-install.log` et les volumes Docker `transteira_*`.

## 5. Premier lancement

À la fin, le script affiche :

- l'**URL d'initialisation** `https://admin.transfer.example.com/admin/setup` et le
  **jeton d'initialisation**. Le jeton n'apparaît que sur le terminal, jamais dans
  le fichier journal, et n'est pas affiché du tout avec `--yes` (la sortie finit
  en général dans un journal d'automatisation) : lisez-le sur le serveur avec
  `docker logs transteira 2>&1 | grep 'Setup token'`. Il est valable jusqu'au
  redémarrage de TransTeira ; la même commande donne alors le nouveau.
- un **rappel de copier la clé maître** dans votre coffre.

Dans l'ordre :

1. **Sauvegardez la clé maître maintenant.** Affichez-la avec
   `sudo cat /opt/transteira/deploy/secrets/master_key` (mode 0400) et copiez-la
   dans un coffre de mots de passe **hors du serveur**. Sans elle, les fichiers et
   les sauvegardes ne pourront jamais être déchiffrés
   ([Clé maître](../../operations/master-key.md)). En mode interactif, le script
   attend que vous tapiez `copied`.
2. **Créez le super admin** à l'URL d'initialisation : jeton, nom d'utilisateur,
   adresse mail, mot de passe, puis l'enrôlement **TOTP** (obligatoire). Conservez
   les codes de secours
   ([Administration](../../operations/admin.md#first-run-setup)). Le script ne crée
   jamais le super admin : le secret TOTP et les codes restent entre vos mains.
3. **Créez la première entité** dans l'administration, avec l'assistant : son FQDN
   (par exemple `transfer.entity-a.example.com`), sa langue, son SMTP, ses règles et
   ses mentions légales ([Entités](../../operations/tenants.md)). **Créez d'abord son
   enregistrement DNS**, pointant vers ce serveur : Caddy obtient le certificat à la
   première visite.
4. Réglez le **SMTP de l'entité** et envoyez le mail de test ([SMTP](smtp.md)).
5. Prévoyez aussi les [sauvegardes](../../operations/backup.md) de la VM et une copie
   des secrets conservée hors du serveur.

## 6. Mise à jour

Avec l'`install.sh` de la nouvelle release, téléchargé et vérifié comme en section 2 :

```sh
sudo bash install.sh --upgrade
```

Lisez d'abord les [notes de mise à jour](../../operations/upgrade.md) de la version.
Le script alors :

1. vérifie que `/opt/transteira/install.conf` décrit une installation faite par le
   script, et **refuse un retour à une version antérieure** ;
2. vérifie la nouvelle image (signature, attestation SBOM) et la tire ;
3. crée les secrets dont la nouvelle release a besoin, s'il y en a
   (`init-secrets.sh` de la release : fichiers manquants seulement, les existants
   ne sont jamais modifiés) ;
4. vérifie, dans un dossier de préparation, que les fichiers compose de la nouvelle
   release se chargent avec votre `.env`, vos secrets et votre Caddyfile ; sinon, il
   s'arrête avant de rien modifier ;
5. **sauvegarde la base** : `transteira backup` avec SQLite (la copie va dans le
   volume `transteira_backups`), `pg_dump` avec PostgreSQL ;
6. garde les fichiers qu'il va remplacer dans `/opt/transteira/previous` (dossier
   de déploiement avec `.env`, sans les secrets ; fichier compose de Caddy), puis
   remplace les fichiers compose, le fichier compose de Caddy et les filtres
   fail2ban, et fait pointer `TRANSTEIRA_IMAGE` de `.env` vers le nouveau condensé ;
7. redémarre, attend que TransTeira soit sain et vérifie qu'il annonce la nouvelle
   version. **En cas d'échec, il remet les fichiers précédents et redémarre la
   version précédente.**

`.env`, les secrets, la surcharge SMTP, le Caddyfile et le jail fail2ban sont
**conservés**. Si une release change `.env` ou le Caddyfile (nouvelle variable,
nouvelle règle Caddy), les notes de version le disent : appliquez-le à la main. `--upgrade` refuse
`--admin-host`, `--acme-email`, `--smtp-*` et `--postgres` : modifiez les réglages
dans `/opt/transteira/deploy/.env`.

## 7. Désinstallation et retour arrière

Il n'y a pas de commande de désinstallation : le script n'a installé que des
éléments standard.

- **Retour arrière d'une mise à jour** : une mise à jour qui échoue revient
  d'elle-même en arrière (section 6). La version et l'image précédentes sont notées
  dans `/opt/transteira/install.conf` (`TTI_PREVIOUS_VERSION`,
  `TTI_PREVIOUS_IMAGE`) et ses fichiers gardés dans `/opt/transteira/previous`. Pour
  revenir en arrière après une mise à jour réussie, ou si la version précédente
  refuse une base déjà migrée par la nouvelle : restaurez la copie de la base faite
  par la mise à jour ([Sauvegardes](../../operations/backup.md),
  [Mise à jour](../../operations/upgrade.md)), recopiez les fichiers de
  `/opt/transteira/previous/deploy` dans `/opt/transteira/deploy` et lancez
  `docker compose up -d` dans ce dossier. Lancer un `install.sh` plus ancien est
  refusé.
- **Retirer la pile** : dans `/opt/reverse-proxy` et `/opt/transteira/deploy`, lancez
  `docker compose down` (ajoutez `-v` dans le second pour supprimer les volumes, ce
  qui **détruit tous les transferts**). Désactivez ensuite le pare-feu avec
  `systemctl disable --now transteira-firewall`, supprimez
  `/etc/fail2ban/jail.d/transteira*.local` et
  `/etc/apt/apt.conf.d/52transteira-unattended-upgrades`, puis retirez
  `/opt/transteira`, `/opt/reverse-proxy` et `/etc/transteira`. Docker et les paquets
  restent installés.

## 8. Dépannage

- **Journal** : `/var/log/transteira-install.log`. Quand une commande échoue, le
  script affiche la fin du journal. On peut relancer l'installation : elle reprend
  d'après `/opt/transteira/install.conf` (état `installing`). Le script refuse de
  s'exécuter par-dessus une installation terminée (utilisez `--upgrade`) ou une
  installation qu'il n'a pas faite.
- **Démarrage lent de ClamAV** : le premier passage de freshclam télécharge les
  signatures (plusieurs minutes), puis clamd les charge avant d'être sain. Le script
  attend jusqu'à 25 minutes les signatures et 15 minutes chaque conteneur. S'il
  s'arrête sur un délai dépassé, lisez `docker logs transteira-clamav-update` et
  `docker logs transteira-clamav`, puis relancez le script.
- **Certificat non obtenu** (échec ACME) : l'enregistrement DNS de l'hôte ne pointe
  pas encore vers le serveur, ou le port 80 ou 443 est filtré en amont (pare-feu du
  cloud, NAT). Lisez
  `docker compose -f /opt/reverse-proxy/docker-compose.yml logs`. Corrigez le DNS puis
  redémarrez Caddy ; Let's Encrypt limite les échecs répétés, attendez un peu plutôt
  que de réessayer en boucle. Derrière un NAT qui redirige 80 et 443 vers le serveur,
  l'avertissement « ne se résout pas vers ce serveur » est sans conséquence.
- **Ports occupés** : arrêtez ce qui écoute sur 80 ou 443 (`ss -lntup`), le script le
  vérifie avant de rien modifier.
- **Verrouillé hors de SSH** : le pare-feu garde les ports SSH listés avant la
  confirmation (section 4, point 7). Si SSH écoute sur un autre port, ou si vous
  l'avez changé ensuite, passez par la console de la VM, modifiez
  `/etc/transteira/firewall.nft` et lancez `systemctl reload transteira-firewall`.
- **Banni par fail2ban** : `fail2ban-client status transteira`, puis
  `fail2ban-client set transteira unbanip <adresse>`, et ajoutez l'adresse à
  `ignoreip`.
- **Réglages de l'installation** : `/opt/transteira/deploy/.env`. Après modification,
  lancez `docker compose up -d` dans ce dossier. Voir la
  [référence des variables](docker.md#7-configuration-env).
