# SMTP

> Version anglaise de référence : [../smtp.md](../smtp.md). En cas de différence, la version anglaise fait foi.

TransTeira envoie deux sortes de mails :

- les **mails des entités** (codes de vérification, notifications de transfert, confirmations,
  invitations, alertes antivirus et de quota), par **la configuration SMTP de chaque
  entité**, définie dans l’administration (CLAUDE.md section 12.1) ;
- les **mails système** (l’alerte d’espace disque aux super administrateurs), par le
  **serveur SMTP système** défini par variables d’environnement
  ([ci-dessous](#smtp-système-pour-les-alertes)).

Trois sortes de serveurs sont prises en charge, pour les deux : un serveur SMTP authentifié
sur TLS, un relais sans authentification sur le réseau Docker interne et, comme cas
particulier de ce dernier, un relais vers Microsoft 365 via Microsoft Graph.

## Paramètres SMTP des entités

Chaque entité a sa propre configuration (écran **Messagerie (SMTP)** de l’entité,
super administrateur ou administrateur délégué de l’entité) :

| Champ | Remarques |
|---|---|
| Serveur SMTP, port | Nom d’hôte ou adresse IP, port de 1 à 65535. |
| Sécurité de la connexion | `starttls` (port 587 en général) : le passage en chiffré est obligatoire, un serveur qui ne propose pas STARTTLS est une erreur, jamais un repli silencieux en clair. `tls` : TLS implicite dès le premier octet (465 en général). `none` : TCP simple, uniquement pour un relais sur le réseau Docker interne. |
| Nom d’utilisateur, mot de passe | Facultatifs (`AUTH PLAIN`). Refusés avec `none` : les identifiants ne circulent jamais en clair. |
| Adresse d’expéditeur, nom d’expéditeur | L’adresse `From` (par exemple `transfer@entity-a.example.com`) et un nom d’affichage facultatif. |

- **Les certificats** sont vérifiés par rapport au magasin d’autorités de certification de l’image
  (autorités publiques). Un serveur dont le certificat est autosigné ou émis par une autorité privée est refusé.
- **Le mot de passe est chiffré au repos** : scellé par la clé maître, jamais
  réaffiché et jamais journalisé. Lorsque
  le serveur, le port ou le nom d’utilisateur changent, le mot de passe doit être ressaisi.
- **Bouton de test** : envoie un mail de test avec la configuration enregistrée et affiche
  l’étape SMTP atteinte (connexion, TLS, authentification…) avec la réponse
  du serveur ; 5 tests par tranche de 10 minutes par administrateur et par entité. Un mail accepté par le
  serveur peut encore être filtré plus loin.
- **Contrôle DNS** : un contrôle indicatif de SPF, DMARC et DKIM pour le domaine de
  l’adresse d’expéditeur ([ci-dessous](#spf-dkim-et-dmarc)).

Tant qu’une entité n’a pas de configuration SMTP fonctionnelle, elle ne peut envoyer aucun mail : personne
ne peut donc y faire vérifier une adresse. Pour en savoir plus : [Entités, SMTP](../../operations/tenants.md#smtp)
et le [guide de l’administrateur délégué](../../user/fr/delegated-admin.md).

## Serveur SMTP authentifié

Le cas habituel : un fournisseur de messagerie ou votre propre serveur de messagerie, joignable par
Internet ou par votre réseau. Choisissez `starttls` sur le port 587 (ou `tls` sur le port 465),
avec un nom d’utilisateur et un mot de passe dédiés à TransTeira, autorisés à envoyer avec
l’adresse d’expéditeur de l’entité.

Le conteneur TransTeira accède à Internet par le réseau `proxy`
(le réseau `internal` n’a pas d’accès à Internet). Si votre pare-feu filtre
le trafic sortant, autorisez l’hôte Docker à joindre les serveurs SMTP des
entités.

## Relais sans authentification sur le réseau Docker interne

TransTeira accepte un relais SMTP **sans authentification ni chiffrement**
(sécurité `none`), par exemple un conteneur de relais qui transmet à votre système
de messagerie ou à Microsoft Graph. Comme rien ne protège le trafic, le relais
doit se trouver sur un réseau Docker partagé uniquement avec TransTeira, jamais à travers un
réseau non fiable.

**Réseau.** Placez le relais sur un réseau dédié partagé avec le service
`transteira`, ainsi que sur le réseau dont il a besoin pour joindre son serveur amont.
Ne modifiez pas les fichiers compose fournis : ajoutez votre propre fichier à côté d’eux,
par exemple `deploy/docker-compose.mail.yml` :

```yaml
# deploy/docker-compose.mail.yml (your file, not part of the repository)
services:
  smtp-relay:
    image: <relay image>@sha256:<digest>   # pin it
    container_name: transteira-smtp-relay
    restart: unless-stopped
    networks:
      - mail          # reachable by TransTeira only
      - mail_egress   # to reach its upstream (Internet or your mail server)
    # Relay settings and upstream credentials: see the relay's documentation.
    # Keep secrets in Docker secrets, never in plain environment values.

  transteira:
    networks:
      - mail

networks:
  mail:
    internal: true
  mail_egress: {}
```

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.mail.yml up -d
```

(Ajoutez-le à `COMPOSE_FILE` dans `deploy/.env` pour éviter de répéter les options `-f`,
et gardez la même liste pour toutes les commandes suivantes, y compris les
mises à jour.)

Ensuite, dans la configuration de l’entité : serveur `smtp-relay` (le nom du service, résolu
par Docker), port `25` (ou le port du relais), sécurité **Aucune**, pas de nom d’utilisateur.

**`TT_SMTP_DENY_NETWORKS`.** Le serveur SMTP d’une entité est saisi par un
administrateur : TransTeira vérifie donc l’adresse vers laquelle il se résout, à chaque connexion,
par rapport à `TT_SMTP_DENY_NETWORKS` (protection contre la falsification de requête
côté serveur et le DNS rebinding). La valeur par défaut interdit le loopback, le link-local
(y compris les adresses de métadonnées cloud), `0.0.0.0/8` et `::/96`, mais **pas
les plages privées** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) : un
relais sur un réseau Docker fonctionne avec la valeur par défaut, rien n’est à changer.
Conséquences :

- un relais sur le loopback (`127.0.0.1`, ou `localhost`) est refusé pour une entité :
  utilisez un conteneur sur un réseau Docker ;
- si vous définissez la variable, sa valeur **remplace** la valeur par défaut : reprenez la
  liste par défaut et ajoutez-y vos propres réseaux (voir `.env.example`) ;
- **le déploiement fourni la définit** : `deploy/.env.example` reprend la
  liste par défaut et y ajoute les sous-réseaux fixes de la pile, afin que le serveur SMTP
  d’une entité ne puisse joindre ni clamd, ni PostgreSQL, ni le reverse
  proxy et les autres services du réseau partagé : le sous-réseau `proxy`
  (`172.30.0.0/24`), `INTERNAL_SUBNET` (`172.31.10.0/24`, clamd) et
  `DB_SUBNET` (`172.31.11.0/24`, PostgreSQL). Si vous changez l’un de ces
  sous-réseaux, changez aussi la liste (`make deploy-config-check` vérifie les
  fichiers fournis). Un relais d’entité doit donc se trouver sur un réseau qui lui est
  propre, comme le réseau `mail` ci-dessus, jamais sur `proxy` ou `internal` ;
- le serveur SMTP système est un réglage d’installation et n’est **pas** soumis
  à cette liste.

**Relais partagé et adresses d’expéditeur.** Un relais sans authentification envoie
tout ce qu’il reçoit. Si plusieurs entités utilisent le même relais, l’administrateur d’une
entité peut saisir n’importe quelle adresse d’expéditeur dans sa configuration, y compris une adresse
d’une autre entité. Limitez, au niveau du relais ou de son serveur amont, les adresses d’expéditeur
qu’il accepte à celles de vos entités, ou utilisez un relais par entité.

## Microsoft 365 via Microsoft Graph

Microsoft 365 est joignable avec un conteneur de relais qui reçoit le SMTP de
TransTeira et envoie chaque message avec l’API Microsoft Graph (une
application inscrite dans Microsoft Entra ID, avec l’autorisation d’application
`Mail.Send`). Plusieurs relais open source le font ; suivez la
documentation de celui que vous choisissez, et installez-le comme dans la
[section précédente](#relais-sans-authentification-sur-le-réseau-docker-interne).

Pour chaque entité, vérifiez dans Microsoft 365 :

1. **L’adresse d’expéditeur existe** sous forme de boîte aux lettres (une boîte aux lettres partagée suffit)
   dans un domaine accepté par votre organisation Microsoft 365, par exemple
   `transfer@entity-a.example.com`.
2. **DKIM est activé dans Microsoft 365 pour chaque domaine d’entité**, pas seulement pour
   le domaine par défaut : dans le portail Microsoft Defender (paramètres d’authentification
   des e-mails, DKIM), sélectionnez chaque domaine personnalisé, publiez les deux enregistrements `CNAME`
   qu’il affiche (`selector1._domainkey` et `selector2._domainkey`) et
   activez la signature. Sans cela, les mails de ce domaine échouent à l’alignement DMARC
   et risquent d’être rejetés ou classés comme indésirables.
3. **L’adresse d’expéditeur est autorisée dans l’application Graph.** L’autorisation
   d’application `Mail.Send` permet par défaut d’envoyer en tant que **n’importe quelle** boîte aux lettres de
   l’organisation : limitez l’application aux boîtes aux lettres d’expéditeur
   des entités, idéalement à ces seules boîtes, avec une
   stratégie d’accès aux applications Exchange Online (ou le contrôle d’accès basé sur les rôles
   pour les applications, qui lui succède). Par exemple, avec un groupe de sécurité
   à extension messagerie `transteira-senders@example.com` contenant les boîtes aux lettres
   d’expéditeur :

   ```powershell
   New-ApplicationAccessPolicy -AppId <application (client) ID> `
     -PolicyScopeGroupId transteira-senders@example.com `
     -AccessRight RestrictAccess `
     -Description "TransTeira relay: tenant sender mailboxes only"
   Test-ApplicationAccessPolicy -AppId <application (client) ID> -Identity transfer@entity-a.example.com
   ```

   Lorsque vous ajoutez une entité, ajoutez sa boîte aux lettres d’expéditeur au groupe.
4. **SPF, DKIM et DMARC** sont publiés pour chaque domaine (ci-dessous). Pour
   Microsoft 365, SPF comprend `include:spf.protection.outlook.com`, et les
   sélecteurs DKIM à saisir dans le contrôle DNS de TransTeira sont `selector1` et
   `selector2`.

Conservez le secret client (ou le certificat) de l’application Graph dans un secret
Docker du relais, ainsi que dans votre coffre de mots de passe.

## SPF, DKIM et DMARC

Chaque domaine d’envoi (le domaine de l’adresse d’expéditeur de chaque entité, et celui de
l’expéditeur système) nécessite, **avant la mise en production** :

| Enregistrement | Exemple | Rôle |
|---|---|---|
| SPF (`TXT` sur le domaine) | `v=spf1 include:spf.protection.outlook.com -all` | Liste les serveurs autorisés à envoyer pour le domaine. |
| DKIM (`TXT` ou `CNAME` sur `<selector>._domainkey`) | fourni par votre fournisseur de messagerie | Signe chaque message. |
| DMARC (`TXT` sur `_dmarc`) | `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com` | Indique aux serveurs de réception que faire lorsque SPF ou DKIM échouent à l’alignement. |

TransTeira ne signe pas lui-même les mails : DKIM est appliqué par le serveur, ou par le
serveur amont du relais, qui envoie le mail sur Internet.

Le **contrôle DNS** de l’écran SMTP de l’entité recherche ces enregistrements pour le
domaine de l’adresse d’expéditeur et signale chacun comme correct, à vérifier,
absent ou en erreur. Les sélecteurs DKIM ne peuvent pas être découverts : saisissez-en jusqu’à 5 (par
exemple `selector1, selector2` pour Microsoft 365). Le contrôle est indicatif :
il lit le DNS public, il n’envoie pas de message. Confirmez avec un mail de test
et les résultats d’authentification dans ses en-têtes.

## SMTP système pour les alertes

L’alerte d’espace disque concerne toute l’instance : elle n’est donc pas envoyée par
la configuration d’une entité mais par le **serveur SMTP système**, défini dans
`deploy/.env` :

| Variable | Rôle |
|---|---|
| `TT_SYSTEM_SMTP_HOST` | Nom ou adresse du serveur. Vide (par défaut) : pas de mail système, l’alerte disque n’apparaît que dans l’administration, le journal d’audit et le journal applicatif. |
| `TT_SYSTEM_SMTP_PORT` | Par défaut 25 avec `none`, 587 avec `starttls`, 465 avec `tls`. |
| `TT_SYSTEM_SMTP_SECURITY` | `starttls` (par défaut), `tls` ou `none` (relais sans authentification sur le réseau interne). |
| `TT_SYSTEM_SMTP_FROM`, `TT_SYSTEM_SMTP_FROM_NAME` | Adresse d’expéditeur (obligatoire) et nom d’affichage. |
| `TT_SYSTEM_SMTP_USERNAME`, `TT_SYSTEM_SMTP_PASSWORD_FILE` | Identifiants, les deux ou aucun, refusés avec `none`. Le mot de passe n’est lu que dans un fichier (un secret Docker), jamais dans une variable. |

Avec le relais des exemples ci-dessus :

```sh
TT_SYSTEM_SMTP_HOST=smtp-relay
TT_SYSTEM_SMTP_PORT=25
TT_SYSTEM_SMTP_SECURITY=none
TT_SYSTEM_SMTP_FROM=transteira@example.com
```

`TT_SMTP_DENY_NETWORKS` ne s’applique pas au serveur système : il peut s’agir d’un
relais sur n’importe quel réseau interne. Une configuration invalide arrête le démarrage.
Il n’y a pas de bouton de test pour le serveur système : vérifiez soigneusement les valeurs,
et surveillez le journal applicatif (`docker compose logs transteira`), qui
signale un échec de remise.
Pour un serveur authentifié et le secret Docker de son mot de passe, voir
[Administration, serveur SMTP système](../../operations/admin.md#system-smtp-server).
