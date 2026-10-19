# TransTeira : cahier des charges

> Document de cadrage destiné au développement (Claude Code). Il décrit le besoin fonctionnel, les contraintes techniques, les exigences de qualité et les règles de travail de **TransTeira**, un outil de transfert de fichiers multi-tenant open source. Toutes les valeurs indiquées sont validées.
>
> Le périmètre est découpé en trois versions (section 2). Les fonctionnalités marquées **[V1.1]** ou **[V2]** ne sont pas à implémenter en V1, mais **l'architecture de la V1 doit les anticiper** pour éviter toute refonte ultérieure.

---

## 1. Contexte et objectif

TransTeira est un outil de transfert de fichiers de type WeTransfer / SwissTransfer, conçu pour une organisation **multi-filiales / multi-entités**.

- L'outil est **auto-hébergé**, sur une VM exécutant Docker.
- Chaque entité (tenant) dispose de sa propre identité visuelle, de sa propre configuration et d'un **cloisonnement strict de ses données**.
- Toutes les entités partagent la même instance applicative et la même base technique.
- Usage ponctuel, faible concurrence, mais **fichiers très volumineux** (10 Go et plus).
- Le projet est **publié en open source sur GitHub** (dépôt public, licence AGPL). Le code et la documentation restent strictement génériques (section 25). Les choix d'intégration (reverse proxy, anti-bruteforce, supervision, relais SMTP) restent ouverts à plusieurs outils.

---

## 2. Découpage en versions

| Version | Périmètre |
|---|---|
| **V1, le cœur** | Tout le présent cahier des charges hors éléments marqués [V1.1] et [V2], y compris : journal de sécurité pour fail2ban et CrowdSec, configurations de reverse proxys (Caddy, Nginx, Traefik, Apache), configuration par variables d'environnement, mode maintenance, empreinte SHA-256 des fichiers, rotation de la clé maître, effacement cryptographique, guides utilisateur et aide intégrée avec captures automatiques, modèle de menaces. |
| **V1.1, l'exploitation** | Détection des abus (seuils et alertes), métriques Prometheus, endpoint d'état JSON, tableau de bord Grafana et template Zabbix, export syslog, alertes par webhook, rappel d'expiration, nombre maximal de téléchargements, « Mes envois », vérification du destinataire par code, suivi par destinataire, envoi de dossiers par glisser-déposer, dépôt depuis l'extérieur pour les internes déjà vérifiés, réponse au transfert, niveaux de confidentialité, restriction des destinataires, mode sombre, documentation utilisateur personnalisée par entité et export PDF. |
| **V2, l'entreprise** | SSO OpenID Connect (Entra ID), rôle auditeur, preuve de dépôt et de remise en PDF, export / import de configuration d'entité, lien de dépôt permanent, image Docker signée avec SBOM, kit de conformité, client en ligne de commande, option lien seul sans mail, chiffrement de bout en bout en option. |

---

## 3. Stack technique

| Composant | Choix | Remarques |
|---|---|---|
| Langage back-end | **Go** | Binaire unique, léger, adapté au streaming de gros fichiers. |
| Routeur HTTP | Léger (ex. `chi`) | Détermination du tenant, middlewares de filtrage. |
| Base de données | **SQLite** par défaut, **PostgreSQL** en option | Moteur choisi à l'installation. Métadonnées uniquement, jamais les fichiers (section 17). |
| Stockage des fichiers | **Système de fichiers** (volume Docker monté) | Un dossier par tenant. Pas de S3 ni de dépendance externe. |
| Antivirus | **ClamAV** | Conteneur séparé, interrogé par le serveur Go (clamd). |
| Reverse proxy | **Caddy** en référence | Nginx, Traefik et Apache documentés (section 18). |
| Conteneurisation | **Docker**, image minimale (`scratch` ou `alpine`) | Objectif : image la plus légère possible. |
| Reprise d'upload | Protocole **tus** | Envois découpés et reprenables. |
| Spécification d'API | **OpenAPI** | Contrat de l'API, rédigé en premier (API first). |
| Chiffrement au repos | **AES-256-GCM** par blocs (chunks) | Compatible streaming, natif en Go. |
| Configuration | **Variables d'environnement** | Avec fichier `.env.example` documenté. |

---

## 4. Architecture générale

- Un conteneur applicatif Go reçoit toutes les requêtes transmises par le reverse proxy, quel que soit le domaine.
- Le serveur lit l'en-tête `Host` pour identifier le **tenant courant** (ex. `transfer.entity-a.example.com`, `transfer.entity-b.example.com`). Un FQDN inconnu est rejeté et journalisé (section 16.3).
- Ce tenant est injecté dans le contexte de la requête par un middleware et conditionne tout le traitement : habillage, langue, filtrage des données, SMTP, plages IP, domaines autorisés, quotas, seuils.
- **API first** : le back-end expose une API REST documentée (OpenAPI). L'interface publique de dépôt / téléchargement et l'interface d'administration consomment exclusivement cette API.
- Trois espaces fonctionnels :
  1. **Public** : dépôt (internes et externes invités) et téléchargement (destinataires).
  2. **Administration** : super admin et admins délégués, authentifiés.
  3. **API automatisée** : accès par jetons d'API par entité.
- **Une seule instance applicative** par déploiement (contrainte liée à SQLite, section 17).
- **Configuration par variables d'environnement** pour tout ce qui relève de l'installation (moteur de base, chemins, proxys de confiance, clé maître, niveau de journalisation, etc.). La configuration propre aux entités reste en base et se gère dans l'administration.
- **Mode maintenance** : activable par variable d'environnement ou depuis l'administration du super admin, il affiche une page propre (par entité, dans sa langue) et refuse les nouveaux dépôts pendant les mises à jour, tout en laissant le health check répondre.
- Les extensions V1.1 et V2 sont anticipées dès la V1 : système d'événements interne réutilisable (alertes mail, webhooks, journal de sécurité, syslog), modèle de rôles extensible (auditeur), couche d'authentification admin pouvant accueillir un fournisseur OIDC.

### 4.1 Documentation de l'API

Le projet étant public et proposant des jetons d'API, la spécification OpenAPI doit être exploitable par les intégrateurs, pas seulement par les tests.

- **Documentation interactive servie par l'application** (ex. Scalar ou Redoc), générée directement depuis la spécification OpenAPI.
  - Ressources **intégrées au binaire**, **sans aucun CDN** : compatible avec la CSP stricte et fonctionnelle hors ligne.
  - **Accès par défaut : réservé aux admins authentifiés.** Un accès public reste possible en le configurant par variable d'environnement.
- **Spécification téléchargeable** (ex. `/api/openapi.yaml`), pour permettre la génération de clients dans n'importe quel langage.
- **API versionnée dans l'URL** (`/api/v1`) : aucun changement incompatible sans passer à la version suivante.
- **Format d'erreur standard RFC 9457** (Problem Details), avec des **codes d'erreur documentés**.
- **Chaque endpoint est décrit et accompagné d'au moins un exemple** (requête et réponse).
- **Guide d'intégration** dans `docs/api/` :
  - création et utilisation d'un jeton d'API ;
  - dépôt d'un gros fichier par script avec **tus** ;
  - exemples en **curl** et en **PowerShell**.

### 4.2 Documentation utilisateur

- **[V1] Source unique** : des guides en Markdown dans le dépôt (`docs/user/`), **un par profil** (déposant, destinataire, admin délégué, super admin), en **français et en anglais**.
- **[V1] Aide intégrée à l'application**, générée depuis ces guides, avec des **liens contextuels depuis chaque écran**. Comme la documentation de l'API, elle est **intégrée au binaire, sans CDN**.
- **[V1] Captures d'écran générées automatiquement** par les tests Playwright, pour que la documentation reste toujours à jour avec l'interface.
- **[V1.1] Personnalisation par entité** : nom, logo, couleurs, et surtout **les règles réelles de l'entité** injectées dans les guides (taille maximale par envoi, durées disponibles, accès depuis l'extérieur, niveaux de confidentialité, etc.).
- **[V1.1] Export PDF** de la documentation personnalisée d'une entité, pour diffusion aux utilisateurs.

---

## 5. Modèle multi-tenant et cloisonnement

- **Base unique**, chaque enregistrement porte un `tenant_id`.
- Le filtrage par tenant est appliqué **au plus bas niveau possible** (couche d'accès aux données recevant obligatoirement le tenant du contexte), afin qu'aucune requête ne puisse l'omettre par erreur.
- Avec PostgreSQL, une couche supplémentaire de **row-level security** renforce le cloisonnement entre entités.
- **Isolation stricte** : une entité ne voit jamais les transferts, fichiers, adresses, journaux ou configuration d'une autre.
- Fichiers physiques rangés dans un **dossier par tenant**, avec des noms de fichiers aléatoires non devinables (jamais le nom d'origine sur disque).
- Le cloisonnement est couvert par des **tests dédiés, avec une couverture de 100 %** (section 24).

### Configuration d'un tenant

- Nom de l'entité, FQDN
- Logo, couleurs, image de fond
- Langue par défaut
- Configuration SMTP (serveur, port, chiffrement, authentification optionnelle, mot de passe chiffré, adresse d'expéditeur)
- Plages d'adresses IP internes autorisées (liste CIDR)
- Domaines de messagerie internes autorisés (ex. `entity-a.example.com`)
- Limite de taille par envoi (au plus 20 Go)
- Quota global de stockage (défini par le super admin)
- Modèles de mails personnalisés
- Textes de mentions légales et de politique de confidentialité
- Jetons d'API
- **[V1.1]** Seuils de détection des abus, URL de webhooks, dépôt depuis l'extérieur pour les internes vérifiés, réponse au transfert, niveaux de confidentialité et leurs règles, domaines destinataires autorisés et interdits
- **[V2]** Paramètres SSO, liens de dépôt permanents

---

## 6. Utilisateurs, rôles et identification

### 6.1 Utilisateurs sans compte

Aucun compte n'est créé pour les utilisateurs qui déposent. Ils renseignent simplement leur adresse mail, vérifiée par code (section 7).

### 6.2 Utilisateur interne

Un utilisateur est reconnu comme **interne** si les deux conditions sont réunies :

1. son adresse IP appartient à une plage autorisée du tenant ;
2. le domaine de son adresse mail fait partie des domaines autorisés du tenant.

Seul un utilisateur interne peut déposer librement et émettre des invitations.

### 6.3 Utilisateur externe

Un externe (hors plage IP ou hors domaine autorisé) ne peut déposer que via une **invitation** émise par un utilisateur interne (section 9), **[V1.1]** via une réponse à un transfert (section 10), ou **[V2]** via un lien de dépôt permanent (section 22).

### 6.4 [V1.1] Dépôt depuis l'extérieur pour les internes déjà vérifiés

Pour faciliter le télétravail, une entité peut autoriser un utilisateur interne à déposer **hors des plages IP** de l'entité, sans invitation.

- **Option activable par entité**, désactivée par défaut.
- Ne concerne que les adresses d'un **domaine autorisé** de l'entité, **déjà vérifiées une première fois depuis le réseau interne** (la date et l'origine de la première vérification sont conservées).
- Depuis l'extérieur, **un code de vérification est exigé à chaque dépôt**, au lieu de la vérification unique : depuis l'extérieur, seule la possession de la boîte mail prouve l'identité.
- Les dépôts faits depuis l'extérieur sont **signalés dans les journaux d'audit**, et pris en compte par la détection des abus (section 15).

### 6.5 Administration

| Rôle | Périmètre |
|---|---|
| **Super admin** | Toutes les entités. Crée les entités, définit les quotas globaux, désigne les admins délégués, active le mode maintenance, reçoit les alertes d'espace disque. |
| **Admin délégué** | Rattaché à une ou plusieurs entités, limité strictement à celles-ci. Gère l'habillage, le SMTP, les plages IP, les domaines, la limite par envoi (à la baisse), les modèles de mails, les jetons d'API, la liste de blocage. Consulte les transferts de son entité, relance un envoi, supprime un transfert avant expiration. Reçoit les alertes de quota et d'abus. |
| **[V2] Auditeur** | Lecture seule, sur une ou plusieurs entités : journaux d'audit, journaux de sécurité, statistiques. Aucune modification possible. Destiné à un RSSI ou à un audit (ex. ISO 27001). |

**Authentification des admins** : identifiant + mot de passe (haché, ex. argon2id) **+ double authentification TOTP**, obligatoire pour le super admin et recommandée pour tous.

**[V2] SSO** : connexion des admins et auditeurs en **OpenID Connect**, compatible **Microsoft Entra ID**, configurable par entité. Le compte local du super admin avec TOTP reste toujours disponible en secours.

### 6.6 Premier lancement

Au premier démarrage, une **procédure d'initialisation** crée le compte super admin et **impose la configuration de la double authentification TOTP** avant tout autre usage de l'administration.

---

## 7. Vérification de l'adresse mail

- À la première utilisation d'une adresse, un **code à usage unique** (6 chiffres) est envoyé via le SMTP du tenant.
- L'utilisateur saisit le code sur la page, sans la quitter.
- Durée de validité du code : **15 minutes**.
- **2 tentatives** de saisie erronées maximum, puis le code est invalidé et un nouveau code doit être demandé.
- **Limitation des envois de codes** : au plus **5 codes par heure pour une même adresse** et **20 codes par heure depuis une même IP**.
- Une fois l'adresse vérifiée, **la vérification n'est plus redemandée** pour cette adresse (stockée en base, rattachée au tenant). Un cookie technique peut faciliter la reconnaissance, mais la base fait foi.
- Chaque adresse vérifiée porte une date de dernière utilisation. Une adresse **inutilisée depuis 12 mois** est supprimée et devra être revérifiée.

---

## 8. Dépôt d'un transfert

### 8.1 Conditions d'accès

- Par défaut, le dépôt n'est possible que depuis les **plages IP internes** du tenant, par un utilisateur interne (section 6.2), ou **[V1.1]** un interne déjà vérifié déposant depuis l'extérieur (section 6.4).
- Exceptions : un externe muni d'une invitation valide (section 9), **[V1.1]** une réponse à un transfert (section 10), **[V2]** un lien de dépôt permanent (section 22).
- Une adresse ou un domaine présent dans la **liste de blocage** de l'entité ne peut pas déposer.
- La vraie IP cliente est lue dans l'en-tête transmis par le reverse proxy (`X-Forwarded-For` / `X-Real-IP`), **uniquement si la requête provient d'un proxy de confiance déclaré** dans la configuration, pour qu'un client ne puisse pas falsifier son IP.

### 8.2 Contenu d'un envoi

- Adresse de l'expéditeur (vérifiée), un ou plusieurs destinataires, message optionnel.
- **Plusieurs fichiers par envoi.**
- Durée de validité choisie par l'expéditeur : **1, 7 ou 30 jours**.
- Option : **protection par mot de passe** (sans complexité minimale imposée).
- Option : **suppression après le premier téléchargement**.
- **[V1.1]** Option : **nombre maximal de téléchargements** par transfert.
- **[V1.1]** Option : **vérification du destinataire** (section 10).
- **[V1.1]** **Envoi de dossiers entiers par glisser-déposer**, avec **arborescence conservée** dans l'archive ZIP et dans la liste des fichiers.
- **[V2]** Option : **lien seul, sans envoi de mail** aux destinataires. L'expéditeur copie le lien affiché à la fin du dépôt et le transmet lui-même (ex. par Teams).
- **[V2]** Option : **chiffrement de bout en bout** (section 22).

### 8.3 [V1.1] Niveaux de confidentialité

- L'expéditeur choisit un **niveau de confidentialité** pour chaque envoi, par exemple **public**, **interne** ou **confidentiel**.
- Chaque niveau **impose ses propres règles**, définies par l'admin délégué pour son entité. Exemple pour « confidentiel » : vérification du destinataire obligatoire, durée de validité courte imposée, mot de passe obligatoire, destinataires limités aux domaines autorisés.
- Les niveaux, leurs libellés et leurs règles sont **configurables par entité**, avec des valeurs par défaut fournies.
- Le niveau apparaît dans les mails, sur la page de téléchargement et dans les journaux d'audit.

### 8.4 [V1.1] Restriction des destinataires

- Chaque entité peut définir une **liste de domaines destinataires autorisés** et/ou une **liste de domaines interdits** (ex. messageries personnelles grand public), pour limiter les risques de fuite.
- Un envoi vers un destinataire non autorisé est refusé avec un message explicite, et l'événement est journalisé.

### 8.5 Limites

- **Limite par envoi : 20 Go au total** (somme des fichiers), réductible par un admin pour son entité.
- **Quota global de stockage par entité**, défini par le super admin.
- Quota atteint : **nouveaux dépôts bloqués** jusqu'à libération d'espace (expiration ou suppression), et **notification de l'admin délégué**.
- **Alerte préventive** à l'admin délégué lorsque **80 %** du quota est atteint.

### 8.6 Gros fichiers

- Upload **découpé et reprenable** via le protocole **tus** : une coupure réseau ne doit pas obliger à tout recommencer.
- Traitement en **streaming** de bout en bout : aucun fichier n'est chargé en mémoire.
- Chiffrement et calcul de l'**empreinte SHA-256** appliqués en flux pendant l'écriture sur disque.
- La progression des envois est gérée sur disque ; la base n'est mise à jour qu'au début et à la fin d'un envoi (section 17).

### 8.7 [V1.1] « Mes envois »

Sans créer de compte, l'expéditeur peut demander par mail un **lien d'accès temporaire** (après vérification de son adresse) pour consulter ses transferts en cours, **les supprimer** ou **prolonger leur durée** (dans la limite des durées autorisées).

---

## 9. Invitations externes

- **N'importe quel utilisateur interne** peut inviter une personne externe en saisissant son adresse mail.
- L'externe reçoit un lien d'invitation unique, rattaché au tenant.
- Il passe la vérification par code (section 7) puis peut déposer. Les fichiers sont adressés à l'interne qui l'a invité.
- L'invitation **expire au bout de 12 mois si elle n'est pas utilisée**.
- L'émetteur de chaque invitation est **tracé en base** et dans les journaux d'audit.
- **[V1.1]** Nombre maximal d'invitations par interne et quota de dépôt propre aux externes (section 15).

---

## 10. Téléchargement

- Lien unique, non devinable, avec date d'expiration.
- Le destinataire peut télécharger **fichier par fichier** ou **l'ensemble en archive ZIP**.
- Le ZIP est **généré à la volée en streaming, sans compression** (mode store) : aucune copie supplémentaire sur disque.
- **Téléchargement forcé** (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`) : un fichier n'est jamais affiché ni exécuté dans le navigateur.
- L'**empreinte SHA-256** de chaque fichier est affichée sur la page, pour permettre au destinataire de vérifier son intégrité.
- Si le transfert est protégé par mot de passe : saisie avant téléchargement, **3 essais ratés maximum, puis blocage pendant 15 minutes**.
- Si un fichier n'a pas pu être analysé par l'antivirus (taille), la page de téléchargement l'indique clairement.
- **[V1.1]** **Vérification du destinataire** (option choisie par l'expéditeur) : chaque destinataire reçoit **un lien qui lui est propre** et doit valider son adresse par un code avant de télécharger. Un lien transféré à une autre personne est donc inutilisable. Mêmes règles que la vérification de l'expéditeur (15 minutes, 2 tentatives, limitation des envois).
- **[V1.1]** **Suivi par destinataire** : l'expéditeur voit, pour chaque destinataire, quels fichiers ont été téléchargés et quand (via « Mes envois » et l'accusé de réception). Ce suivi suppose des liens propres à chaque destinataire.
- **[V1.1]** Un **bouton « Signaler un abus »** sur la page de téléchargement alerte l'admin délégué de l'entité.
- **[V1.1]** **Réponse au transfert** : depuis la page de téléchargement, le destinataire peut **renvoyer des fichiers à l'expéditeur** via un lien de retour, sans invitation. Le lien de retour est lié au transfert d'origine, valable pendant sa durée de vie, réservé au destinataire (vérification de son adresse par code), et soumis aux quotas externes, à l'antivirus et à la détection des abus. Option activable par entité.

---

## 11. Antivirus (ClamAV)

- Chaque fichier déposé est analysé par ClamAV (conteneur séparé, réseau interne) avant d'être mis à disposition.
- **Virus détecté** : le fichier est **supprimé** et l'expéditeur reçoit une **alerte**. Pas de quarantaine.
- **Fichier trop gros pour être analysé** (au-delà des limites de ClamAV, de l'ordre de 2 Go au mieux) : le fichier est **accepté**, l'**expéditeur est prévenu**, et le **destinataire est informé** sur la page de téléchargement qu'il n'a pas pu être analysé en raison de sa taille.
- Les limites de taille de ClamAV (`MaxFileSize`, `MaxScanSize`, `StreamMaxLength`) sont relevées au maximum raisonnable et configurables.

---

## 12. Notifications

### 12.1 SMTP par tenant

- Chaque entité envoie depuis **sa propre configuration SMTP**.
- **L'authentification SMTP est optionnelle** : TransTeira doit accepter un relais SMTP **sans authentification ni chiffrement** sur le réseau Docker interne (ex. relais SMTP vers Microsoft Graph), en plus d'un serveur SMTP classique authentifié.
- Mot de passe SMTP, s'il existe, **chiffré en base**.
- **Bouton de test d'envoi** dans l'administration.
- Prérequis d'exploitation : **SPF, DKIM et DMARC** configurés pour chaque domaine d'envoi. L'administration affiche un contrôle indicatif de ces enregistrements.
- La documentation d'installation précise, pour un relais vers Microsoft 365 : vérifier que **DKIM est activé dans Microsoft 365 pour chaque domaine d'entité**, et que **l'adresse d'envoi de chaque entité est autorisée** dans l'application Graph (idéalement limitée à ces seules boîtes).

### 12.2 Mails émis

| Mail | Destinataire | Remarques |
|---|---|---|
| Code de vérification | Expéditeur | Code 6 chiffres, valable 15 min |
| Notification de transfert | Destinataires | Lien + **QR code du lien intégré en pièce jointe inline** (CID, pas d'image distante) + empreintes SHA-256. Si mot de passe : mention que celui-ci est transmis **par un autre canal**. |
| Confirmation d'envoi | Expéditeur | |
| Accusé de premier téléchargement | Expéditeur | **Uniquement au premier téléchargement** |
| Virus détecté | Expéditeur | Fichier supprimé |
| Fichier non analysé (taille) | Expéditeur | |
| Invitation externe | Externe invité | Lien d'invitation |
| Alerte quota 80 % / quota atteint | Admin délégué | |
| Alerte espace disque | Super admin | Seuil par défaut 85 % |
| **[V1.1]** Rappel d'expiration | Destinataires | **La veille de l'expiration**, uniquement s'ils n'ont pas encore téléchargé |
| **[V1.1]** Alerte d'abus / signalement | Admin délégué | |
| **[V1.1]** Lien « Mes envois » | Expéditeur | |

### 12.3 Modèles

- **Modèles de mails personnalisables par entité** (habillage, textes), dans chaque langue disponible.
- Modèles par défaut fournis en français et en anglais.

### 12.4 [V1.1] Webhooks

- En plus des mails, les alertes (virus, abus, signalement, quotas, espace disque) peuvent être envoyées par **webhook** vers **Teams**, **Slack** ou une **URL générique** (JSON).
- Configurables par entité (admin délégué) et au niveau global (super admin).

---

## 13. Habillage graphique et accessibilité

- Par entité : logo, couleurs, **une seule image de fond plein écran** (esprit WeTransfer / SwissTransfer).
- **Image par défaut** si l'entité n'en a pas configuré.
- Lisibilité garantie par un voile semi-transparent ou un encadré derrière la zone de dépôt.
- Page **mentions légales / politique de confidentialité** par entité.
- Respect de l'accessibilité **RGAA** : contrastes suffisants, navigation complète au clavier, libellés lisibles par les lecteurs d'écran, textes alternatifs sur les images.
- L'administration **avertit lorsqu'une couleur choisie pour une entité n'offre pas un contraste suffisant**.

### 13.1 [V1.1] Mode sombre

- Thème sombre qui **suit par défaut le réglage du système** de l'utilisateur (`prefers-color-scheme`).
- **Bouton de changement manuel** de thème, mémorisé par un **cookie technique**.
- Les **deux thèmes respectent les mêmes exigences RGAA** de contraste.
- Le **contrôle de contraste** des couleurs d'une entité vérifie **les deux thèmes** (une couleur lisible sur fond clair peut ne plus l'être sur fond sombre).
- Le **voile posé sur l'image de fond s'adapte au thème** actif.
- L'architecture CSS de la V1 repose déjà sur des variables de thème, pour que l'ajout du mode sombre ne demande pas de refonte.

---

## 14. Langues

- Interface **multilingue**, langues au lancement : **français et anglais**.
- Chaque entité définit sa **langue par défaut**.
- La langue du navigateur (`Accept-Language`) est utilisée si elle est disponible, sinon la langue par défaut de l'entité.
- Architecture i18n permettant d'ajouter facilement d'autres langues.

---

## 15. [V1.1] Détection des abus

Le mécanisme couvre deux risques : **les fuites de données en interne** et **le détournement de l'outil par des externes**. Toutes les alertes vont à l'admin délégué de l'entité (mail et webhook), et **tous les seuils sont réglables par entité**.

### 15.1 Fuites internes

- **Seuils par expéditeur** : volume maximal par jour, nombre maximal de transferts par jour, nombre maximal de destinataires par envoi. Dépassement : alerte, et blocage optionnel.
- **Détection de comportements inhabituels** : volume nettement supérieur aux habitudes de l'expéditeur, gros envois vers des adresses externes, envois en dehors des heures de bureau (plage horaire configurable).

### 15.2 Détournement par des externes

- **Nombre maximal d'invitations** par utilisateur interne.
- **Quota de dépôt propre aux externes** (volume et nombre de dépôts).
- **Bouton « Signaler un abus »** sur la page de téléchargement.
- **Liste de blocage** gérée par l'admin délégué : adresses mail, domaines et empreintes SHA-256 de fichiers interdits.

> Note : la **liste de blocage** et le **journal de sécurité** (section 16.3) font partie de la V1, car ils conditionnent la sécurité de base.

---

## 16. Sécurité

### 16.1 Chiffrement au repos

- Les fichiers sont **chiffrés sur disque**, de façon transparente côté serveur (déchiffrement à la volée au téléchargement).
- Algorithme : **AES-256-GCM**, appliqué **par blocs (chunks)** pour permettre le streaming.
- **Gestion des clés** :
  - une **clé maître** fournie au conteneur par un **secret Docker** ou un fichier monté **hors du volume de données** ;
  - **une clé par fichier**, chiffrée par la clé maître (envelope encryption) et stockée en base ;
  - la clé maître est également conservée dans un **coffre de mots de passe, hors de la VM**, pour permettre la restauration.
- **Rotation de la clé maître** : une commande d'administration (et une action du super admin) permet de remplacer la clé maître. Grâce à l'envelope encryption, seules les clés par fichier sont rechiffrées avec la nouvelle clé maître, **sans relire ni réécrire les fichiers**. L'opération est reprenable en cas d'interruption, journalisée dans l'audit, et la documentation décrit la procédure (dont la mise à jour de la copie dans le coffre).
- **Effacement cryptographique** : à la suppression d'un transfert (expiration, suppression manuelle, effacement RGPD), la clé de chaque fichier est **détruite en base** en plus de la suppression du fichier. Les copies présentes dans les sauvegardes deviennent ainsi **illisibles**.
- Le chiffrement est couvert par des tests avec une **couverture de 100 %**.

### 16.2 Protections applicatives

- Filtrage IP par tenant, avec lecture de l'IP réelle uniquement depuis les proxys de confiance déclarés.
- Limitation de débit (rate limiting) sur les codes de vérification, les mots de passe de transfert, l'authentification admin et les jetons d'API.
- **En-têtes de sécurité HTTP** : CSP stricte, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` / `frame-ancestors`, `Permissions-Policy`. HSTS géré par le reverse proxy.
- Liens, codes et jetons générés avec un générateur aléatoire cryptographique.
- Secrets (mots de passe SMTP, jetons d'API) chiffrés ou hachés en base, jamais en clair dans les journaux.
- **Uniquement des cookies strictement techniques** (aucun cookie de mesure d'audience ou tiers), ce qui dispense de bandeau de consentement.

### 16.3 Journal de sécurité (fail2ban et CrowdSec)

- TransTeira écrit un **journal de sécurité dédié**, distinct du journal d'audit, dans un **format stable et documenté** (une ligne par événement, horodatage, type d'événement, **IP réelle du client**, tenant).
- Événements journalisés : code de vérification erroné, mauvais mot de passe de transfert, échec de connexion admin (mot de passe ou TOTP), jeton d'API invalide, FQDN inconnu, dépôt refusé hors plage IP ou par la liste de blocage, dépassement de limitation de débit.
- Le dépôt fournit **les deux intégrations prêtes à l'emploi**, au choix de l'exploitant :
  - **fail2ban** : filtre et jail, avec action sur la chaîne **`DOCKER-USER`** (sans quoi Docker contourne les règles) ;
  - **CrowdSec** : parser et scénario, avec mention du bouncer Caddy.
- Le format du journal fait l'objet de tests, pour que les intégrations ne cassent pas lors des évolutions.

### 16.4 Jetons d'API

- Jetons d'API **par entité**, créés et révoqués par les admins, pour des dépôts automatisés par des scripts ou logiciels tiers.
- **Pas d'expiration par défaut**, **révocables à tout moment**, avec possibilité de fixer une **date d'expiration optionnelle**.
- Jetons stockés hachés, avec date de création et de dernière utilisation.

---

## 17. Base de données

- **SQLite par défaut**, **PostgreSQL au choix** lors de l'installation (variable d'environnement).
- La couche d'accès aux données est abstraite pour supporter les deux moteurs.
- **Migrations de schéma versionnées**, appliquées **automatiquement au démarrage**, sans perte de données, sur les deux moteurs.
- Règles propres à SQLite :
  - mode **WAL** ;
  - **pas d'écriture en base à chaque morceau d'un envoi** : la progression reste sur disque, la base n'est mise à jour qu'au début et à la fin d'un envoi ;
  - **une seule instance applicative** sur une même base.
- Avec PostgreSQL : **row-level security** activée comme couche supplémentaire de cloisonnement entre entités.
- **L'ensemble des tests et des migrations s'exécute sur les deux moteurs.**

---

## 18. Conteneurs, réseau et reverse proxy

### 18.1 Organisation Docker

- Le **reverse proxy est mutualisé** pour d'autres services : il a **son propre docker-compose**, distinct de celui de TransTeira.
- Un **réseau Docker externe partagé** (ex. `proxy`) relie le reverse proxy et le conteneur applicatif.
- Le conteneur applicatif **n'expose aucun port sur l'hôte** : tout passe par le reverse proxy.
- Le docker-compose de TransTeira contient l'application et **ClamAV** (et PostgreSQL si ce moteur est choisi), reliés par un **réseau interne** non visible du proxy.
- Volumes : données (fichiers chiffrés), base SQLite, sauvegardes de la base, journaux. La clé maître est fournie hors de ces volumes.

### 18.2 Reverse proxys documentés

**Caddy** est la configuration de référence. La documentation fournit aussi des configurations prêtes à l'emploi pour **Nginx**, **Traefik** et **Apache**.

Pour chacun, les réglages critiques sont expliqués :

- certificat TLS pour chaque FQDN d'entité (automatique avec Caddy et Traefik) ;
- **mise en tampon désactivée** (requêtes et réponses) ;
- **pas de limite de taille de requête** bloquante ;
- **délais d'attente allongés** pour les envois et téléchargements volumineux ;
- transmission de l'**IP réelle** du client (`X-Forwarded-For` / `X-Real-IP`) ;
- déclaration de l'IP du proxy dans la variable des **proxys de confiance** de TransTeira.

---

## 19. Supervision

- **[V1]** Endpoint de **health check** (ex. `/healthz`) vérifiant l'application, la base et la disponibilité de ClamAV. Directement exploitable par **Uptime Kuma**.
- **[V1]** **Alerte sur l'espace disque** au super admin à **85 %** de remplissage, seuil **modifiable dans l'administration**.
- **[V1.1]** Endpoint de **métriques au format Prometheus** (ex. `/metrics`, protégé) : transferts, volumes, quotas, détections antivirus, erreurs, espace disque, files d'analyse.
- **[V1.1]** Endpoint d'**état en JSON** (ex. `/status`, protégé), plus simple à exploiter pour les outils ne lisant pas le format Prometheus (ex. **Observium**, scripts maison).
- **[V1.1]** Fournis dans le dépôt : un **tableau de bord Grafana** prêt à importer et un **template Zabbix** (lecture native de l'endpoint Prometheus).
- **[V1.1]** **Export des journaux en syslog** (audit et sécurité) vers un SIEM.

---

## 20. Cycle de vie des données et RGPD

| Donnée | Règle de conservation |
|---|---|
| Transferts et fichiers | Suppression automatique à expiration (1, 7 ou 30 jours), après le premier téléchargement si l'option est cochée, **[V1.1]** au nombre maximal de téléchargements atteint, ou sur suppression manuelle |
| Adresses vérifiées | Supprimées après **12 mois** sans utilisation |
| Invitations | Expirées après **12 mois** sans utilisation |
| Journaux d'audit et de sécurité | Conservés **12 mois** |
| Codes de vérification | Supprimés après usage ou expiration |

- Une **tâche de nettoyage périodique** unique gère toutes ces purges.
- Toute suppression de fichier s'accompagne d'un **effacement cryptographique** (section 16.1), y compris pour les copies présentes dans les sauvegardes.
- Principe de minimisation des données appliqué partout.
- **Exercice des droits des personnes** : une fonction d'administration permet de **rechercher une adresse mail et de supprimer toutes les données qui y sont liées** (dans le périmètre de l'admin).
- Uniquement des cookies techniques (section 16.2).

---

## 21. Journaux d'audit et statistiques

### 21.1 Journaux d'audit

- Actions tracées : dépôts, téléchargements, invitations (avec émetteur), vérifications d'adresse, actions des admins (connexion, modification de configuration, suppression de transfert, effacement de données, mode maintenance), détections de virus, dépassements de quota, utilisations de jetons d'API, signalements d'abus.
- Chaque entrée : horodatage, tenant, acteur (adresse ou admin), IP, action, objet concerné.
- Conservation **12 mois**, cloisonnés par tenant (l'admin délégué ne voit que ceux de son entité).

### 21.2 Tableau de bord

- Statistiques par entité pour les admins : volumes échangés, nombre de transferts, espace occupé et taux de remplissage du quota.
- Vue globale pour le super admin.

---

## 22. Fonctionnalités V2 (entreprise)

À ne pas implémenter en V1, mais à anticiper dans l'architecture.

- **SSO OpenID Connect** pour les admins et auditeurs, compatible **Microsoft Entra ID** (section 6.5).
- **Rôle auditeur** en lecture seule (section 6.5).
- **Preuve de dépôt et de remise** : récapitulatif horodaté d'un transfert (expéditeur, destinataires, fichiers et empreintes SHA-256, date de dépôt, date du premier téléchargement), **exportable en PDF**, utilisable en cas de litige.
- **Export et import de la configuration d'une entité** (JSON), pour créer une entité en dupliquant une existante. Les secrets (SMTP, jetons) ne sont jamais exportés.
- **Lien de dépôt permanent** : adresse fixe attribuée à un service (ex. collecte de pièces auprès de tiers), avec **vérification du déposant par code**, soumise aux quotas externes et à la détection des abus.
- **Image Docker signée** (ex. cosign) et publiée avec son **SBOM** (liste des composants). Sans CI, la construction, la signature et la publication se font en local via une commande dédiée (ex. `make release`).
- **Client en ligne de commande** écrit en Go (binaire unique multiplateforme) pour déposer et télécharger depuis des scripts, via l'API, les jetons d'API et le protocole tus (reprise automatique).
- **Option lien seul, sans mail** (section 8.2).
- **Chiffrement de bout en bout en option** : les fichiers sont chiffrés dans le navigateur de l'expéditeur, et la clé n'est jamais transmise au serveur (ex. clé placée dans le fragment `#` du lien), qui ne peut donc jamais lire les fichiers. Conséquence assumée : **l'analyse antivirus est impossible** pour ces envois, ce que la page de téléchargement indique clairement. L'option peut être autorisée, imposée ou interdite par entité et par niveau de confidentialité.
- **Kit de conformité** dans la documentation : fiche prête à l'emploi pour le **registre des traitements RGPD** et **correspondance avec les mesures de l'annexe A de l'ISO 27001**, accompagnées du **modèle de menaces** (section 27.1).

---

## 23. Sauvegarde et restauration

- La sauvegarde de la **VM hébergeant Docker** (ex. Veeam) couvre les volumes.
- Pour éviter une copie incohérente de SQLite pendant une écriture, TransTeira réalise une **copie propre et régulière de la base** (ex. `VACUUM INTO` nocturne) dans le volume de sauvegarde, capturée ensuite par la sauvegarde de la VM. Avec PostgreSQL, un `pg_dump` régulier joue le même rôle.
- La **clé maître** doit être sauvegardée séparément (coffre de mots de passe) : sans elle, les fichiers sauvegardés sont inexploitables.
- Procédure de restauration documentée.

---

## 24. Exigences de développement et de tests

### 24.1 Principes

- **API first** : la spécification OpenAPI est rédigée et validée avant l'implémentation ; le front consomme l'API.
- **Tout le code est en anglais** : identifiants, variables, fonctions, commentaires, messages de commit. Seule l'interface utilisateur est traduite (français et anglais).
- **Code documenté** : commentaires GoDoc sur les éléments exportés, plus la documentation d'installation et d'exploitation.

### 24.2 Tests

- **Tests unitaires sur chaque fonction.**
- **Tests d'intégration**, notamment :
  - parcours complet : vérification par code, dépôt multi-fichiers, lien, téléchargement unitaire et ZIP, empreintes SHA-256 ;
  - filtrage IP + domaine, proxys de confiance, invitations externes, liste de blocage ;
  - quotas (alerte 80 %, blocage) ;
  - antivirus (fichier infecté, fichier trop gros) ;
  - mot de passe de transfert (3 essais, blocage) ;
  - format du journal de sécurité, mode maintenance.
- **Tests de bout en bout dans un vrai navigateur** (ex. Playwright), simulant un dépôt et un téléchargement complets comme un utilisateur.
- **Tests de contrat** vérifiant que l'API respecte exactement la spécification OpenAPI.
- **Tests de sécurité** :
  - vérification systématique qu'une entité ne peut jamais accéder aux données d'une autre, pour chaque endpoint ;
  - **fuzzing** (natif Go) sur toutes les entrées utilisateur.
- **Test de gros fichier automatisé** : génération à la volée d'un fichier aléatoire de **20 Go**, envoi à travers un vrai Caddy lancé dans Docker, **coupure de connexion en cours d'envoi puis reprise**, vérification de l'empreinte du fichier téléchargé par rapport à l'original, et **contrôle que la consommation mémoire reste stable**.
- Tous les tests s'exécutent sur **SQLite et sur PostgreSQL**.
- Environnement de test local : **Mailpit** pour capturer les mails, domaines en `*.localhost` pour simuler plusieurs entités.

### 24.3 Couverture

- **85 % minimum au global.**
- **100 % sur les parties critiques** : cloisonnement entre entités, chiffrement, authentification.
- Une étape de développement n'est considérée comme terminée que si ces seuils sont atteints et tous les tests passent.

### 24.4 Exécution en local uniquement

- **Aucune intégration continue sur GitHub** (pas de GitHub Actions).
- L'ensemble des contrôles s'exécute **en local**, lancé par **une seule commande** (ex. `make check`) : tests (tous types, y compris le test 20 Go), `go vet`, linter, **`govulncheck`**, **linter de la spécification OpenAPI** (ex. Spectral, vérifiant notamment que chaque endpoint est décrit et accompagné d'un exemple), mesure de couverture.
- **Analyse des secrets** (ex. gitleaks) exécutée automatiquement **avant chaque envoi vers GitHub** via un hook git local (pre-push).

---

## 25. Publication sur GitHub

- **Dépôt public**, licence **AGPL-3.0** (fichier `LICENSE`).
- **Code totalement générique** : aucun nom de client ou d'entité réelle ; uniquement des exemples fictifs (domaines en `example.com`).
- Fichiers à fournir :
  - **`README.md` soigné** : présentation de TransTeira, captures d'écran, fonctionnalités, installation avec Docker et reverse proxy, configuration, licence. Badges limités à la licence et à la version (pas de badges de tests, puisqu'il n'y a pas de CI).
  - **`SECURITY.md`** : procédure de signalement privé des failles.
  - **`CHANGELOG.md`** : résumé des changements par version.
  - **`.env.example`** : toutes les variables d'environnement documentées.
  - **`.gitignore`** excluant la base, les fichiers déposés, les sauvegardes, les journaux, le `.env` et tous les secrets.
  - **`docs/api/`** : guide d'intégration de l'API (section 4.1).
  - **`docs/user/`** : guides utilisateur par profil, en français et en anglais (section 4.2).
  - **`docs/security/threat-model.md`** : modèle de menaces STRIDE (section 27.1).
  - Dossier d'intégrations : configurations des reverse proxys, fail2ban, CrowdSec, puis **[V1.1]** Grafana et Zabbix.
- **Gestion des versions** : numérotation sémantique (SemVer), numéro de version visible dans l'application et dans l'API.

---

## 26. Prérequis avant démarrage

- **Compte ou organisation GitHub** choisi avant d'écrire la moindre ligne : le chemin du module Go en dépend et apparaît dans tout le code (ex. `github.com/<compte>/transteira`). Si l'information n'est pas fournie, Claude Code doit la demander avant d'initialiser le module.
- Vérifier que le nom **TransTeira** est disponible sur GitHub et ne correspond pas à une marque déposée.
- Poste de développement : Git, Go, Docker Desktop (avec au moins **60 à 80 Go d'espace disque** alloués, pour le test de 20 Go), VS Code avec Claude Code.

---

## 27. Règles de travail pour Claude Code

### 27.1 Démarrage

Conformément au principe API first, le développement démarre par trois livrables à faire valider **avant toute écriture de code applicatif** :

1. **La spécification OpenAPI** complète de l'API V1 (endpoints publics, administration, jetons d'API, modèles de données, codes d'erreur), conçue pour accueillir les ajouts V1.1 et V2.
2. **L'arborescence du projet** (organisation des packages Go, emplacement des tests, migrations pour SQLite et PostgreSQL, ressources i18n, modèles de mails, fichiers Docker, dossier d'intégrations, documentation API et utilisateur).
3. **Le modèle de menaces** (`docs/security/threat-model.md`), selon la méthode **STRIDE** : actifs, frontières de confiance, flux de données, menaces identifiées par composant et mesures correspondantes dans le cahier des charges. Il sert de **référence à l'agent de sécurité**, il est **mis à jour à chaque version** et il est intégré au kit de conformité.

Claude Code crée aussi, dès le début, le **fichier de réglages du projet** (`.claude/settings.json`) pré-autorisant les commandes courantes (`go build`, `go test`, `go vet`, `make check`, `docker compose`, etc.), afin de travailler sans interruptions inutiles.

### 27.2 Méthode

- Avancer **par étapes**, en commençant par la V1 uniquement.
- **Utiliser le mode plan avant chaque grosse étape** et présenter le plan avant d'implémenter.
- **Ne jamais passer à l'étape suivante sans que `make check` soit entièrement au vert.**
- **Un commit Git à chaque étape validée**, avec un message clair en anglais, pour pouvoir revenir en arrière à tout moment.
- Tenir le `CHANGELOG.md` à jour.

### 27.3 Parallélisme et rapidité

- **Utiliser systématiquement des sous-agents en parallèle** dès que les tâches sont indépendantes (ex. code et tests de packages différents, documentation, intégrations).
- Créer des **agents spécialisés** (via `/agents`) au minimum pour : **les tests**, **la sécurité** (cloisonnement, chiffrement, authentification) et **la relecture de code**. L'agent de relecture et l'agent de sécurité passent sur chaque étape avant le commit.
- Lorsque c'est pertinent, des sessions parallèles peuvent travailler sur des **git worktrees** séparés (ex. administration d'un côté, antivirus de l'autre), fusionnés ensuite après `make check`.

### 27.4 Points de relecture humaine

Arrêter et demander une validation explicite sur :

- la spécification OpenAPI, l'arborescence et le modèle de menaces (avant de coder) ;
- le cloisonnement entre entités ;
- le chiffrement et la gestion des clés ;
- l'authentification des admins ;
- l'essai réel avec de très gros fichiers derrière le reverse proxy, en fin de V1.
