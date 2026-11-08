# Registre RGPD des activités de traitement : service de transfert de fichiers

Modèle de fiche du registre des activités de traitement (RGPD, article 30)
d'une organisation qui exploite **TransTeira 2.0**. Elle est pré-remplie à
partir de ce que fait le logiciel (modèle de données, tâche de nettoyage,
écrans d'administration). Tout ce que seule l'organisation peut décider est
marqué `<à compléter>`.

English: [docs/compliance/gdpr-processing-record.md](../gdpr-processing-record.md).

> Ceci est un modèle, pas un avis juridique. Voir l'[avertissement](README.md).
> Une instance TransTeira peut servir plusieurs entités (tenants). Si les
> entités sont des responsables de traitement distincts, remplissez une copie
> par entité ; si une seule personne morale les exploite toutes, un registre
> unique listant les entités suffit.

## 1. Identification

| Élément | Valeur |
|---|---|
| Activité de traitement | Service de transfert de fichiers (« TransTeira ») |
| Version et date de la fiche | `<à compléter>` |
| Responsable de traitement (personne morale, adresse) | `<à compléter>` |
| Représentant du responsable de traitement | `<à compléter>` |
| Délégué à la protection des données (DPO) ou contact | `<à compléter>` |
| Responsables conjoints (si les entités d'un groupe décident ensemble) | `<à compléter>` ou aucun |
| Entités (tenants) couvertes | `<à compléter>` (noms d'hôte, par exemple `transfer.entity-a.example.com`) |

## 2. Finalités

- Transférer des fichiers, éventuellement très volumineux, d'un expéditeur à
  des destinataires, pour une durée limitée (1, 7 ou 30 jours).
- Vérifier l'identité de l'expéditeur (code envoyé dans sa boîte mail) et,
  en option, de chaque destinataire.
- Protéger le service et les données : contrôle d'accès, analyse antivirus,
  détection des abus, journaux d'audit et de sécurité.
- Prouver un dépôt ou une remise en cas de litige (déclarations signées).
- Administrer le service (comptes d'administrateurs et d'auditeurs).

## 3. Base légale (article 6)

Choisissez une base par finalité et supprimez les autres.

| Finalité | Base légale | Choix |
|---|---|---|
| Transfert de fichiers entre utilisateurs et tiers invités | Intérêt légitime (art. 6.1.f) / exécution d'un contrat (art. 6.1.b) | `<à compléter>` |
| Sécurité, journaux d'audit et de sécurité, détection des abus | Intérêt légitime (art. 6.1.f) / obligation légale (art. 6.1.c) | `<à compléter>` |
| Preuves de dépôt et de remise | Intérêt légitime (art. 6.1.f) / contrat (art. 6.1.b) | `<à compléter>` |
| Administration du service | Intérêt légitime (art. 6.1.f) | `<à compléter>` |

TransTeira ne demande jamais de consentement et n'a aucun traitement fondé sur
le consentement.

## 4. Personnes concernées

| Catégorie | Qui |
|---|---|
| Expéditeurs | Utilisateurs internes (adresse d'un domaine interne, depuis le réseau de l'entité) et personnes externes invitées, qui déposent des fichiers. Aucun compte n'est créé. |
| Destinataires | Personnes à qui un transfert est adressé, par mail. |
| Personnes invitées | Personnes externes invitées par un utilisateur interne à déposer. |
| Déposants par lien de dépôt permanent | Personnes externes qui déposent vers un service (lien de dépôt), après vérification de leur adresse. |
| Administrateurs | Super admin et admins délégués. |
| Auditeurs | Comptes en lecture seule (RSSI, auditeurs). |
| Autres personnes citées en texte libre | Personnes mentionnées dans le message d'un transfert, un nom de fichier ou un signalement d'abus. |

## 5. Catégories de données personnelles

| Donnée | Détail | Où elle est conservée |
|---|---|---|
| Adresses mail | Expéditeur, destinataires, invités, déposants, auteurs de signalements d'abus ; adresses des administrateurs et auditeurs. | Base de données (transferts, destinataires, invitations, adresses vérifiées, preuves, liens de dépôt, administrateurs). |
| Adresses IP | De l'expéditeur au dépôt, à la vérification d'adresse (première vérification, et première vérification en interne), des demandes de vérification, des auteurs de signalements ; IP du client dans les journaux d'audit et de sécurité. | Base de données et fichiers de journaux. |
| Noms, tailles et empreintes SHA-256 des fichiers | De chaque fichier déposé ; les noms sont un texte libre choisi par l'expéditeur. | Base de données ; les empreintes figurent aussi dans les mails de notification et les preuves. |
| Messages des transferts | Texte libre facultatif de l'expéditeur. | Base de données. |
| Contenu des fichiers | Peut contenir toute donnée, y compris sensible. Chiffré sur disque (AES-256-GCM, une clé par fichier). Pour un transfert chiffré de bout en bout, le navigateur chiffre et le serveur ne détient jamais la clé : **l'exploitant ne peut pas le lire** ; l'analyse antivirus est alors impossible et la page de téléchargement l'indique. | Volume de données (chiffré) ; clés, chiffrées par la clé maître, en base. |
| Événements des transferts | Dates de dépôt, de premier téléchargement, téléchargements par destinataire et par fichier (liens par destinataire). | Base de données. |
| État de vérification | Codes (stockés sous forme de MAC, jamais en clair), tentatives, sessions de dépôt, date de dernière utilisation d'une adresse vérifiée. | Base de données. |
| Journal d'audit | Horodatage, entité, acteur (adresse ou administrateur), IP, action, objet. | Base de données. |
| Journal de sécurité | Horodatage, type d'événement, IP réelle du client, entité. Aucune adresse mail. | Fichier de journal et base de données. |
| Preuves de dépôt et de remise | Déclarations signées nommant l'expéditeur, les destinataires, les fichiers et leurs empreintes, les dates. Aucune adresse IP. | Base de données. |
| Signalements d'abus | Catégorie, message en texte libre, IP de l'auteur. | Base de données. |
| Comptes d'administrateurs | Identifiant, mail, rôle, haché du mot de passe (argon2id), secret TOTP (scellé par la clé maître), codes de secours (hachés), enregistrements de sessions. | Base de données. |
| Identifiants d'authentification unique (si utilisée) | Émetteur, identifiant client et sujet (`sub`) du compte du fournisseur d'identité lié à un administrateur. | Base de données. |
| Cookies techniques | Strictement nécessaires uniquement, voir la section 9. | Navigateur. |

TransTeira ne collecte lui-même aucune catégorie particulière de données
(article 9), mais **les fichiers et messages envoyés par les utilisateurs
peuvent en contenir**. Le responsable de traitement décide, dans ses règles
d'usage, ce qui peut être envoyé (niveaux de confidentialité, restriction des
domaines destinataires).

## 6. Destinataires des données

| Destinataire | Détail |
|---|---|
| En interne | Expéditeur et destinataires de chaque transfert ; admins délégués de l'entité (métadonnées, jamais le contenu des fichiers : décision P18) ; auditeurs (lecture seule) ; super admin. |
| Sous-traitants et prestataires | Voir la section 7. |
| Tiers autorisés par la loi | `<à compléter>` (autorités, sur réquisition) |

## 7. Sous-traitants et transferts hors UE

TransTeira est **auto-hébergé** : l'exploitant choisit où et par qui il est
exploité, et le projet ne reçoit aucune donnée. La seule connexion sortante
vers le projet est la vérification des mises à jour (requête anonyme vers l'API
GitHub toutes les 24 heures ; aucun identifiant d'entité, d'utilisateur ou
d'instance n'est envoyé, mais GitHub voit l'adresse IP du serveur ;
`TT_UPDATE_CHECK=false` la désactive, menace T-245).

| Sous-traitant ou service | Rôle | Données concernées | Localisation | Contrat (art. 28) | Transfert hors UE et garanties |
|---|---|---|---|---|---|
| Hébergement de la VM et de ses sauvegardes | Fait fonctionner le service et les sauvegardes | Toutes les données (les fichiers sont chiffrés au repos) | `<à compléter>` | `<à compléter>` | `<à compléter>` |
| Relais SMTP (par exemple Microsoft 365 ou un autre relais) | Envoie les mails du service | Adresses des destinataires et expéditeurs, contenu des mails (liens, empreintes, messages) | `<à compléter>` | `<à compléter>` | `<à compléter>` |
| Fournisseur OpenID Connect (par exemple Microsoft Entra ID), si l'authentification unique est utilisée | Authentifie les administrateurs et auditeurs | Identité de l'administrateur (mail, `sub`) | `<à compléter>` | `<à compléter>` | `<à compléter>` |
| Destinations de webhooks (Teams, Slack, générique), si utilisées | Reçoivent les alertes | Charge minimale par défaut (décision P31) | `<à compléter>` | `<à compléter>` | `<à compléter>` |
| Moteur antivirus distant (ICAP, API HTTP), si utilisé | Analyse les fichiers | Contenu des fichiers en transit, en clair vers le moteur | `<à compléter>` | `<à compléter>` | `<à compléter>` |
| Collecteur syslog ou SIEM, si utilisé | Reçoit les journaux d'audit et de sécurité | Journaux (IP, adresses du journal d'audit) | `<à compléter>` | `<à compléter>` | `<à compléter>` |
| Infogéreur (ESN), s'il exploite l'instance | Administration, provisionnement | `<à compléter>` | `<à compléter>` | `<à compléter>` | `<à compléter>` |

Supprimez les lignes qui ne s'appliquent pas. Le moteur ClamAV par défaut
tourne dans un conteneur du même hôte et n'envoie rien à l'extérieur.

## 8. Conservation

Les durées ci-dessous sont celles qu'applique le logiciel (la tâche de
nettoyage de TransTeira, exécutée toutes les heures pour les purges de lignes).
Quand l'exploitant peut agir, la dernière colonne dit où.

| Donnée | Conservation | L'exploitant peut modifier |
|---|---|---|
| Transferts et leurs fichiers | Jusqu'à l'expiration choisie par l'expéditeur (**1, 7 ou 30 jours**), ou plus tôt : après le premier téléchargement si l'option est cochée, au nombre maximal de téléchargements atteint, ou sur suppression manuelle par l'expéditeur (Mes envois) ou un admin. Les fichiers sont alors supprimés et leurs clés détruites. La ligne de métadonnées (sans clés) d'un transfert terminé est purgée **30 jours** après sa fin. | Les durées disponibles et la taille maximale par entité (administration, réglages généraux). Pas le délai de purge. |
| Envois inachevés | Abandonnés après `TT_UPLOAD_TTL` (24 h par défaut) d'inactivité, et au plus tard `TT_UPLOAD_MAX_AGE`. | `.env` : [`.env.example`](../../../.env.example) |
| Transferts bloqués en analyse antivirus | Effacés 30 jours après le dépôt si l'analyse n'aboutit jamais. | Non |
| Adresses vérifiées | Supprimées après **12 mois** sans utilisation ; l'adresse doit alors être revérifiée. | Non |
| Invitations | Valables 12 mois à partir de la création ou de la dernière utilisation ; invitations inactives purgées ensuite. | Un admin peut révoquer une invitation à tout moment. |
| Liens de dépôt permanents | Les liens expirés ou révoqués sont purgés 12 mois après, une fois leurs transferts supprimés. | Un admin peut désactiver, révoquer ou fixer une date d'expiration. |
| Codes de vérification | Supprimés après usage ou expiration (les lignes servant à la limitation de débit sont gardées une heure). | Non |
| Sessions de dépôt, compteurs d'échecs de mot de passe, liens d'accès « Mes envois » | Purgés après leur courte validité (quelques heures). | Durée d'une session de dépôt : `TT_DEPOSIT_SESSION_TTL`. |
| Journal d'audit | **12 mois**, puis purge. Aucune modification ni suppression par l'application, sauf la pseudonymisation d'un effacement. | Non |
| Journal de sécurité, copie en base | **12 mois** (purge en base). Le **fichier** de journal est tourné par l'exploitant : gardez-le 12 mois aussi ([journal de sécurité](../../operations/security-log.md)). | Rotation des journaux (exploitant). |
| Export syslog | Selon la conservation de votre collecteur. | Exploitant. |
| Preuves de dépôt et de remise | **12 mois** après leur création, même si le transfert est supprimé. | Non |
| Signalements d'abus | 12 mois. | Non |
| Alertes d'abus (données de dédoublonnage) | 2 jours. | Non |
| Compteurs de statistiques (volumes, nombres, aucune donnée personnelle) | 13 mois. | Non |
| Sessions d'administration | Inactivité de 30 minutes et durée maximale de 12 heures par défaut. | `TT_ADMIN_SESSION_IDLE_TIMEOUT`, `TT_ADMIN_SESSION_MAX_AGE` |
| Comptes d'administrateurs et d'auditeurs | Jusqu'à suppression par le super admin. | Super admin. |
| Copies de la base (SQLite `VACUUM INTO`, PostgreSQL `pg_dump`) | `TT_BACKUP_KEEP` copies (7 par défaut pour SQLite), puis la conservation des sauvegardes de la VM. | `.env` et politique de sauvegarde ([sauvegarde](../../operations/backup.md)). |
| Sauvegardes de la VM | `<à compléter>` | Exploitant. |

## 9. Cookies

TransTeira n'utilise que des **cookies strictement techniques** : aucune
mesure d'audience, aucun cookie tiers, donc aucun bandeau de consentement
n'est nécessaire. Les cookies préfixés `__Host-` sont posés par le serveur,
pour l'hôte seul, `Secure`, `HttpOnly`, `SameSite=Strict` (sauf le cookie du
flux de connexion, en `Lax`).

| Cookie | Rôle | Durée |
|---|---|---|
| `__Host-tt_deposit` | Session de dépôt après vérification de l'adresse | Validité de la session (4 heures par défaut) |
| `__Host-tt_known` | Reconnaissance d'une adresse déjà vérifiée | Jusqu'à 12 mois |
| `__Host-tt_dl` | Autorisation après saisie du bon mot de passe de transfert | 1 heure |
| `__Host-tt_rv` | Vérification d'un destinataire sur son lien | 1 heure |
| `__Host-tt_me` | Session « Mes envois » | 1 heure |
| `__Host-tt_admin` | Session d'administration | Inactivité de 30 min, maximum 12 h par défaut |
| `__Host-tt_oidc` | Flux d'authentification unique en cours | 10 minutes, usage unique |
| `tt_theme` | Thème clair ou sombre choisi par l'utilisateur (écrit par le navigateur, jamais lu par le serveur) | 1 an |

## 10. Droits des personnes

Les droits d'accès, de rectification, d'effacement, de limitation,
d'opposition et de portabilité sont traités par le responsable de traitement.
TransTeira fournit :

- **Recherche et effacement par adresse mail** : l'écran d'administration
  « Données personnelles » (guide de l'admin délégué, section
  [Données personnelles (RGPD)](../../user/fr/delegated-admin.md)). Un admin
  délégué recherche une adresse, voit un résumé des données qui lui sont liées
  dans l'entité, puis les efface. Effets : adresse vérifiée, codes et sessions
  supprimés ; transferts envoyés par l'adresse rendus illisibles puis
  supprimés ; adresse retirée des transferts reçus (un transfert resté sans
  destinataire est supprimé) ; invitations supprimées ou révoquées ; preuves
  nommant l'adresse supprimées ; adresse remplacée par un pseudonyme dans le
  journal d'audit (décision P19). L'effacement se termine par un rapport
  d'effacement, conservable comme élément de preuve.
- **Ce qui est conservé volontairement** : entrées de la liste de blocage,
  adresses des expéditeurs autorisés d'un jeton d'API (modifier le jeton),
  adresses IP des clients dans le journal d'audit jusqu'à la fin de leurs 12
  mois, mails déjà en file d'attente, et texte libre des transferts d'autres
  expéditeurs qui mentionne la personne (jusqu'à l'expiration de ce
  transfert). Détails : [guide d'administration](../../operations/admin.md).
- L'effacement est **par entité** : répétez-le dans chaque entité où la
  personne apparaît.
- Accès et portabilité : le responsable de traitement extrait les données
  trouvées par l'écran de recherche et le journal d'audit, car aucun service
  en libre accès n'existe pour les personnes concernées. `<à compléter>`
  (procédure interne et contact)

## 11. Effacement cryptographique et sauvegardes

À toute suppression (expiration, suppression manuelle, demande d'effacement),
TransTeira **détruit la clé de chaque fichier** en base avant de supprimer le
fichier (effacement cryptographique) : une copie du fichier chiffré qui
subsisterait est illisible depuis le système en production.

Limite à documenter : une copie de la base ou une sauvegarde de la VM prise
**pendant que le transfert existait** contient encore la clé chiffrée, et la
clé maître actuelle l'ouvre. Ses fichiers ne deviennent illisibles qu'après
une **rotation de la clé maître** et la **destruction de l'ancienne clé**,
une fois expirées toutes les sauvegardes antérieures à la rotation. Faites une
rotation au moins une fois par durée de conservation des sauvegardes ; un
transfert supprimé reste alors récupérable dans les sauvegardes pendant au plus
environ le double de cette durée
([clé maître](../../operations/master-key.md#crypto-erase),
[sauvegarde](../../operations/backup.md), décision P25). Indiquez la
conservation que vous appliquez : `<à compléter>`.

## 12. Mesures de sécurité (article 32)

Résumé ; la correspondance complète est dans le document
[ISO/IEC 27001 annexe A](iso27001-annex-a.md).

- **Cloisonnement des entités** : chaque enregistrement porte son entité ;
  filtrage dans la couche d'accès aux données et, avec PostgreSQL, row-level
  security (T-74 à T-79).
- **Chiffrement au repos** : AES-256-GCM par blocs, une clé par fichier
  chiffrée par la clé maître ; clé maître conservée hors du volume de données ;
  rotation sans réécriture des fichiers ; chiffrement de bout en bout optionnel
  dans le navigateur.
- **Chiffrement en transit** : TLS au niveau du reverse proxy (exploitant).
- **Contrôle d'accès** : administrateurs avec mot de passe argon2id et TOTP
  obligatoire pour le super admin ; OpenID Connect en option ; admins délégués
  limités à leurs entités ; rôle auditeur en lecture seule ; jetons d'API
  hachés, par entité, révocables.
- **Vérification d'identité** : code à usage unique par mail, avec limitation
  de débit ; vérification par destinataire en option.
- **Réseau** : aucun port publié par le conteneur, réseau Docker interne,
  proxys de confiance, plages IP par entité.
- **Analyse antivirus** de chaque fichier (ClamAV, moteur ICAP ou API HTTP).
- **Minimisation et masquage** : ni contenu de fichier ni adresse dans le
  journal de sécurité ; secrets hachés ou scellés, jamais journalisés ;
  déclarations sans IP.
- **Traçabilité** : journal d'audit, journal de sécurité (fail2ban et
  CrowdSec), export syslog, métriques.
- **Résilience** : copie nocturne de la base, restauration documentée.
- **Développement sécurisé** : tests, fuzzing, `govulncheck`, analyse des
  secrets, modèle de menaces ; images signées avec SBOM.

Mesures organisationnelles du responsable de traitement (politiques,
formation, contrats, sécurité physique de l'hôte) : `<à compléter>`

## 13. Analyse d'impact (AIPD)

Une analyse d'impact relative à la protection des données n'est pas
systématiquement requise pour ce traitement, mais le responsable de traitement
décide selon le volume et la sensibilité des données qu'il compte transférer
(par exemple des données de santé à grande échelle). Décision et référence :
`<à compléter>`. Le [modèle de menaces](../../security/threat-model.md) peut
alimenter l'analyse de risques.

## 14. Violations de données personnelles

Procédure du responsable de traitement pour notifier l'autorité de contrôle
sous 72 heures et, si nécessaire, les personnes concernées : `<à compléter>`.
TransTeira fournit le journal d'audit, le journal de sécurité, des alertes par
mail et webhook, et la [politique de sécurité](../../../SECURITY.md) pour le
signalement des vulnérabilités.
