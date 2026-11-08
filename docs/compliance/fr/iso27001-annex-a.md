# Correspondance ISO/IEC 27001:2022 annexe A

Correspondance entre les 93 mesures de l'**annexe A de l'ISO/IEC 27001:2022**
et **TransTeira 2.0**, pour aider à construire la déclaration d'applicabilité
(DdA) et à préparer les audits.

English: [docs/compliance/iso27001-annex-a.md](../iso27001-annex-a.md).

> Ceci est un modèle, pas un avis juridique ni une certification. Il indique ce
> que fournit le logiciel ; l'inclusion d'une mesure dans votre DdA, sa
> justification et les preuves vous appartiennent. Voir l'[avertissement](README.md).

## Lire les tableaux

| Statut | Signification |
|---|---|
| **Couverte** | TransTeira fournit la mesure à lui seul. L'exploitant n'a rien de plus à faire que d'installer le logiciel et de le tenir à jour. |
| **Partagée** | TransTeira fournit un mécanisme que l'exploitant doit **configurer ou faire fonctionner** (réglages, clés, hébergement, supervision, procédures). |
| **Exploitant** | Hors du logiciel : organisation, personnes, locaux, hôte, fournisseurs. TransTeira peut aider à la marge ; la note le dit. |

Références : les `T-xxx` sont des menaces et les `Pxx` des décisions du
[modèle de menaces](../../security/threat-model.md) ; les autres références sont
des documents de ce dépôt (en anglais, sauf mention contraire).

Une organisation qui exploite TransTeira n'hérite pas de ces statuts pour le
reste de son système d'information : la correspondance ne couvre que le
**service de transfert de fichiers**.

## Synthèse des mesures technologiques

| Besoin | Mécanisme | Mesures |
|---|---|---|
| Cloisonnement entre entités | Entité dans chaque enregistrement, filtrage dans la couche d'accès aux données, row-level security PostgreSQL | 8.3 |
| Authentification | argon2id, TOTP obligatoire pour le super admin, OpenID Connect, limitation de débit et verrouillages | 8.2, 8.5 |
| Chiffrement | AES-256-GCM par blocs, chiffrement d'enveloppe, rotation de la clé maître, bout en bout en option | 8.24 |
| Détection et traçabilité | Journal d'audit, journal de sécurité, syslog, métriques, alertes | 8.15, 8.16 |
| Programmes malveillants | ClamAV, moteur ICAP ou API HTTP | 8.7 |
| Suppression | Expiration, effacement cryptographique, écran d'effacement | 8.10 |
| Développement et livraison sécurisés | `make check`, versions signées avec SBOM | 8.8, 8.25 à 8.29, 8.32 |

## 5. Mesures organisationnelles (5.1 à 5.37)

| N° | Mesure | Statut | Mécanisme et note | Référence |
|---|---|---|---|---|
| 5.1 | Politiques de sécurité de l'information | Exploitant | Vos politiques. La politique de sécurité du projet ne couvre que le signalement des vulnérabilités. | [SECURITY.md](../../../SECURITY.md) |
| 5.2 | Fonctions et responsabilités liées à la sécurité de l'information | Partagée | Rôles définis dans le logiciel : super admin, admin délégué, auditeur (lecture seule). Y affecter les personnes vous appartient. | [Guide d'administration](../../operations/admin.md) ; P55 |
| 5.3 | Séparation des tâches | Partagée | Le super admin (instance, clés, entités) est distinct des admins délégués (leurs entités) et de l'auditeur, qui ne peut rien modifier. Les admins délégués ne lisent jamais le contenu des fichiers. | P18, P55 ; T-281 à T-285 |
| 5.4 | Responsabilités de la direction | Exploitant | | |
| 5.5 | Contact avec les autorités | Exploitant | | |
| 5.6 | Contact avec des groupes de travail spécialisés | Exploitant | | |
| 5.7 | Renseignements sur les menaces | Partagée | La vérification des mises à jour informe le super admin des nouvelles versions ; `govulncheck` dans les contrôles du projet. Vous suivez les avis du projet. | [SECURITY.md](../../../SECURITY.md) ; T-244 à T-248 |
| 5.8 | Sécurité de l'information dans la gestion de projet | Exploitant | Vos propres projets. Le projet lui-même s'appuie sur un modèle de menaces revu à chaque version. | [Modèle de menaces](../../security/threat-model.md) |
| 5.9 | Inventaire des informations et autres actifs associés | Partagée | Le modèle de menaces liste les actifs du service (section 2) ; le SBOM de chaque version liste les composants logiciels. Votre inventaire vous appartient. | [Modèle de menaces](../../security/threat-model.md) section 2 ; [installation Docker](../../install/docker.md#published-signed-image-alternative-to-building) |
| 5.10 | Utilisation correcte des informations et autres actifs associés | Partagée | Mentions légales et politique de confidentialité par entité, niveaux de confidentialité et restriction des domaines destinataires appliquent vos règles. Les règles sont les vôtres. | [Entités](../../operations/tenants.md) ; T-194 à T-198 |
| 5.11 | Restitution des actifs | Exploitant | | |
| 5.12 | Classification des informations | Partagée | Niveaux de confidentialité par entité, avec des libellés et des valeurs par défaut modifiables, chaque niveau imposant ses règles (mot de passe, durée, vérification du destinataire, domaines destinataires). Le choix du schéma vous appartient. | [Guide de l'admin délégué](../../user/fr/delegated-admin.md) ; T-194 à T-198 |
| 5.13 | Marquage des informations | Partagée | Le niveau apparaît dans les mails de notification, sur la page de téléchargement et dans le journal d'audit. | [Guide de l'admin délégué](../../user/fr/delegated-admin.md) ; P40 |
| 5.14 | Transfert des informations | Couverte | C'est l'objet du produit : chiffrement au repos, liens expirants, mot de passe optionnel, vérification du destinataire, chiffrement de bout en bout optionnel, empreintes, antivirus. Le TLS en transit est assuré par votre reverse proxy ; les règles de transfert et les accords avec les tiers vous appartiennent. | [Guide du déposant](../../user/fr/depositor.md) ; T-47 à T-57, T-199 à T-206, T-318 à T-327 |
| 5.15 | Contrôle d'accès | Couverte | Dépôt seulement depuis les réseaux et domaines internes des entités, ou par invitation, lien de dépôt ou réponse ; administration par rôle et par entité ; jetons d'API par entité. | T-16 à T-20, T-58 à T-73, T-212 à T-215 |
| 5.16 | Gestion des identités | Partagée | Les comptes d'administrateurs sont créés à l'avance par le super admin, jamais par une connexion ; les identités SSO sont épinglées (émetteur, sujet). Les utilisateurs publics sont identifiés par une adresse vérifiée, sans compte. Les processus d'arrivée et de départ vous appartiennent (désactiver le compte, retirer le lien SSO). | [Authentification unique](../../operations/fr/sso.md) ; T-286 à T-297, P57, P58 |
| 5.17 | Informations d'authentification | Partagée | Mots de passe hachés en argon2id, secrets TOTP scellés par la clé maître, codes de secours et jetons d'API stockés hachés, liens d'activation à usage unique. La politique de mots de passe et leur remise vous appartiennent. | T-58 à T-67, T-68 à T-73 ; P12, P13 |
| 5.18 | Droits d'accès | Partagée | Rôles et périmètre par entité ; admins délégués limités à leurs entités ; le super admin rattache et détache les admins. La revue périodique des droits vous appartient (liste des administrateurs dans l'administration). | [Guide d'administration](../../operations/admin.md) ; T-146 à T-150 |
| 5.19 | Sécurité de l'information dans les relations avec les fournisseurs | Exploitant | Hébergement, relais SMTP, fournisseur d'identité, moteur antivirus. | [Registre RGPD](gdpr-processing-record.md) section 7 |
| 5.20 | La sécurité de l'information dans les accords conclus avec les fournisseurs | Exploitant | | |
| 5.21 | Gestion de la sécurité de l'information dans la chaîne d'approvisionnement TIC | Partagée | Images signées et SBOM pour vérifier ce que vous exécutez ; dépendances analysées par `govulncheck` ; menaces de la chaîne de construction publiées. | [Installation Docker](../../install/docker.md#published-signed-image-alternative-to-building) ; T-117 à T-122, T-332 à T-335 |
| 5.22 | Surveillance, révision et gestion des changements des services fournisseurs | Exploitant | | |
| 5.23 | Sécurité de l'information dans l'utilisation de services en nuage | Exploitant | TransTeira est auto-hébergé. Si vous l'hébergez chez un fournisseur de cloud, ou utilisez un relais SMTP ou un fournisseur d'identité en nuage, les mesures sont les vôtres ; les fichiers restent chiffrés avec une clé hors du volume de données. | [Clé maître](../../operations/master-key.md) |
| 5.24 | Planification et préparation de la gestion des incidents de sécurité de l'information | Exploitant | Votre procédure. TransTeira fournit les entrées de détection (voir 5.25). | [Registre RGPD](gdpr-processing-record.md) section 14 |
| 5.25 | Appréciation des événements de sécurité de l'information et prise de décision | Partagée | Entrées : journal d'audit, journal de sécurité, signalements d'abus, alertes par mail et webhook. L'appréciation vous appartient. | [Journal de sécurité](../../operations/security-log.md) ; T-216 à T-221 |
| 5.26 | Réponse aux incidents de sécurité de l'information | Exploitant | Outils : listes de blocage, révocation de jetons et de liens, suppression de transferts, effacement, mode maintenance, rotation de la clé maître. | [Guide d'administration](../../operations/admin.md) |
| 5.27 | Tirer des enseignements des incidents de sécurité de l'information | Exploitant | | |
| 5.28 | Collecte de preuves | Partagée | Journal d'audit non modifiable par l'application (12 mois) ; preuves de dépôt et de remise signées (Ed25519, vérifiables hors ligne, conservées 12 mois) ; envoi des journaux vers un SIEM. La conservation au-delà et la chaîne de custodie vous appartiennent. | [Preuves](../../operations/fr/proofs.md) ; [syslog](../../operations/syslog.md) ; T-298 à T-303, T-187 à T-190 |
| 5.29 | Sécurité de l'information pendant une perturbation | Partagée | Health check, mode maintenance, restauration documentée. Les plans vous appartiennent. | [Sauvegarde](../../operations/backup.md) ; [supervision](../../operations/supervision.md) ; T-105 à T-107 |
| 5.30 | Préparation des TIC pour la continuité d'activité | Exploitant | Voir 8.13 et 8.14. | [Sauvegarde](../../operations/backup.md) |
| 5.31 | Exigences légales, statutaires, réglementaires et contractuelles | Partagée | Ce kit et les propositions de mentions légales et de politique de confidentialité par entité. Le registre des exigences vous appartient. | [Registre RGPD](gdpr-processing-record.md) |
| 5.32 | Droits de propriété intellectuelle | Partagée | Licence AGPL-3.0 ; le SBOM liste les dépendances et leurs composants. Respecter l'AGPL si vous modifiez le logiciel vous appartient. | [LICENSE](../../../LICENSE) |
| 5.33 | Protection des enregistrements | Partagée | Journaux d'audit, de sécurité et preuves conservés 12 mois avec des mesures d'intégrité ; sauvegardes de la base. La rotation des fichiers de journaux et les archives vous appartiennent. | [Journal de sécurité](../../operations/security-log.md) ; T-99 à T-104 |
| 5.34 | Vie privée et protection des DCP | Partagée | Minimisation, conservation et purge, cookies strictement techniques, effacement par adresse, effacement cryptographique. Le registre, la base légale et le DPO vous appartiennent. | [Registre RGPD](gdpr-processing-record.md) ; P19, P60 |
| 5.35 | Révision indépendante de la sécurité de l'information | Exploitant | Le modèle de menaces et le code source sont publics et peuvent alimenter une revue. | [Modèle de menaces](../../security/threat-model.md) |
| 5.36 | Conformité aux politiques, règles et normes de sécurité de l'information | Exploitant | Le rôle auditeur en lecture seule et le journal d'audit facilitent les contrôles. | T-281 à T-285 |
| 5.37 | Procédures d'exploitation documentées | Partagée | Guides d'installation, d'exploitation, de mise à jour, de sauvegarde, de rotation des clés et de publication dans `docs/`. Vos procédures locales vous appartiennent. | [Installation Docker](../../install/fr/docker.md) ; [mise à jour](../../operations/upgrade.md) |

## 6. Mesures liées aux personnes (6.1 à 6.8)

| N° | Mesure | Statut | Mécanisme et note | Référence |
|---|---|---|---|---|
| 6.1 | Sélection des candidats | Exploitant | | |
| 6.2 | Conditions générales d'embauche | Exploitant | | |
| 6.3 | Sensibilisation, apprentissage et formation à la sécurité de l'information | Exploitant | Guides utilisateur et admin par profil, aide intégrée à l'application, support de formation. | [Guides utilisateur](../../user/README.md) |
| 6.4 | Processus disciplinaire | Exploitant | | |
| 6.5 | Responsabilités après la fin ou le changement d'un emploi | Exploitant | Désactiver le compte d'administrateur, révoquer les jetons d'API qu'il a créés. | [Guide d'administration](../../operations/admin.md) |
| 6.6 | Accords de confidentialité ou de non-divulgation | Exploitant | | |
| 6.7 | Travail à distance | Partagée | Le dépôt depuis l'extérieur du réseau de l'entité est refusé par défaut ; le mode optionnel pour les internes vérifiés exige un code à chaque dépôt et est signalé dans le journal d'audit et la détection des abus. | T-212 à T-215 ; P35 |
| 6.8 | Déclaration des événements de sécurité de l'information | Partagée | Le bouton « Signaler un abus » de la page de téléchargement alerte l'admin délégué ; la politique de sécurité indique comment signaler une vulnérabilité. Les canaux de signalement internes vous appartiennent. | [SECURITY.md](../../../SECURITY.md) ; T-216 à T-221 |

## 7. Mesures physiques (7.1 à 7.14)

Toutes les mesures physiques concernent les locaux et l'hôte et relèvent de
l'exploitant. Les lignes avec une note sont les seules sur lesquelles le
logiciel agit.

| N° | Mesure | Statut | Mécanisme et note | Référence |
|---|---|---|---|---|
| 7.1 | Périmètres de sécurité physique | Exploitant | | |
| 7.2 | Les entrées physiques | Exploitant | | |
| 7.3 | Sécurisation des bureaux, des salles et des équipements | Exploitant | | |
| 7.4 | Surveillance de la sécurité physique | Exploitant | | |
| 7.5 | Protection contre les menaces physiques et environnementales | Exploitant | | |
| 7.6 | Travail dans les zones sécurisées | Exploitant | | |
| 7.7 | Bureau propre et écran vide | Exploitant | La session d'administration prend fin après un délai d'inactivité (30 minutes par défaut). | [Guide d'administration](../../operations/admin.md) |
| 7.8 | Emplacement et protection du matériel | Exploitant | | |
| 7.9 | Sécurité des actifs hors des locaux | Exploitant | | |
| 7.10 | Supports de stockage | Partagée | Les fichiers et les clés sont chiffrés sur le volume de données, et la clé maître est conservée en dehors. La manipulation des supports vous appartient. | [Clé maître](../../operations/master-key.md) ; T-28 à T-40 |
| 7.11 | Services supports | Exploitant | | |
| 7.12 | Sécurité du câblage | Exploitant | | |
| 7.13 | Maintenance du matériel | Exploitant | | |
| 7.14 | Mise au rebut ou recyclage sécurisé du matériel | Partagée | Les fichiers étant chiffrés et les clés détruites à la suppression, détruire la clé maître et la base rend le volume de données illisible. L'effacement des supports vous appartient. | [Clé maître](../../operations/master-key.md#crypto-erase) |

## 8. Mesures technologiques (8.1 à 8.34)

| N° | Mesure | Statut | Mécanisme et note | Référence |
|---|---|---|---|---|
| 8.1 | Terminaux finaux des utilisateurs | Exploitant | L'application ne stocke rien dans le navigateur en dehors des cookies techniques ; le client en ligne de commande garde son jeton dans une variable d'environnement ou un fichier que vous protégez. | [Client en ligne de commande](../../api/cli.md) ; T-328 à T-331, T-337 |
| 8.2 | Droits d'accès privilégiés | Couverte | Les actions qui concernent toute l'instance (entités, quotas, clés, SSO, maintenance, jetons de provisionnement) sont réservées au super admin, dont le TOTP est obligatoire ; la création d'un jeton de provisionnement redemande le code TOTP ; l'auditeur est en lecture seule. | T-58 à T-67, T-154 à T-158, T-267 à T-276, T-281 à T-285 ; P49, P55 |
| 8.3 | Restriction d'accès aux informations | Couverte | Chaque enregistrement porte son entité ; filtrage dans la couche d'accès aux données, qui exige l'entité de la requête ; row-level security PostgreSQL en seconde couche ; dossier distinct par entité sur disque, noms de fichiers aléatoires ; les admins voient les métadonnées, jamais le contenu. Testé avec une couverture de 100 % et pour chaque endpoint. | T-01 à T-04, T-74 à T-79 ; P18 |
| 8.4 | Accès au code source | Partagée | Le code source est public (AGPL). La protection de votre propre fork et des secrets qu'il contient vous appartient ; le projet analyse les secrets avant chaque envoi. | T-117 à T-122 |
| 8.5 | Authentification sécurisée | Couverte | argon2id, TOTP obligatoire pour le super admin (recommandé pour tous), codes de secours, sessions opaques côté serveur dans des cookies `__Host-`, protection CSRF, délais d'inactivité et absolu, limitation de débit et verrouillage des connexions, OpenID Connect avec PKCE (client confidentiel, option `enforced`). Codes à usage unique par mail pour les utilisateurs publics, limités en tentatives et en débit. | [Guide d'administration](../../operations/admin.md) ; [SSO](../../operations/fr/sso.md) ; T-58 à T-67, T-286 à T-297, T-09 à T-15 ; P1, P2 |
| 8.6 | Dimensionnement | Partagée | Quota de stockage par entité, alertes à 80 % et à saturation, alerte d'espace disque au super admin (85 % par défaut, modifiable), limites d'envoi et de débit, métriques Prometheus. Le dimensionnement de l'hôte vous appartient. | [Supervision](../../operations/supervision.md) ; [entités](../../operations/tenants.md) ; T-123 à T-128 |
| 8.7 | Protection contre les programmes malveillants | Partagée | Chaque fichier est analysé avant de pouvoir être téléchargé (ClamAV par défaut, moteurs ICAP ou API HTTP), un virus entraîne la suppression du fichier, un moteur indisponible bloque le fichier (fail-closed), les fichiers trop gros pour être analysés et les fichiers chiffrés de bout en bout sont signalés au destinataire. La mise à jour des signatures et la protection de l'hôte vous appartiennent. | [Antivirus](../../operations/antivirus.md) ; T-41 à T-46, T-236 à T-243 ; P10, P43, P66 |
| 8.8 | Gestion des vulnérabilités techniques | Partagée | `govulncheck` et contrôle des dépendances dans `make check` du projet ; signalement privé des vulnérabilités ; SBOM de chaque version ; information du super admin sur les mises à jour. Appliquer les mises à jour et patcher l'hôte, Docker et ClamAV vous appartient. | [SECURITY.md](../../../SECURITY.md) ; [mise à jour](../../operations/upgrade.md) ; T-244 à T-248, T-117 à T-122 |
| 8.9 | Gestion de la configuration | Partagée | Réglages d'installation en variables d'environnement (documentées dans `.env.example`), réglages des entités en base, validés au démarrage ; conteneur durci (non root, système de fichiers en lecture seule, aucune capability) ; export et import de la configuration d'une entité sans secrets. Garder la configuration sous gestion de versions vous appartient. | [`.env.example`](../../../.env.example) ; [installation Docker](../../install/fr/docker.md) ; T-304 à T-308 ; P24 |
| 8.10 | Suppression d'informations | Couverte | Purge automatique à l'expiration, après le premier téléchargement ou au nombre maximal de téléchargements ; destruction des clés des fichiers (effacement cryptographique) ; purge des données échues ; effacement par adresse mail. Les copies présentes dans les sauvegardes ne deviennent illisibles qu'après une rotation de la clé maître et la destruction de l'ancienne clé. | [Clé maître](../../operations/master-key.md#crypto-erase) ; T-108 à T-112 ; P19, P25 |
| 8.11 | Masquage des données | Couverte | Mots de passe et secrets hachés ou scellés par la clé maître et jamais journalisés ; aucune adresse mail dans le journal de sécurité ; pseudonyme dans le journal d'audit après un effacement ; déclarations sans adresse IP ; charge minimale des webhooks. | T-99 à T-104 ; P19, P31 |
| 8.12 | Prévention de la fuite de données | Partagée | Seuils de détection des abus par expéditeur et par entité (volume, nombre, destinataires, hors des heures de bureau), liste de blocage (adresses, domaines, SHA-256), listes de domaines destinataires autorisés et interdits, niveaux de confidentialité, quotas de dépôt des externes, alertes. Les seuils et règles sont à régler par vous ; TransTeira n'inspecte pas le contenu des fichiers. | [Guide de l'admin délégué](../../user/fr/delegated-admin.md) ; T-194 à T-198, T-216 à T-221 |
| 8.13 | Sauvegarde des informations | Partagée | Copie nocturne cohérente de la base (`VACUUM INTO` pour SQLite, `pg_dump` pour PostgreSQL) dans le volume de sauvegarde ; restauration documentée. La sauvegarde de la VM et des volumes, la clé maître dans un coffre hors de la VM et les tests de restauration vous appartiennent. | [Sauvegarde](../../operations/backup.md) ; [clé maître](../../operations/master-key.md) ; T-113 à T-116 |
| 8.14 | Redondance des moyens de traitement de l'information | Exploitant | Une seule instance applicative par base, par conception. La haute disponibilité de l'hôte, des volumes et de PostgreSQL vous appartient. | [Sauvegarde](../../operations/backup.md) |
| 8.15 | Journalisation | Couverte | Journal d'audit (acteur, IP, action, objet, par entité, 12 mois, non modifiable) et journal de sécurité dédié au format stable (fail2ban et CrowdSec), copié en base ; export syslog (RFC 5424). La centralisation et la conservation longue vous appartiennent. | [Guide d'administration](../../operations/admin.md#audit-log) ; [journal de sécurité](../../operations/security-log.md) ; [syslog](../../operations/syslog.md) ; T-99 à T-104, T-187 à T-190 ; P22, P41 |
| 8.16 | Activités de surveillance | Partagée | Health check `/healthz`, métriques Prometheus et `/status` JSON (protégés par jeton), modèles Grafana et Zabbix, journal de sécurité avec fail2ban ou CrowdSec, alertes d'abus, de quota et d'espace disque par mail et webhook. Faire fonctionner la supervision et réagir vous appartient. | [Supervision](../../operations/supervision.md) ; [journal de sécurité](../../operations/security-log.md) ; T-191 à T-193, T-178 à T-186 ; P28 |
| 8.17 | Synchronisation des horloges | Exploitant | Synchronisation de l'heure (NTP) de l'hôte. Les codes, sessions et journaux reposent sur l'horloge de l'hôte. | |
| 8.18 | Utilisation de programmes utilitaires à privilèges | Exploitant | Les commandes d'administration `transteira` (récupération de compte, rotation de clé, sauvegarde) s'exécutent sur l'hôte avec ses droits d'accès ; restreignez cet accès. | [Guide d'administration](../../operations/admin.md) ; [clé maître](../../operations/master-key.md) |
| 8.19 | Installation de logiciels sur des systèmes opérationnels | Partagée | Image multi-architecture signée et tags Git signés, attestation SBOM, image `FROM scratch` ; la vérification de la signature et l'épinglage par empreinte sont décrits. Faire la vérification à chaque mise à jour vous appartient. | [Installation Docker, section 5](../../install/docker.md#published-signed-image-alternative-to-building) ; [publication](../../operations/release.md) ; T-332 à T-335, P67 |
| 8.20 | Sécurité des réseaux | Partagée | Le conteneur ne publie aucun port ; le proxy et l'application sont sur un réseau partagé, l'antivirus et la base sur un réseau interne ; proxys de confiance pour l'IP réelle du client ; plages IP par entité ; noms d'hôte inconnus refusés et journalisés ; en-têtes de sécurité et CSP stricte. Le pare-feu, les règles `DOCKER-USER` et le proxy vous appartiennent. | [Reverse proxy](../../install/reverse-proxy.md) ; [installation Docker](../../install/fr/docker.md) ; T-05 à T-08, T-172 à T-177 ; P24 |
| 8.21 | Sécurité des services réseau | Partagée | Configurations de référence de proxys (Caddy, Nginx, Traefik, Apache) avec délais, sans mise en tampon et transmission de l'IP réelle ; TLS vérifié pour le SSO, syslog, les webhooks et les moteurs antivirus distants. Les certificats TLS et HSTS relèvent du proxy. | [Reverse proxy](../../install/reverse-proxy.md) ; P30, P41, P45, P59 |
| 8.22 | Cloisonnement des réseaux | Partagée | Réseau Docker interne pour ClamAV et PostgreSQL, invisible du proxy ; gardes de sortie contre les requêtes vers les réseaux internes pour les webhooks et le SSO, et liste d'exclusion optionnelle pour les hôtes SMTP qu'un admin peut saisir. Le zonage réseau autour de l'hôte vous appartient. | [Installation Docker](../../install/fr/docker.md) ; T-133 à T-136 ; P21, P30, P59 |
| 8.23 | Filtrage web | Exploitant | Sans objet pour le service. Ses connexions sortantes se limitent à celles que vous configurez (SMTP, webhooks, SSO, vérification des mises à jour). | T-133 à T-136 ; T-245 |
| 8.24 | Utilisation de la cryptographie | Couverte | AES-256-GCM par blocs avec une clé par fichier (chiffrement d'enveloppe), clé maître hors du volume de données, rotation sans réécriture des fichiers, effacement cryptographique, chiffrement de bout en bout optionnel dans le navigateur, preuves signées Ed25519, versions signées. La garde de la clé (copie en coffre) et le TLS au proxy vous appartiennent. | [Clé maître](../../operations/master-key.md) ; [format E2E](../../architecture/e2e-format.md) ; T-28 à T-40, T-318 à T-327, T-298 à T-303 ; P7, P13, P61, P65 |
| 8.25 | Cycle de vie de développement sécurisé | Couverte | API first (OpenAPI), modèle de menaces mis à jour à chaque version, relecture de chaque étape, tests avant chaque commit, le tout lancé en local par une seule commande. | [Modèle de menaces](../../security/threat-model.md) ; T-117 à T-122 |
| 8.26 | Exigences de sécurité des applications | Couverte | Exigences dans le cahier des charges et dans le modèle de menaces (par composant, avec les mesures) ; des tests de contrat vérifient l'API par rapport à sa spécification OpenAPI. | [Modèle de menaces](../../security/threat-model.md) sections 6 et 9 |
| 8.27 | Principes d'ingénierie et d'architecture des systèmes sécurisés | Couverte | Cloisonnement des entités à la couche la plus basse, antivirus fail-closed, données minimales, moindre privilège (rôles, rôle de base de données sans `BYPASSRLS`), image minimale. | [Modèle de menaces](../../security/threat-model.md) ; [PostgreSQL](../../install/postgresql.md) ; P24 |
| 8.28 | Codage sécurisé | Couverte | Décodage strict des entrées, sorties échappées, CSP stricte, linters, `go vet`, fuzzing natif Go sur les entrées utilisateur. | T-91 à T-98, T-160 à T-170 |
| 8.29 | Tests de sécurité dans le développement et l'acceptation | Couverte | Tests unitaires, d'intégration, de contrat, de cloisonnement et de bout en bout sur SQLite et PostgreSQL, fuzzing, `govulncheck`, analyse des secrets (gitleaks, hook pre-push), seuils de couverture (85 % global, 100 % pour le cloisonnement, le chiffrement et l'authentification), test de gros fichier à travers un vrai reverse proxy. | [Modèle de menaces](../../security/threat-model.md) section 9 |
| 8.30 | Développement externalisé | Exploitant | S'applique si vous commandez des modifications spécifiques ; le projet est développé en ouvert sous AGPL. | |
| 8.31 | Séparation des environnements de développement, de test et de production | Partagée | Le projet teste avec des entités fictives locales (`*.localhost`) et un récepteur de mails. Séparer votre production des instances de test vous appartient. | |
| 8.32 | Gestion des changements | Partagée | Versionnement sémantique, CHANGELOG, tags Git signés et images signées avec SBOM, guides de mise à jour et de retour arrière, migrations de schéma automatiques testées sur les deux moteurs. Votre propre validation des mises à jour vous appartient. | [Mise à jour](../../operations/upgrade.md) ; [publication](../../operations/release.md) ; [CHANGELOG](../../../CHANGELOG.md) ; T-332 à T-335 |
| 8.33 | Informations de test | Couverte | Les tests utilisent des données générées et fictives (domaines en `example.com`), jamais des données de production. | |
| 8.34 | Protection des systèmes d'information pendant les tests d'audit | Exploitant | Le rôle auditeur en lecture seule et le journal d'audit permettent à un audit de lire sans modifier. Le périmètre et le calendrier des tests d'intrusion vous appartiennent. | T-281 à T-285 ; P55 |
