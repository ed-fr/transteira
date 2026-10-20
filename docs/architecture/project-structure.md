# TransTeira : arborescence du projet

> Livrable 2 de la section 27.1 du cahier des charges. Statut : **proposition à valider**.
> Module Go : `github.com/ed-fr/transteira`.

## 1. Principes d'organisation

- **Un seul binaire** (`cmd/transteira`) avec des sous-commandes : `serve`, `migrate`, `rotate-master-key`, `backup`, `healthcheck` (pour le `HEALTHCHECK` Docker d'une image `scratch` sans shell), `version`.
- **Tout le code applicatif est dans `internal/`** : rien n'est importable par des tiers, ce qui laisse l'API Go interne libre d'évoluer. Le futur client en ligne de commande (V2) vivra dans `cmd/transteira-cli` et consommera l'API HTTP, pas les packages internes.
- **Des packages par domaine** (transfer, invitation, download…), pas par couche technique. Chaque domaine expose un service et dépend d'interfaces de stockage. Ces packages indépendants peuvent être développés en parallèle, chacun par un sous-agent.
- **API first** : `api/openapi.yaml` est la source de vérité. Les types et l'interface serveur sont **générés** (`oapi-codegen`, mode *strict server*) dans `internal/api/gen`. Les handlers implémentent cette interface, si bien qu'un écart avec la spécification ne compile pas.
- **Ressources embarquées** (`go:embed`) : spécification OpenAPI, interface web compilée, documentation interactive de l'API, aide utilisateur, traductions, modèles de mails, migrations. Comme `go:embed` ne peut pas remonter dans l'arborescence, chaque dossier embarqué contient un petit fichier `embed.go`.
- **Tests à côté du code** (`*_test.go`, y compris les `Fuzz*`). Les tests qui traversent plusieurs packages (intégration, contrat, cloisonnement, bout en bout, gros fichier) sont dans `test/`.

## 2. Arborescence

```text
transteira/
├── cmd/
│   └── transteira/
│       ├── main.go                  # Sous-commandes : serve, migrate, rotate-master-key, backup, healthcheck, version
│       └── rotate.go                # rotate-master-key : rotation reprenable, -abandon, -recover-from
│
├── api/
│   ├── openapi.yaml                 # Spécification OpenAPI 3.1 (source de vérité)
│   ├── embed.go                     # Embarque la spécification (servie sur /api/openapi.yaml)
│   └── oapi-codegen.yaml            # Configuration de la génération de code
│
├── internal/
│   ├── app/                         # Assemblage des dépendances, cycle de vie, arrêt propre
│   ├── config/                      # Lecture et validation des variables d'environnement (TT_*)
│   ├── version/                     # Version SemVer injectée par -ldflags
│   │
│   ├── httpserver/                  # Serveur HTTP (net/http.ServeMux, motifs Go 1.22+), montage des espaces public / admin / API
│   │   └── middleware/              # request-id, IP réelle (proxys de confiance), résolution du tenant,
│   │                                # en-têtes de sécurité / CSP, limitation de débit, limite de corps
│   │                                # et type JSON, récupération des panics (CSRF : à venir).
│   │                                # Mode maintenance et délais par opération : httpserver/
│   ├── api/
│   │   ├── gen/                     # Code généré depuis openapi.yaml (ne pas modifier à la main)
│   │   ├── stubs/                   # Stubs générés (tools/genstubs) : chaque opération non écrite → 404
│   │   ├── public/                  # Handlers : meta, tenant public, sessions de dépôt, transferts, invitations, téléchargements
│   │   ├── admin/                   # Handlers : auth admin, tenants, opérations, système
│   │   └── problem/                 # Construction des réponses RFC 9457 et catalogue des codes d'erreur
│   │
│   ├── tenant/                      # Modèle Tenant, contexte (tenant.FromContext), résolution par Host
│   ├── netpolicy/                   # Plages CIDR, domaines internes, règle « utilisateur interne »
│   ├── identity/                    # Codes de vérification, adresses vérifiées, sessions de dépôt
│   ├── transfer/                    # Cycle de vie d'un transfert (uploading, scanning, available, expired…)
│   ├── upload/                      # Serveur tus (HEAD/PATCH/DELETE/OPTIONS), progression sur disque
│   ├── download/                    # Téléchargement unitaire (Range), ZIP64 en flux en mode store, mot de passe
│   ├── invitation/                  # Invitations externes
│   ├── blocklist/                   # Liste de blocage (adresse, domaine, SHA-256)
│   ├── quota/                       # Limite par envoi, quota par entité, réservations, seuils 80 % / 100 %
│   ├── adminauth/                   # Comptes admin, argon2id, TOTP, codes de secours, sessions, premier lancement
│   │                                # (couche d'authentification prévue pour accueillir un fournisseur OIDC en V2)
│   ├── authz/                       # Rôles et périmètres (super_admin, delegated_admin ; auditor en V2)
│   ├── apitoken/                    # Jetons d'API par entité (hachés, expiration optionnelle, révocation)
│   ├── crypto/                      # Primitives pures : clé maître, enveloppe (DEK chiffrée par la clé maître),
│   │                                # format de fichier AES-256-GCM par blocs, points de reprise tus
│   ├── masterkey/                   # Trousseau (clé courante + nouvelle), contrôle au démarrage, rotation
│   │   │                            # reprenable, effacement cryptographique (table wrapped_keys)
│   │   └── masterkeytest/           # Clés maîtres et fichiers de clé pour les tests (hors seuils de couverture)
│   ├── storage/                     # Stockage des fichiers : un dossier par tenant, noms aléatoires, écriture atomique
│   ├── antivirus/                   # Client clamd (INSTREAM), file d'analyse, gestion des fichiers trop gros
│   ├── notify/                      # Rendu des mails (modèles par entité et par langue), envoi SMTP, QR code CID
│   ├── events/                      # Bus d'événements interne (mail, journal de sécurité ; webhooks et syslog en V1.1)
│   ├── audit/                       # Journal d'audit (en base, cloisonné par tenant)
│   ├── securitylog/                 # Journal de sécurité (format ligne stable pour fail2ban / CrowdSec)
│   ├── maintenance/                 # État du mode maintenance (variable d'environnement + administration)
│   ├── cleanup/                     # Tâche périodique unique : expirations, uploads abandonnés, purges RGPD
│   ├── backup/                      # VACUUM INTO (SQLite) / pg_dump (PostgreSQL)
│   ├── gdpr/                        # Recherche et effacement des données d'une adresse
│   ├── stats/                       # Statistiques par entité et globales, espace disque
│   ├── i18n/                        # Négociation de langue, chargement des traductions
│   ├── ratelimit/                   # Paniers par clé et fenêtres de verrouillage (bornés, horloge injectable)
│   ├── health/                      # Vérifications /healthz (base, ClamAV, stockage)
│   ├── id/                          # Identifiants préfixés (ULID) et jetons à forte entropie
│   │
│   ├── store/                       # Couche d'accès aux données (database/sql, SQLite et PostgreSQL)
│   │   ├── query.go, lexer.go       # Registre des requêtes : tenantQuery (exactement un `tenant_id = ?`) / systemQuery (liste blanche)
│   │   ├── exec.go                  # Exécuteurs typés Scoped(tenant.ID) et System(raison), injection du tenant
│   │   ├── dialect.go               # Différences de moteur (placeholders, pragmas SQLite, set_config PostgreSQL)
│   │   ├── migrate.go               # Migrateur (checksum, verrou, refus d'une base plus récente)
│   │   ├── tenants.go, networkrules.go, blocklist.go, … # Dépôts ; chaque méthode à portée d'entité exige un tenant.ID
│   │   ├── migrations/
│   │   │   ├── sqlite/              # 0001_init.sql, … (versionnées, appliquées au démarrage)
│   │   │   └── postgres/            # Mêmes versions ; ENABLE + FORCE ROW LEVEL SECURITY
│   │   └── storetest/               # Moteurs de test (SQLite + PostgreSQL) pour les suites communes
│   │
│   └── testutil/                    # Fabriques de données, horloge simulée, SMTP de test, clamd simulé
│
├── locales/                         # Traductions côté serveur (pages, mails, erreurs)
│   ├── embed.go
│   ├── fr.json
│   └── en.json
│
├── templates/
│   └── email/                       # Modèles de mails par défaut
│       ├── embed.go
│       ├── fr/                      # verification-code.html / .txt / .subject, transfer-notification…, etc.
│       └── en/
│
├── web/                             # Interface web (consomme exclusivement l'API)
│   ├── embed.go                     # Embarque web/dist
│   ├── package.json
│   ├── src/
│   │   ├── public/                  # Dépôt, vérification par code, invitation, téléchargement
│   │   ├── admin/                   # Administration
│   │   ├── help/                    # Aide intégrée (générée depuis docs/user)
│   │   ├── shared/                  # Client API généré, i18n, composants accessibles (RGAA)
│   │   ├── styles/                  # Variables de thème CSS (clair en V1, sombre prêt pour la V1.1)
│   │   └── locales/                 # fr.json, en.json
│   ├── static/                      # Image de fond par défaut, favicon
│   ├── apidocs/                     # Documentation interactive de l'API (Scalar ou Redoc), vendorisée, sans CDN
│   └── dist/                        # Résultat de la compilation (ignoré par git)
│
├── test/
│   ├── integration/                 # Parcours complets contre un serveur réel (SQLite et PostgreSQL)
│   │   ├── masterkey_test.go        # Cycle de vie de la clé maître, effacement cryptographique, reprise chiffrée
│   │   └── recover_test.go          # Clés restées sous une clé retirée : refus au démarrage, -recover-from
│   ├── contract/                    # Validation de chaque requête / réponse contre openapi.yaml (kin-openapi)
│   ├── isolation/                   # Cloisonnement : chaque opération de la spécification est rejouée depuis un autre tenant
│   ├── e2e/                         # Playwright (navigateur réel) + génération des captures pour docs/user
│   ├── bigfile/                     # Test de 20 Go à travers Caddy, coupure et reprise, mémoire stable (tag de build)
│   ├── fixtures/                    # Données de test ; la signature EICAR est générée à l'exécution
│   └── docker-compose.test.yml      # Mailpit, ClamAV, PostgreSQL, Caddy, domaines *.localhost
│
├── deploy/
│   ├── docker-compose.yml           # Application + ClamAV, réseau interne + réseau externe « proxy »
│   ├── docker-compose.postgres.yml  # Surcharge ajoutant PostgreSQL
│   └── clamav/
│       └── clamd.conf               # Limites MaxFileSize / MaxScanSize / StreamMaxLength relevées
│
├── integrations/
│   ├── reverse-proxy/
│   │   ├── caddy/                   # Configuration de référence
│   │   ├── nginx/
│   │   ├── traefik/
│   │   └── apache/
│   ├── fail2ban/                    # filter.d, jail.d, action sur la chaîne DOCKER-USER
│   └── crowdsec/                    # Parser, scénario, mention du bouncer Caddy
│                                    # (V1.1 : grafana/, zabbix/)
│
├── docs/
│   ├── api/                         # Guide d'intégration : jetons, tus, exemples curl et PowerShell, errors.md
│   ├── user/
│   │   ├── embed.go                 # Source de l'aide intégrée
│   │   ├── fr/                      # deposant.md, destinataire.md, admin-delegue.md, super-admin.md
│   │   ├── en/                      # depositor.md, recipient.md, delegated-admin.md, super-admin.md
│   │   └── screenshots/             # Générées par Playwright (ne pas modifier à la main)
│   ├── install/                     # Docker, reverse proxy, SMTP (dont relais vers Microsoft 365), première installation
│   ├── operations/                  # master-key.md (clé maître, rotation), security-log.md ; à venir :
│   │                                # sauvegarde / restauration, maintenance
│   ├── security/
│   │   └── threat-model.md          # Modèle de menaces STRIDE
│   └── architecture/
│       └── project-structure.md     # Ce document
│
├── tools/
│   ├── covercheck/                  # Seuils de couverture (section 24.3), appelé par make cover
│   ├── envexample/                  # Génère .env.example depuis internal/config
│   └── genstubs/                    # Génère internal/api/stubs depuis l'interface du serveur
│
├── scripts/
│   ├── hooks/pre-push               # gitleaks avant chaque envoi vers GitHub
│   └── install-hooks.sh / .ps1
│
├── .claude/
│   ├── settings.json                # Commandes pré-autorisées
│   └── agents/                      # test-engineer, security-reviewer, code-reviewer
│
├── Dockerfile                       # Multi-étapes : web (node) → go build → image scratch
├── Makefile                         # make check, make test, make lint, make e2e, make bigfile, make generate…
├── .golangci.yml
├── .spectral.yaml                   # Lint OpenAPI : chaque opération décrite et accompagnée d'un exemple
├── .gitleaks.toml
├── .env.example
├── .gitignore / .dockerignore
├── go.mod / go.sum
├── LICENSE                          # AGPL-3.0
├── README.md
├── SECURITY.md
├── CHANGELOG.md
└── CLAUDE.md
```

## 3. Choix structurants

### 3.1 Cloisonnement au plus bas niveau (§5)

- Le tenant est résolu une seule fois par le middleware (en-tête `Host`) puis placé dans le contexte. `tenant.ID` est un **type dédié** qui ne s'obtient que par `tenant.FromContext` ou par le code d'administration, après contrôle du périmètre de l'admin.
- Chaque méthode de dépôt à portée d'entité dans `internal/store` prend un `tenant.ID` en **paramètre obligatoire**.
- Chaque requête SQL est déclarée dans un registre. Une `tenantQuery` doit contenir **exactement un** prédicat `tenant_id = ?` au premier niveau du `WHERE` (relié par `AND`), ou la colonne `tenant_id` d'un `INSERT`. Elle est validée au chargement du package, et l'exécuteur `Scoped` y injecte lui-même l'identifiant d'entité. Une `systemQuery` n'est exécutable que par l'exécuteur `System`, et la liste de ces requêtes est figée par un test. Les deux types sont distincts : le compilateur empêche de les mélanger.
- Avec PostgreSQL, chaque transaction exécute `set_config('app.tenant_id', …, true)`, limité à la transaction, et des politiques RLS (`ENABLE` + `FORCE ROW LEVEL SECURITY`) doublent le filtre. Deux rôles : un rôle propriétaire (`TT_DB_MIGRATE_DSN`) qui applique les migrations et accorde les droits, et un rôle d'exécution (`TT_DB_DSN`) qui ne possède rien. Au démarrage, `store.Verify` refuse tout rôle d'exécution dangereux (voir `docs/install/postgresql.md`). Sous SQLite, le registre de requêtes est la seule couche.
- `test/isolation` parcourt **toutes les opérations déclarées dans `openapi.yaml`** et vérifie qu'un appel depuis un autre tenant échoue. Un nouvel endpoint est donc couvert d'office.

### 3.2 Chiffrement (§16.1)

- `internal/crypto` ne dépend d'aucun autre package interne, ce qui permet de le tester isolément à 100 %.
- `internal/masterkey` regroupe ce qui touche la base (trousseau, contrôle au démarrage, rotation) et s'appuie sur `internal/crypto` et `internal/store`.
- Format de fichier sur disque (décision P7) : en-tête versionné de 16 octets (`TTEF`, version, taille de bloc, préfixe de nonce aléatoire de 7 octets), puis blocs AES-256-GCM. Nonce = préfixe | compteur 32 bits | octet « dernier bloc » ; données authentifiées = en-tête | tenant | identifiant de fichier. Le dernier bloc est toujours présent, ce qui empêche troncature et permutation. L'identifiant de la clé maître n'est pas dans le fichier mais sur la ligne `wrapped_keys` de la DEK, ce qui permet la rotation sans réécrire les fichiers. Spécification complète : GoDoc de `internal/crypto`.

### 3.3 Upload tus et base de données (§8.6, §17)

- `internal/upload` écrit la progression dans un fichier d'état à côté du fichier partiel. La base n'est touchée qu'à la création du transfert et à sa finalisation.

### 3.4 Tests sur les deux moteurs (§17, §24)

- `make test` lance chaque suite deux fois (`TT_DB_DRIVER=sqlite` puis `postgres`). PostgreSQL est fourni par `test/docker-compose.test.yml`.

## 4. Décisions

| Sujet | Choix | Statut |
|---|---|---|
| Interface web | **Svelte compilé avec Vite**, sortie statique embarquée dans le binaire | Décidé le 2026-10-19 |
| Documentation interactive de l'API | **Scalar**, vendorisé dans `web/apidocs/`, sans CDN | Décidé le 2026-10-19 |
| Génération de code | `oapi-codegen` (strict server) côté Go, client TypeScript généré pour le front | Proposé par défaut |
| Hôte de l'administration | Accessible depuis tout FQDN d'entité, liste restrictive optionnelle (`TT_ADMIN_HOSTS`) ; cookie de session admin propre à chaque hôte | Proposé par défaut |
