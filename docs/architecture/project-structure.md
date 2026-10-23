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
│       └── rotate.go                # rotate-master-key : rotation reprenable, -abandon, -recover-from (auditée, acteur cli)
│
├── api/
│   ├── openapi.yaml                 # Spécification OpenAPI 3.1 (source de vérité)
│   ├── embed.go                     # Embarque la spécification (servie sur /api/openapi.yaml)
│   └── oapi-codegen.yaml            # Configuration de la génération de code
│
├── internal/
│   ├── app/                         # Assemblage des dépendances, cycle de vie, arrêt propre ; file des mails
│   │                                # système (systemmail.go, SMTP TT_SYSTEM_SMTP_*, sans liste d'exclusion)
│   ├── config/                      # Lecture et validation des variables d'environnement (TT_*)
│   ├── version/                     # Version SemVer injectée par -ldflags
│   │
│   ├── httpserver/                  # Serveur HTTP (net/http.ServeMux, motifs Go 1.22+), routage par hôte : hôte admin dédié
│   │                                # (admin.go, sans entité) ou FQDN d'entité (public / API), sinon 421
│   │   └── middleware/              # request-id, IP réelle (proxys de confiance), résolution du tenant,
│   │                                # en-têtes de sécurité / CSP, limitation de débit, limite de corps
│   │                                # et type JSON, récupération des panics, cookie de session de dépôt et CSRF
│   │                                # (jeton X-CSRF-Token, Origin, Sec-Fetch-Site), contexte du jeton d'API.
│   │                                # Mode maintenance et délais par opération : httpserver/ ; voie jeton d'API
│   │                                # (préséance du Bearer, verrouillage par IP) : apitoken.go ; page /api/docs
│   │                                # (CSP propre, accès admin par défaut) : docs.go
│   │                                # ; interface web (deux applications, CSP, cache, repli) : webui.go
│   ├── api/
│   │   ├── gen/                     # Code généré depuis openapi.yaml (ne pas modifier à la main)
│   │   ├── stubs/                   # Stubs générés (tools/genstubs) : chaque opération non écrite → 404
│   │   ├── public/                  # Handlers : meta, tenant public, sessions de dépôt, transferts, invitations, téléchargements
│   │   ├── admin/                   # Handlers : auth admin, tenants, opérations, système
│   │   └── problem/                 # Construction des réponses RFC 9457 et catalogue des codes d'erreur
│   │
│   ├── tenant/                      # Modèle Tenant, contexte (tenant.FromContext), résolution par Host
│   ├── netpolicy/                   # Règle « utilisateur interne » (§ 6.2), pure : IP dans une plage CIDR de l'entité
│   │                                # ET domaine de l'adresse parmi ses domaines internes ; réévaluée à chaque action
│   │                                # (session, confirmation, invitation, transfert). Les règles sont lues via store
│   ├── deposit/                     # Identification des déposants : éligibilité (blocage, invitation, règle interne),
│   │                                # codes de vérification, adresses vérifiées, cookie technique de reconnaissance
│   │                                # (__Host-tt_known), sessions de dépôt et CSRF, invitations (limite par invitant)
│   ├── transfer/                    # Création (éligibilité revérifiée, quota réservé sous verrou, destinataire imposé
│   │                                # pour un externe, idempotence), consultation, annulation, finalisation
│   ├── upload/                      # Moteur tus : verrou par fichier, flux chiffré + SHA-256, points de reprise scellés,
│   │                                # réinitialisation après crash, expiration
│   ├── filename/                    # Assainissement des noms de fichiers (P8) et noms uniques dans le ZIP
│   ├── textsafe/                    # Caractères qui masquent ou déguisent du texte (contrôle, bidi, invisibles) :
│   │                                # définition unique, retrait dans les messages, refus dans les noms (filename)
│   ├── download/                    # Accès par jeton, mot de passe et blocage, cookie de déverrouillage, fichier avec
│   │                                # Range, archive, suivi des plages servies et premier téléchargement
│   ├── zipstream/                   # Écrivain ZIP64 déterministe en mode store (taille exacte calculée d'avance)
│   ├── lifecycle/                   # Tâche périodique unique (§20, §23) : suppression après premier téléchargement,
│   │                                # expirations, uploads abandonnés, purge des lignes (transferts terminés depuis
│   │                                # 30 jours, codes, sessions, compteurs, adresses et invitations à 12 mois),
│   │                                # réconciliation des orphelins sur disque, copie nocturne SQLite (VACUUM INTO) ;
│   │                                # EraseTransfer (suppression admin ou RGPD, antivirus bloqué avant la destruction des clés)
│   ├── (blocklist → store)          # Liste de blocage (adresse, domaine, SHA-256) : pas de package dédié,
│   │                                # dépôt store/blocklist.go, gérée par tenantops, appliquée par deposit
│   │                                # (et transfer pour les empreintes)
│   ├── (réservations → transfer)    # Limite par envoi et réservation du quota sous verrou d'entité : transfer
│   ├── quota/                       # Alertes de quota 80 % / 100 % (niveau en base, hystérésis 75 % / 95 %, une alerte
│   │                                # par franchissement), destinataires, balayage toutes les 15 min
│   ├── adminauth/                   # Comptes admin, argon2id, TOTP, codes de secours, sessions, premier lancement
│   │                                # (couche d'authentification prévue pour accueillir un fournisseur OIDC en V2)
│   ├── (authz → adminauth)          # Rôles et périmètres dans adminauth/authz.go (super_admin, delegated_admin ; auditor en V2)
│   ├── apitoken/                    # Jetons d'API par entité : génération (tt_ + 256 bits), empreinte SHA-256,
│   │                                # plages autorisées, expiration optionnelle, révocation, administration auditée,
│   │                                # authentification dans la portée de l'entité, dernière utilisation (au plus 1/min)
│   ├── crypto/                      # Primitives pures : clé maître, enveloppe (DEK chiffrée par la clé maître),
│   │                                # format de fichier AES-256-GCM par blocs, points de reprise tus, clés MAC
│   │                                # dérivées, hachage des mots de passe argon2id (PHC, parallélisme borné)
│   ├── masterkey/                   # Trousseau (clé courante + nouvelle), contrôle au démarrage, rotation
│   │   │                            # reprenable, effacement cryptographique (table wrapped_keys)
│   │   └── masterkeytest/           # Clés maîtres et fichiers de clé pour les tests (hors seuils de couverture)
│   ├── storage/                     # Stockage des fichiers confiné par os.Root : un dossier par tenant, noms aléatoires,
│   │                                # points de reprise écrits de façon atomique
│   ├── antivirus/                   # Client clamd (PING, INSTREAM), verdicts, limite de taille ; antivirustest : faux clamd
│   ├── scan/                        # Worker d'analyse : file, balayage au démarrage, fail-closed, effacement des fichiers
│   │                                # infectés, lien de téléchargement, envoi des notifications, Hold (transfert
│   │                                # retiré de l'analyse pendant sa suppression)
│   ├── notify/                      # Construction des mails de transfert (QR code inline, empreintes, alertes expéditeur)
│   ├── mail/                        # SMTP par entité (sans chiffrement, STARTTLS, TLS), MIME, modèles FR/EN intégrés
│   │                                # (templates/, variables {{nom}} sans logique), surcharge par entité, file d'envoi
│   │   └── sanitize/                # Filtre HTML par liste blanche (modèles personnalisés, mentions légales)
│   ├── markup/                      # Markdown limité vers HTML filtré (mentions légales)
│   ├── branding/                    # Images d'habillage (détection, décodage borné, réencodage), contraste WCAG, fond par défaut
│   ├── tenantadmin/                 # Configuration des entités : droits, habillage, réseau, SMTP (test, DNS, garde SSRF),
│   │                                # modèles, mentions légales, suppression
│   ├── tenantops/                   # Opérations des entités : transferts (liste, détail, suppression, renvoi de la
│   │                                # notification), invitations (liste, révocation), liste de blocage, journal
│   │                                # d'audit de l'entité et journal global (super admin)
│   ├── events/                      # Bus d'événements interne (mail, journal de sécurité ; webhooks et syslog en V1.1)
│   ├── audit/                       # Rédacteur du journal d'audit (table audit_events, cloisonnée par tenant, purge à 12 mois),
│   │                                # garde-fou « aucune adresse dans les détails », caviardage des textes libres
│   ├── securitylog/                 # Journal de sécurité (format ligne stable pour fail2ban / CrowdSec)
│   ├── maintenance/                 # Mode maintenance : TT_MAINTENANCE (prioritaire) ou choix du super admin stocké
│   │                                # (system_settings, audité), messages par langue en texte brut, état atomique
│   ├── systemsettings/              # Réglages de l'instance (super admin) : seuil d'alerte disque, adresse d'alerte
│   │                                # supplémentaire ; config.updated audité avec les noms de champs seulement
│   ├── diskalert/                   # Alerte d'espace disque : mesure toutes les 5 min, niveau en base (compare-and-swap),
│   │                                # hystérésis de 5 points, mail disk_alert via le SMTP système, audit
│   ├── keyrotation/                 # Rotation de la clé maître lancée depuis l'administration : reconfirmation TOTP,
│   │                                # worker unique par instance, audit, état des clés (restartRequired)
│   ├── (backup → lifecycle)         # Copie SQLite dans lifecycle ; PostgreSQL : conteneur pg_dump dédié (compose)
│   ├── datasubject/                 # Droits des personnes (RGPD) : recherche et effacement des données d'une adresse
│   │                                # dans une entité, pseudonymisation de l'audit (anciennement prévu sous le nom gdpr/)
│   ├── stats/                       # Statistiques par entité et globales (agrégats quotidiens, espace disque)
│   ├── usage/                       # Compteurs d'activité par entité et par jour UTC, cumulés en mémoire et écrits
│   │                                # toutes les 30 s (table tenant_daily_stats, sans donnée personnelle)
│   ├── diskusage/                   # Taille et espace libre du système de fichiers des données (statfs / Windows)
│   ├── i18n/                        # Négociation de langue (Accept-Language), catalogue de messages (locales/<langue>.json)
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
│   │   ├── depositor.go             # store.Depositor (adresse, type, invitation) : l'identité d'un déposant partagée
│   │                                # par transfer (Sender) et upload (Principal), et sa règle de propriété (Owns)
│   │   ├── migrations/
│   │   │   ├── sqlite/              # 0001_init.sql, … (versionnées, appliquées au démarrage)
│   │   │   └── postgres/            # Mêmes versions ; ENABLE + FORCE ROW LEVEL SECURITY
│   │   └── storetest/               # Moteurs de test (SQLite + PostgreSQL) pour les suites communes
│   │
│   └── testutil/                    # Fabriques de données, horloge simulée, SMTP de test, clamd simulé
│
├── (traductions et modèles côté serveur) # Pas de dossier racine : traductions des pages et erreurs du serveur dans
│                                    # internal/i18n/locales/<langue>.json, modèles de mails par défaut dans
│                                    # internal/mail/templates/<langue>/ ; traductions de l'interface dans
│                                    # web/src/locales/<langue>/<zone>.json
│
├── web/                             # Interface web : deux applications Svelte 5 statiques construites par Vite,
│   │                                # consommant exclusivement l'API (/api/v1) ; voir web/README.md
│   ├── embed.go                     # Package web : embarque web/dist (Dist() fs.FS) ; embed_test.go
│   ├── package.json                 # Une seule dépendance d'exécution (svelte), versions exactes, Node 24 / npm 11
│   ├── package-lock.json            # Versionné ; installation par npm ci --ignore-scripts (T-159)
│   ├── .npmrc                       # save-exact, engine-strict, ignore-scripts
│   ├── vite.config.ts               # Deux entrées (public, admin), assets empreintés, aucun data: ni polyfill en ligne
│   ├── svelte.config.js, tsconfig.json, eslint.config.js, .prettierrc, vitest.config.ts
│   ├── src/                         # Racine Vite
│   │   ├── public/                  # Application publique (FQDN d'entité) : index.html, main.ts, App.svelte,
│   │   │                            # routes, écrans (dépôt avec vérification par code, invitation,
│   │   │                            # téléchargement, mentions légales, erreurs, maintenance)
│   │   ├── admin/                   # Application d'administration (hôte admin, sous /admin/) : coquille en V1 étape 15
│   │   ├── help/                    # Réservé à l'aide intégrée (générée depuis docs/user, étape 17)
│   │   ├── shared/
│   │   │   ├── api/                 # schema.ts (généré depuis api/openapi.yaml, versionné), client typé,
│   │   │   │                        # lecture des Problem Details, jeton CSRF en mémoire
│   │   │   ├── router/              # Routeur History API (titre, focus, annonce à chaque navigation)
│   │   │   ├── i18n/                # Traductions, choix de la langue (localStorage tt.lang), pluriels, formats
│   │   │   ├── upload/              # Moteur tus 1.0.0 (reprise, relances, transport XHR, reprise après rechargement)
│   │   │   ├── theme/               # Couleurs de l'entité (validées puis écrites par le CSSOM), contraste WCAG
│   │   │   ├── safe/                # safeApiHref : filtre des URL reçues de l'API
│   │   │   └── components/          # Composants accessibles (RGAA) partagés par les deux applications
│   │   ├── styles/                  # tokens.css (variables de thème, clair en V1, sombre prêt pour la V1.1),
│   │   │                            # base.css, layout.css, utilities.css
│   │   └── locales/                 # <langue>/<zone>.json (fr, en), montés sous le nom de la zone
│   │                                # (upload.json : clés upload.*)
│   ├── static/                      # Copiés tels quels à la racine de dist/ : favicon.svg, robots.txt (Disallow: /)
│   ├── scripts/                     # gen-types.mjs (types de l'API, --check), check-dist.mjs (conformité du build
│   │                                # à la CSP), keep-dist.mjs (recrée dist/.gitkeep)
│   ├── dev/Caddyfile                # Boucle de développement : *.localhost en HTTPS (écoute sur la boucle locale seulement), /api vers Go, reste vers Vite
│   ├── apidocs/                     # Documentation interactive /api/docs : Scalar vendorisé (version épinglée,
│   │                                # empreinte dans README.md), index.html et init.js sans script en ligne, embed.go
│   └── dist/                        # Résultat de la compilation (public/index.html, admin/index.html, assets/) ;
│                                    # seul dist/.gitkeep est versionné (build absent : page de repli 503)
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
│   │   ├── caddy/                   # Configuration de référence (prévue : encode, caviardage de /d/ et /i/, § 3.5)
│   │   ├── nginx/
│   │   ├── traefik/
│   │   └── apache/
│   ├── fail2ban/                    # filter.d, jail.d, action sur la chaîne DOCKER-USER
│   └── crowdsec/                    # Parser, scénario, mention du bouncer Caddy
│                                    # (V1.1 : grafana/, zabbix/)
│
├── docs/
│   ├── api/                         # integration.md (jetons, dépôt tus, scripts bash/curl et PowerShell), errors.md
│   ├── user/
│   │   ├── embed.go                 # Source de l'aide intégrée
│   │   ├── fr/                      # deposant.md, destinataire.md, admin-delegue.md, super-admin.md
│   │   ├── en/                      # depositor.md, recipient.md, delegated-admin.md, super-admin.md
│   │   └── screenshots/             # Générées par Playwright (ne pas modifier à la main)
│   ├── install/                     # Docker, reverse proxy, SMTP (dont relais vers Microsoft 365), première installation
│   ├── operations/                  # admin.md (administration, jetons d'API), tenants.md, antivirus.md,
│   │                                # backup.md, master-key.md (clé maître, rotation, y compris depuis
│   │                                # l'administration), security-log.md ; maintenance, réglages système,
│   │                                # alerte disque et SMTP système dans admin.md
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

### 3.5 Interface web (§4, §13, §16.2)

Les deux applications sont construites par `make web-build` dans `web/dist`, embarquées par `web/embed.go` et chargées en mémoire au démarrage (`internal/httpserver/webui.go`). Seuls les fichiers d'extension autorisée (`.js`, `.css`, `.svg`, `.png`, `.ico`, `.txt`) sont servis.

| Hôte | Chemin | Réponse | `Cache-Control` |
|---|---|---|---|
| FQDN d'entité | `/assets/<nom>` (fichiers empreintés) | fichier, ou `404` Problem si inconnu | `public, max-age=31536000, immutable` |
| FQDN d'entité | `/favicon.svg`, `/robots.txt` (racine du build) | fichier, ETag et `304` | `no-cache` |
| FQDN d'entité | `/`, `/d/{jeton}`, `/i/{jeton}`, `/legal/{document}`, `/invite`, `/help/…` | page de l'application publique, `200`, ETag et `304` | `no-cache` |
| FQDN d'entité | tout autre chemin hors `/api` | page de l'application publique avec le statut `404` (écran « page introuvable ») | `no-cache` |
| Hôte admin | `/` | `302` vers `/admin/` | `no-store` |
| Hôte admin | `/admin/`, `/admin/…` | page de l'application d'administration, `200` | `no-store` |
| Hôte admin | `/assets/<nom>` | fichier | `public, max-age=31536000, immutable` |
| Hôte admin | tout autre chemin hors `/api` | page d'administration avec le statut `404` | `no-store` |
| Les deux | `/api`, `/api/…` sans route | `404` Problem (jamais une page de l'interface) | |
| Les deux | méthode autre que `GET` / `HEAD` | `405` Problem, `Allow: GET, HEAD` | |
| Hôte inconnu | tout | `421` (aucun fichier de l'interface) | |

- **CSP** posée sur chaque réponse de l'interface : application publique `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` ; administration identique avec `img-src 'self' data:` (QR code TOTP). Règles pour les contributeurs (aucun style ni script en ligne, `{@html}` réservé aux mentions légales, `safeApiHref`) : `web/README.md` et modèle de menaces T-91.
- **`X-Robots-Tag: noindex, nofollow`** sur toutes les réponses de l'interface, `Referrer-Policy: no-referrer` et `X-Frame-Options: DENY` par le middleware d'en-têtes (T-161, T-94).
- **L'application d'administration n'est jamais servie sur un FQDN d'entité**, ni l'application publique sur l'hôte admin.
- **Repli** : un binaire construit sans `make web-build` (seul `dist/.gitkeep` présent) répond `503` avec une page statique bilingue, sans script ni style, et journalise un avertissement au démarrage ; `make build` refuse de produire un binaire sans l'interface.
- **Aucune compression par l'application** : elle est confiée au reverse proxy.

**Prévu pour les configurations de reverse proxy** (`integrations/reverse-proxy/`, à venir) :

- **compression** des fichiers de l'interface par le proxy (Caddy : directive `encode zstd gzip`, limitée aux types textuels (HTML, JavaScript, CSS, SVG, JSON) : les envois tus, les fichiers téléchargés et les archives ne sont ni compressés ni mis en tampon) ;
- **caviardage des jetons dans les journaux d'accès** : les chemins `/d/{jeton}` et `/i/{jeton}` (et `/api/v1/downloads/{jeton}/…`, `/api/v1/invitations/{jeton}`) ne doivent pas apparaître en clair dans les journaux du proxy (Caddy : filtre `log` → `format filter` sur `request.uri`, par exemple avec `regexp`, ou exclusion de ces chemins ; équivalents Nginx, Traefik et Apache) (T-161).

## 4. Décisions

| Sujet | Choix | Statut |
|---|---|---|
| Interface web | **Svelte compilé avec Vite**, sortie statique embarquée dans le binaire | Décidé le 2026-10-19 |
| Documentation interactive de l'API | **Scalar**, vendorisé dans `web/apidocs/`, sans CDN | Décidé le 2026-10-19 |
| Génération de code | `oapi-codegen` (strict server) côté Go, client TypeScript généré pour le front | Proposé par défaut |
| Hôte de l'administration | Hôte dédié obligatoire (`TT_ADMIN_HOSTS`), jamais un FQDN d'entité ; l'administration n'est servie que là, l'API publique jamais | Décidé le 2026-10-21 |
