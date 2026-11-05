# Authentification unique (OpenID Connect)

Depuis la 2.0, les admins délégués et les auditeurs d'une entité peuvent se
connecter à l'administration avec le fournisseur d'identité de leur
organisation (Microsoft Entra ID, Keycloak, tout fournisseur OpenID Connect) à
la place d'un mot de passe local et du TOTP. Le fournisseur se configure **par
entité**, par le **super admin** seulement. L'authentification unique ne
concerne que **l'interface d'administration** : les jetons d'API, les liens de
dépôt et les pages publiques ne changent pas
([guide de l'API](../../api/integration.md)).

English: [docs/operations/sso.md](../sso.md).

- Variables : `TT_SSO_USE_PROXY`, `TT_SSO_ALLOW_NETWORKS`, voir `.env.example`.
  Tout le reste (émetteur, identifiant client, secret client, domaines, options)
  est stocké par entité et se gère dans l'administration.
- Opérations : `getTenantSso`, `putTenantSso`, `deleteTenantSso`,
  `testTenantSso`, `startAdminOidcLogin`, `completeAdminOidcLogin`,
  `getAdminAuthMethods`, `deleteAdminIdentity` (`api/openapi.yaml`).
- Modèle de menaces : T-286 à T-297 (section 6.48), décisions P57 à P59 dans
  `docs/security/threat-model.md`.

## Fonctionnement

- **Flux :** code d'autorisation avec PKCE (S256), `state` et `nonce` ;
  TransTeira est un **client confidentiel** (le secret client est envoyé au
  point de terminaison du jeton, en TLS vérifié). Le contexte du flux est
  gardé dans un cookie technique signé de l'hôte d'administration, valable 10
  minutes et à usage unique.
- **URI de redirection** à déclarer chez le fournisseur, sur **l'hôte
  d'administration** (`TT_ADMIN_HOSTS`) :

  ```text
  https://admin.example.com/api/v1/admin/auth/oidc/callback
  ```

- **Le super admin n'utilise jamais l'authentification unique.** Le compte
  local avec mot de passe et TOTP reste disponible quelle que soit la
  configuration : c'est lui qui permet de corriger ou de désactiver
  l'authentification unique d'une entité.
- **Les comptes sont créés à l'avance** par le super admin. Aucun compte n'est
  créé par une connexion. Un compte inconnu, d'une autre entité ou désactivé
  est refusé.
- **Le second facteur est délégué au fournisseur** (`requireMfa`, activé par
  défaut) : la connexion n'est acceptée que si le jeton d'identité prouve
  qu'une authentification multifacteur a eu lieu (`amr` contenant `mfa`).
- **Portée de la session.** Une session SSO n'ouvre que les entités du compte
  dont la configuration d'authentification unique est activée **avec le même
  émetteur et le même identifiant client** que la connexion, et dont
  `requireMfa` est satisfait par cette connexion. Toute autre entité du compte
  répond `404 not-found` à cette session. Une connexion locale par mot de passe
  ouvre les entités qui n'imposent pas l'authentification unique.

## Microsoft Entra ID

### 1. Inscrire l'application

Dans le centre d'administration Entra (ou le portail Azure) de l'annuaire de
l'organisation :

1. **Inscriptions d'applications > Nouvelle inscription**. Nom : par exemple
   `TransTeira entité A`. Types de comptes pris en charge : **Comptes dans cet
   annuaire d'organisation uniquement (locataire unique)**.
2. **URI de redirection** : plateforme **Web**, valeur
   `https://admin.example.com/api/v1/admin/auth/oidc/callback` (votre hôte
   d'administration), saisie exactement, sans barre oblique finale.
3. Sur la page **Vue d'ensemble**, noter l'**ID d'application (client)** et
   l'**ID de l'annuaire (locataire)**.
4. **Certificats et secrets > Nouveau secret client** : copier la **valeur**
   (affichée une seule fois) et noter sa date d'expiration : le secret doit être
   renouvelé dans TransTeira avant (voir
   [Renouveler le secret](#renouveler-le-secret)).
5. **Autorisations d'API** : la permission déléguée `User.Read` par défaut
   suffit. TransTeira ne demande que les portées `openid`, `profile` et `email`.

### 2. Émetteur : propre à l'annuaire, jamais `common`

L'émetteur à saisir dans TransTeira est :

```text
https://login.microsoftonline.com/<id-annuaire>/v2.0
```

TransTeira **refuse** les points de terminaison multi-annuaires `common`,
`organizations` et `consumers` (`422 sso-issuer-not-allowed`) : ils acceptent
les utilisateurs de n'importe quel annuaire Entra, et un jeton pourrait être
émis pour un annuaire étranger.

### 3. Ajouter la revendication facultative `amr` (nécessaire à `requireMfa`)

Les jetons d'identité **v2 d'Entra ID ne portent la revendication `amr` que si
elle est demandée** comme revendication facultative. Sans elle, TransTeira ne
voit jamais `mfa` et toute connexion échoue avec `sso-mfa-required` (motif
`mfa_missing` au journal de sécurité).

1. Dans l'application : **Configuration des jetons > Ajouter une revendication
   facultative**.
2. Type de jeton **ID**, revendication **`amr`**, puis **Ajouter** (accepter
   l'invite d'activation de la permission Microsoft Graph si elle s'affiche).

Équivalent dans le **manifeste** :

```json
"optionalClaims": {
  "idToken": [
    { "name": "amr", "source": null, "essential": false, "additionalProperties": [] }
  ]
}
```

### 4. Exiger le MFA par l'accès conditionnel

La revendication `amr` ne fait que **rapporter** ce qui s'est passé ; c'est
Entra qui doit **faire** l'authentification multifacteur. Créer une stratégie
d'**accès conditionnel** :

- **Ressources cibles :** l'application TransTeira (la choisir par son nom).
- **Utilisateurs :** les admins délégués et les auditeurs (un groupe est
  pratique).
- **Octroi :** *Exiger l'authentification multifacteur* (ou une force
  d'authentification).

Un utilisateur dont la session valide a déjà satisfait le MFA obtient `mfa`
dans `amr` sans nouvelle invite : c'est normal.

### 5. Ce qu'envoie Entra et comment le compte est reconnu

À la première connexion, TransTeira rapproche le compte d'une **adresse mail
vérifiée** : la revendication `email` avec `email_verified: true` ou, pour un
émetteur Entra propre à un annuaire, `preferred_username` (le nom d'utilisateur
principal, unique dans l'annuaire). Entra n'inclut pas toujours `email_verified`
ni `email`, d'où l'acceptation de `preferred_username` pour ce type d'émetteur.
L'adresse doit correspondre à celle du compte créé à l'avance, et son domaine
doit être l'un des domaines SSO de l'entité.

## Fournisseur générique (Keycloak et autres)

Tout fournisseur qui gère la découverte OpenID Connect
(`<émetteur>/.well-known/openid-configuration`), le flux par code
d'autorisation avec PKCE S256 et des jetons d'identité signés (RS256, PS256 ou
ES256) convient. Exemple avec Keycloak (realm `corp`) :

1. **Clients > Créer un client** : type **OpenID Connect**, identifiant
   `transteira-entity-a`, **Client authentication : On** (confidentiel),
   **Standard flow** seulement (désactiver l'accès direct et le flux
   implicite).
2. **Valid redirect URIs** :
   `https://admin.example.com/api/v1/admin/auth/oidc/callback`.
   **Advanced > Proof Key for Code Exchange Code Challenge Method :** `S256`.
3. **Credentials** : copier le **Client secret**.
4. Émetteur : `https://sso.example.com/realms/corp`, exactement l'`issuer` du
   document de découverte.
5. Les utilisateurs doivent avoir une adresse mail vérifiée (`email` et
   `email_verified: true`) : à la première connexion, TransTeira accepte le jeton mais la connexion échoue (`account_unknown`).
6. Pour `requireMfa`, le jeton doit porter `amr` contenant `mfa`. Dans Keycloak,
   ajouter au client un mappeur **Authentication Method Reference** (ou exiger
   un flux à deux facteurs) pour que `amr` soit émis ; si votre fournisseur ne
   peut pas l'affirmer, désactivez `requireMfa` pour cette entité et imposez le
   MFA chez le fournisseur, sachant que TransTeira ne peut alors pas le vérifier.

Le fournisseur doit être joignable en **HTTPS** depuis le conteneur TransTeira.
Un fournisseur sur un réseau privé demande
[`TT_SSO_ALLOW_NETWORKS`](#proxy-et-réseaux-privés).

## Configurer une entité dans TransTeira

Réservé au **super admin**. Les admins délégués et les auditeurs peuvent lire la
configuration (le secret n'est jamais renvoyé : seulement `hasClientSecret`).

Dans l'administration, ouvrir l'entité, puis **Authentification unique**.
Champs :

| Champ | Signification |
|---|---|
| Activer l'authentification unique | Active ou coupe la connexion pour l'entité. |
| Émetteur | URL `https` du fournisseur. Entra : propre à l'annuaire (voir plus haut). |
| Identifiant client | ID d'application (client). |
| Secret client | En écriture seule. Obligatoire la première fois et chaque fois que l'émetteur ou l'identifiant client change ; sinon le laisser vide conserve le secret stocké. Scellé par la clé maître comme le mot de passe SMTP et couvert par la [rotation de la clé maître](master-key.md). |
| Domaines de messagerie | Domaines dirigés vers le fournisseur de cette entité. Chacun doit être l'un des **domaines de messagerie internes** de l'entité et n'appartient qu'à **une entité** sur toute l'instance (`409 sso-domain-conflict` sinon). |
| Imposer l'authentification unique (`enforced`) | Refuse la connexion locale par mot de passe aux admins délégués et auditeurs rattachés à l'entité. Désactivé par défaut. |
| Exiger le MFA (`requireMfa`) | Le jeton d'identité doit prouver l'authentification multifacteur. Activé par défaut. |

Utilisez **Tester** avant d'activer : TransTeira récupère le document de
découverte de l'émetteur et vérifie qu'il porte le même émetteur et les points
de terminaison nécessaires. Le test ne connecte personne et n'envoie jamais le
secret client ; ses échecs sont rapportés par catégorie (`dns_error`,
`connect_error`, `tls_error`, `timeout`, `http_status`, `invalid_document`,
`issuer_mismatch`, `missing_endpoint`).

Par l'API (session du super admin, jeton CSRF) :

```sh
curl -sS -X PUT https://admin.example.com/api/v1/admin/tenants/$TENANT_ID/sso \
  -H "Cookie: $SESSION_COOKIE" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{
    "enabled": true,
    "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
    "clientId": "7f3c9a10-0000-4000-8000-00000000c0de",
    "clientSecret": "client-secret-from-the-provider",
    "emailDomains": ["entity-a.example.com"],
    "enforced": false,
    "requireMfa": true
  }'
```

Chaque modification est auditée (`tenant.sso_updated`, noms des membres
modifiés, jamais le secret) ; la suppression par `tenant.sso_deleted`.

### Modifier ou supprimer la configuration

- **Changer l'émetteur ou l'identifiant client** **révoque les sessions SSO**
  de l'entité et **désépingle les identités** épinglées pour l'ancien couple
  (émetteur, identifiant client), sauf si une autre entité du même compte
  utilise encore ce couple. Un nouveau secret client est alors exigé : un secret
  stocké n'est jamais reporté sur une autre application.
- **Désactiver ou supprimer** la configuration **révoque les sessions SSO** de
  l'entité mais **conserve les identités épinglées**. Elles sont inutilisables
  tant qu'une configuration avec le même couple (émetteur, identifiant client)
  n'est pas revenue ; elles refonctionnent alors sans nouvelle première
  connexion.
- Les comptes créés sans lien d'activation (SSO seul) ne peuvent plus se
  connecter tant que la configuration n'est pas rétablie.

### Renouveler le secret

Créer un second secret chez le fournisseur, faire un **PUT** de la configuration
avec le nouveau `clientSecret` (même émetteur et même identifiant client), puis
supprimer l'ancien secret chez le fournisseur. Un secret expiré fait échouer
toute connexion à l'échange du jeton (`issuer_error`).

## Comptes

### Comptes SSO seul

À la création d'un admin délégué ou d'un auditeur, le super admin peut choisir
la remise **`none`** (**Authentification unique uniquement, sans lien d'activation**) : le compte n'a **aucun mot de
passe** et ne peut se connecter que par l'authentification unique. Cela exige
que **toutes les entités du compte aient leur authentification unique
activée** (`409 sso-not-configured` sinon). Impossible pour un super admin. La
liste des administrateurs indique ces comptes (`ssoOnly`).

Les autres remises (`mail`, `copy`) créent un compte normal qui peut utiliser
les deux voies, sauf si `enforced` est activé.

### Première connexion et épinglage

1. La personne saisit son adresse mail sur la page de connexion ; si son domaine
   est dirigé vers une entité dotée de l'authentification unique, la page
   propose **Se connecter avec l'authentification unique**
   (`POST /admin/auth/oidc/start`, puis redirection vers le fournisseur). Un
   domaine sans authentification unique reçoit `404 sso-not-available`,
   identique à un domaine inconnu.
2. Chez le fournisseur, la personne s'authentifie (MFA si exigé).
3. À la **première** connexion, TransTeira rapproche le compte par l'adresse
   mail vérifiée (voir plus haut) et **épingle l'identité** sur (émetteur,
   identifiant client, subject) : audit `admin.identity_linked`.
4. Aux connexions suivantes, seul ce triplet compte. L'adresse n'est plus
   utilisée : une boîte renommée continue de fonctionner (changer l'adresse mail d'un compte dans TransTeira **désépingle** en revanche ses identités), et **un autre subject
   présentant la même adresse est refusé** (`identity_mismatch`). Chez Entra ID,
   le `sub` est propre à chaque application : la même personne a un subject
   différent dans une autre inscription, d'où l'identifiant client dans la clé.
5. Le rôle est contrôlé à **chaque** connexion : un compte promu super admin ne
   peut plus se connecter par l'authentification unique (ses identités épinglées
   sont supprimées).
6. Le second facteur d'une connexion par authentification unique relève du
   réglage **`requireMfa`** de l'entité. Le réglage local « TOTP obligatoire »
   du compte ne s'y applique pas.

### Désépingler une identité

Quand une personne change de compte chez le fournisseur (nouvel annuaire,
nouvel objet utilisateur), le super admin supprime l'identité épinglée :
**Administrateurs**, **Modifier** sur le compte, **Identités d'authentification unique épinglées**, **Désépingler**
(`DELETE /admin/admins/{adminId}/identities/{identityId}`, audit
`admin.identity_unlinked`, motif `unpinned`). Désépingler **révoque aussi les sessions ouvertes par cette identité**. À la connexion suivante, le compte est de nouveau
épinglé à l'identité qui correspond à son adresse mail. À faire seulement après
avoir vérifié que la nouvelle identité est bien celle de la même personne.

## Mode imposé et procédure de panne

Avec **`enforced`**, la connexion locale par mot de passe d'un admin délégué ou
d'un auditeur rattaché à l'entité est refusée par `403 sso-required`, **après**
la vérification du mot de passe et au même coût, pour que la réponse ne révèle
pas si le compte existe. Recommandé lorsque tout le monde s'est connecté au
moins une fois par l'authentification unique.

De plus, une **session par mot de passe** existante (ouverte par un lien
d'activation, ou avant l'activation du mode imposé) n'atteint plus les entités
où il est imposé : elles disparaissent de la liste des entités du compte jusqu'à
ce que la personne se connecte par l'authentification unique. Le super admin
n'est jamais concerné.

Un compte rattaché à **plusieurs** entités se voit refuser le mot de passe local
dès qu'**une seule** impose l'authentification unique.

**Si le fournisseur est en panne** (incident, secret client expiré, application
supprimée) et que les administrateurs sont bloqués :

1. Le **super admin** se connecte en local (mot de passe et TOTP : ce compte ne
   dépend jamais de l'authentification unique).
2. Ouvrir l'entité, **Authentification unique**, décocher **Imposer
   l'authentification unique**, enregistrer (audit `tenant.sso_updated`). Les
   admins délégués qui ont un mot de passe peuvent de nouveau se connecter en
   local immédiatement.
3. Les comptes SSO seul (`delivery: none`) n'ont pas de mot de passe et ne
   peuvent pas se connecter tant que le fournisseur n'est pas revenu.
4. Réparer le fournisseur (renouveler le secret, restaurer l'application),
   lancer le **test**, puis réactiver `enforced`.

Gardez les identifiants et les codes de secours du super admin accessibles hors
du fournisseur : ils sont le recours (voir [Administration](admin.md)).

## Proxy et réseaux privés

Le client OpenID Connect utilise la même garde de sortie que les webhooks
(`internal/netpolicy`) : HTTPS seul, adresse contrôlée **au moment de la
connexion** après une nouvelle résolution (pas de rebinding DNS), aucune
redirection suivie, délai court et corps bornés.

- **`TT_SSO_USE_PROXY`** (défaut `false`). Par défaut, le client ignore
  `HTTPS_PROXY` et se connecte directement. À `true`, il passe par le proxy du
  conteneur : la garde ne voit alors **que le proxy**, qui résout et joint
  lui-même le fournisseur. À n'activer que si le conteneur n'a pas d'accès direct
  à Internet, en restreignant les destinations au niveau du proxy.
- **`TT_SSO_ALLOW_NETWORKS`** (défaut vide). La liste de refus intégrée écarte
  les plages privées (RFC 1918, `100.64.0.0/10`, `fc00::/7`...). Pour un
  fournisseur **sur site** (ADFS, Keycloak) sur un réseau privé, indiquer son
  adresse ou le plus petit préfixe qui le contient, par exemple
  `TT_SSO_ALLOW_NETWORKS=10.20.30.0/28`. Le cœur de la liste de refus (adresses
  non spécifiées, lien-local et métadonnées des clouds, multicast, plages
  réservées, réseaux du conteneur) ne peut jamais être ouvert ; un tel préfixe
  arrête TransTeira au démarrage. Redémarrer après modification.

Les deux s'appliquent au document de découverte, aux clés de signature et au
point de terminaison du jeton. Le navigateur est redirigé vers
l'`authorization_endpoint`, dont on vérifie seulement qu'il est en `https` sans
identifiants.

## Dépannage

La page de connexion affiche volontairement un message générique pour la
plupart des échecs ; le motif figure au [journal de sécurité](security-log.md)
(événement `sso_failed`, champ `reason`) et au journal applicatif.

| Code sur la page | `reason` du journal de sécurité | Cause et remède |
|---|---|---|
| `sso-mfa-required` | `mfa_missing` | Le jeton d'identité n'a pas d'`amr` contenant `mfa`. Entra : ajouter la revendication facultative `amr` au jeton ID et exiger le MFA par l'accès conditionnel ; ou désactiver `requireMfa` en connaissance de cause. |
| `sso-not-available` | aucun | Le domaine n'a pas d'authentification unique activée, ou est inconnu (même réponse volontairement). Vérifier les domaines SSO de l'entité et son activation. |
| `invalid-credentials` | `state_invalid` | Cookie de flux absent, expiré (10 minutes) ou déjà utilisé ; onglet périmé, retour mis en favori, redémarrage de TransTeira pendant la connexion. Recommencer depuis la page de connexion. |
| `invalid-credentials` | `token_invalid` | Échec du jeton d'identité ou de l'échange du code : mauvais secret client (expiré ?), mauvais identifiant client, mauvaise URI de redirection, signature, `nonce`, audience ou expiration, ou jeton d'un autre annuaire Entra (`tid` différent de l'émetteur). Lancer le **test** ; vérifier l'URI de redirection exacte. |
| `invalid-credentials` | `account_unknown` | Aucun compte de cette entité ne correspond (non créé, adresse mail non vérifiée par le fournisseur (le jeton est accepté mais la première connexion échoue), invité B2B Entra (revendication `idp` différente de l'émetteur : refusé à la première liaison), désactivé, super admin, autre entité, adresse hors des domaines SSO, ou Entra sans `preferred_username`). Créer le compte d'abord. |
| `invalid-credentials` | `identity_mismatch` | Le compte est épinglé à un autre subject. Vérifier la personne, puis **désépingler** l'ancienne identité. |
| `invalid-credentials` | `issuer_error` | Le fournisseur est injoignable ou ses documents sont incorrects : DNS, TLS, réseau privé non ouvert (`TT_SSO_ALLOW_NETWORKS`), proxy, émetteur différent de celui du document de découverte. |
| `rate-limited` | (`rate_limited`) | Trop de tentatives depuis cette adresse ; patienter. |
| API `403 sso-required` | aucun | Mot de passe local refusé : l'entité impose l'authentification unique. |
| API `422 sso-issuer-not-allowed` | aucun | Pas en `https`, ou `common`, `organizations`, `consumers`. |
| API `409 sso-domain-conflict` | aucun | Le domaine est déjà dirigé vers une autre entité. |
| API `409 sso-not-configured` | aucun | `delivery: none` alors qu'une entité du compte n'a pas d'authentification unique activée. |
| API `400 validation-failed` (`not-internal-domain`) | aucun | Un domaine SSO n'est pas parmi les domaines de messagerie internes de l'entité (`/emailDomains/<n>`). |

Les codes d'erreur sont décrits dans le [catalogue des erreurs](../../api/errors.md).

## Notes de sécurité

- **Qui décide de qui se connecte, c'est le fournisseur de l'entité**,
  configuré par le seul super admin : un admin délégué ne peut pas choisir un
  émetteur. Un fournisseur compromis, ou un administrateur de l'annuaire Entra,
  peut émettre des jetons pour tout compte épinglé de l'entité et affirmer le
  MFA : c'est une confiance acceptée (modèle de menaces, H16). Limitez qui
  administre l'inscription de l'application et gardez l'accès conditionnel.
- Aucun compte n'est créé par une connexion ; le rôle est contrôlé à chaque
  connexion ; le super admin n'utilise jamais l'authentification unique.
- Le secret client est scellé par la clé maître, jamais renvoyé par l'API,
  jamais écrit dans les journaux, l'audit ni l'export de configuration.
- Les échecs de connexion sont écrits au journal de sécurité (`sso_failed`) et
  comptés par une jail fail2ban et un scénario CrowdSec distincts, avec un
  **seuil plus haut** que pour les mots de passe, un onglet périmé provoquant
  `state_invalid`
  ([fail2ban](../../../integrations/fail2ban/README.md),
  [CrowdSec](../../../integrations/crowdsec/README.md)).
- Actions d'audit : `admin.login` (`details.method` = `oidc`),
  `admin.identity_linked`, `admin.identity_unlinked`, `tenant.sso_updated`,
  `tenant.sso_deleted`.
- Le client OpenID Connect n'accepte que les signatures RS256, PS256 et ES256,
  lit les clés depuis le `jwks_uri` de l'émetteur sous la garde de sortie, et
  contrôle émetteur, audience, `nonce`, `exp`, `iat` et `nbf` (2 minutes de
  tolérance). Chez Entra, un jeton dont le `tid` ne correspond pas à l'émetteur
  est refusé, et un invité B2B (revendication `idp` différente de l'émetteur) ne
  peut pas être lié à la première connexion.
- `admin.identity_unlinked` porte `identity_id`, `issuer`, `client_id` et
  `reason` : `unpinned` (manuel), `promoted` (compte promu super admin),
  `sso_changed` (émetteur ou identifiant client modifié), `email_changed`
  (adresse mail du compte modifiée).
- Une requête de retour sans cookie de flux valide (par exemple une requête
  inter-sites) reçoit l'erreur générique mais n'est ni comptée ni journalisée :
  une page tierce ne peut pas faire bannir un administrateur. Démarrer
  l'authentification unique pour un domaine indisponible compte dans la limite
  par IP de la connexion admin (20 échecs en 15 minutes), ce qui freine le
  sondage de domaines.
