# Preuves de dépôt et de remise

Depuis la 2.0, TransTeira peut délivrer une **preuve** de deux faits d'un
transfert : les fichiers ont été déposés et mis à disposition, et ils ont été
téléchargés. Une preuve est un PDF **signé par l'instance**, que l'expéditeur,
un admin délégué, le super admin ou un auditeur peuvent conserver et, en cas de
litige, faire vérifier hors ligne par n'importe qui.

English: [docs/operations/proofs.md](../proofs.md).

- Commandes : `transteira proof verify`, `transteira proof keys`,
  `transteira proof retire-key`.
- Opérations : `getMyTransferProof`, `getTenantTransferProof`, `listProofKeys`
  (`api/openapi.yaml`, schéma `ProofStatement`).
- Actions d'audit : `transfer.proof_downloaded`, `proof_key.created`,
  `proof_key.retired`.
- Modèle de menaces : T-298 à T-303 (section 6.49), décision P61 dans
  `docs/security/threat-model.md`.
- Modèle de données : [docs/architecture/data-model-v2.md](../../architecture/data-model-v2.md), section 2.3.

## Ce qu'est une preuve

Le PDF d'une preuve contient une copie lisible d'une **déclaration** et, en
pièces jointes :

- `statement.json` : la déclaration en JSON canonique (RFC 8785), les octets
  exacts qui ont été signés (schéma `ProofStatement` : entité, transfert,
  expéditeur, destinataires, fichiers avec leur empreinte SHA-256, dates,
  identifiant de clé) ;
- `statement.sig` : la signature Ed25519 (64 octets) de ces octets.

**Seule la déclaration signée jointe fait foi.** Le texte visible du PDF n'est
qu'une aide à la lecture : n'importe quel outil PDF peut le modifier, ce qui
n'invalide que le texte visible, raison pour laquelle la vérification ne le lit
jamais. L'empreinte SHA-256 de la déclaration est aussi imprimée dans le PDF.

Il existe deux types :

| Type | Écrite | Atteste |
|---|---|---|
| Dépôt | À la fin de l'analyse antivirus, dans la même transaction que la mise à disposition du transfert | L'expéditeur a déposé ces fichiers (avec leur état d'analyse) pour ces destinataires. |
| Remise | Au premier téléchargement complet du transfert (global) et, pour les liens par destinataire, au premier téléchargement complet de chaque destinataire | Les fichiers ont été téléchargés une première fois, et quand (et par qui pour la preuve d'un destinataire). |

Les preuves sont **immuables** : une par fait, jamais modifiée. Un transfert
rejeté par l'antivirus n'a pas de preuve de dépôt. Pour un transfert chiffré de
bout en bout, les empreintes sont celles du chiffré et la déclaration le dit.

Les déclarations ne contiennent aucune adresse IP.

## Conservation et effacement

- Conservées **12 mois après leur création**, **même si le transfert est
  supprimé** (une preuve doit survivre aux fichiers dont elle parle). Purgées
  par la tâche de nettoyage.
- Effacées par l'**effacement des droits des personnes** (écran Données
  personnelles) quand la déclaration nomme l'adresse comme expéditeur,
  destinataire ou téléchargeur ; le rapport les compte (`proofsDeleted`, et
  `proofs` dans le résumé de la recherche).
- Supprimées avec l'entité.

## Qui obtient une preuve

| Qui | Où | Jusqu'à |
|---|---|---|
| L'expéditeur | « Mes envois », détail du transfert | Tant que le transfert existe |
| Admin délégué, super admin, auditeur | Administration, détail du transfert | 12 mois, même après la suppression du transfert |

Les destinataires ne téléchargent pas de preuve. Chaque téléchargement est
tracé dans le journal d'audit (`transfer.proof_downloaded`) et limité à **10 par
minute et par adresse cliente (rafale de 20)**, l'adresse étant une adresse IPv4 ou
un /64 IPv6, partagée entre les points d'accès de preuve de l'expéditeur et de
l'administration et entre les entités ; au-delà, `429`. Une preuve qui
n'existe pas encore (pas de téléchargement, pas de résultat d'analyse) ou dont
la conservation est dépassée répond `404 proof-not-available`
([erreurs](../../api/errors.md)).

## Vérifier une preuve

La vérification ne demande **ni base de données ni accès à l'instance** : le PDF
et les clés publiques suffisent. Utilisez le binaire `transteira` (le même que
celui du serveur, dans l'image ou une version publiée).

1. Récupérez les clés publiques de l'instance. Elles sont publiques, servies sur
   le FQDN de chaque entité et sur l'hôte d'administration, avec la même liste
   partout :

   ```bash
   curl -fsS https://transfer.example.com/api/v1/proof-keys > keys.json
   ```

   ```json
   {"items":[{"keyId":"psk_01JABCP1Q2R3S4T5V6W7X8Y9Z0","algorithm":"Ed25519",
     "publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
     "createdAt":"2026-11-04T09:00:00Z","retiredAt":null}]}
   ```

   Conservez ce fichier avec la preuve : il permet de vérifier plus tard, même
   si l'instance a disparu. `/proof-keys` répond aussi pendant qu'une entité est
   encore en configuration (il ne contient aucune donnée d'entité).

1. Vérifiez :

   ```bash
   transteira proof verify --keys keys.json preuve-depot.pdf
   # ou, en récupérant les clés lui-même en HTTPS :
   transteira proof verify --url https://transfer.example.com preuve-depot.pdf
   # résultat exploitable par un script :
   transteira proof verify --json --keys keys.json preuve-depot.pdf
   ```

   Donnez exactement l'un de `--keys` et `--url`. La commande vérifie la
   signature Ed25519 de `statement.json` avec la clé nommée dans la déclaration,
   puis affiche les champs **lus dans la déclaration vérifiée** (jamais dans le
   texte visible du PDF). Un code de sortie 0 signifie « vérifiée ». Tout échec
   (déclaration modifiée, clé inconnue, PDF mal formé) affiche `FAILED` avec le
   motif et sort avec un code non nul.

   Le texte vu dans un lecteur PDF est **informatif seulement**. Ne vous fiez
   qu'à la sortie de `transteira proof verify` (champs lus dans la déclaration
   vérifiée) ou à sa sortie `--json`. La commande n'accepte que la structure PDF
   exacte écrite par TransTeira : un PDF modifié ou mis à jour de façon
   incrémentale est rejeté.

1. Comparez ce qui est affiché (transfert, expéditeur, destinataires, fichiers
   et empreintes, dates) aux faits en litige. Pour contrôler un fichier que vous
   détenez, calculez son SHA-256 et comparez-le à l'empreinte de la déclaration.

Une preuve dont le fait est **postérieur** au retrait de sa clé de signature est
rejetée : voir ci-dessous.

## Clés de signature

- Une **clé Ed25519 active** pour toute l'instance, créée automatiquement à
  l'écriture de la première preuve (audit `proof_key.created`). Son identifiant
  commence par `psk_` et est signé dans chaque déclaration.
- La **partie privée** est stockée en base, **scellée par la clé maître** comme
  les autres secrets de l'instance : la [rotation de la clé
  maître](../master-key.md) la couvre, elle n'est jamais exportée, journalisée
  ni renvoyée par l'API. Elle est distincte de la clé qui signe l'image.
- Les **clés publiques**, actives et retirées, sont publiées sur
  `https://<fqdn de l'entité>/api/v1/proof-keys` (et sur l'hôte d'administration)
  et ne sont **jamais retirées** de la liste : elles doivent vérifier les
  anciennes preuves.

Lister les clés de l'instance (demande la configuration de l'instance, à lancer
dans le conteneur) :

```bash
docker compose exec transteira transteira proof keys
```

### Retirer la clé

Il n'y a pas d'écran d'administration : le retrait est une **commande
délibérée** sur l'hôte.

Quand retirer :

- **Compromission suspectée** de la base (ou d'une sauvegarde) **avec la clé
  maître** : qui détient les deux peut signer des preuves. Retirez la clé tout de
  suite, puis faites une rotation de la clé maître ([procédure](../master-key.md)). Faites
  les deux : le retrait seul ne protège pas contre les anciennes sauvegardes (voir
  « Ce que le retrait ne fait pas » ci-dessous).
- **Hygiène périodique**, si votre politique exige une rotation des clés (par
  exemple chaque année). Rien ne casse : les anciennes preuves restent
  vérifiables.

Comment :

```bash
docker compose exec transteira transteira proof retire-key        # demande confirmation
docker compose exec transteira transteira proof retire-key --yes  # sans interaction
```

Effets :

- la **partie privée scellée active est détruite** (effacement cryptographique) :
  l'instance ne peut plus signer avec cette clé (les sauvegardes faites avant le
  retrait la contiennent encore, voir plus bas) ;
- le journal d'audit enregistre `proof_key.retired` ;
- la **preuve suivante crée une nouvelle clé active** (`proof_key.created`) ;
- la **clé publique retirée reste publiée**, avec sa date `retiredAt`, pour que
  les preuves qu'elle a signées restent vérifiables ;
- `transteira proof verify` **rejette une déclaration dont le fait est daté
  après le retrait** de sa clé. Les déclarations de faits datés avant le retrait
  restent valables.

#### Ce que le retrait ne fait pas

Le retrait n'empêche **pas** les fabrications antidatées. Toutes les dates d'une
déclaration sont choisies par celui qui la signe, et la vérification compare
seulement la date du fait au `retiredAt` de la clé. Qui a obtenu la base ou une
sauvegarde (la copie nocturne `VACUUM INTO`, un `pg_dump`) **et** la clé maître
peut desceller la clé privée et signer des déclarations datées **pendant la durée
de vie de la clé** : elles ne se distinguent pas des preuves authentiques par la
signature. Le retrait détruit la clé scellée active, mais toute sauvegarde faite
avant contient encore la clé scellée par la même clé maître, et une rotation de
la clé maître ne change rien à ces anciennes sauvegardes. C'est un risque
résiduel accepté, du même ordre que la confiance accordée à l'exploitant
(modèle de menaces T-299, H1), sans horodatage par un tiers (RFC 3161) en 2.0.

Après une compromission suspectée :

1. **faites une rotation de la clé maître ET retirez la clé de preuves** (le
   retrait seul ne suffit pas, la rotation seule non plus) ;
2. détruisez ou protégez les sauvegardes antérieures, qui contiennent encore la
   clé ;
3. traitez avec prudence les preuves signées par la clé compromise et
   recoupez-les avec le journal d'audit et les mails envoyés à l'expéditeur et
   aux destinataires.

#### Course au retrait

Un signataire préparé juste avant la validation de `transteira proof retire-key`
peut encore signer une fois avec la clé retirée. Une preuve de **remise** écrite
dans cette fenêtre (son fait est daté « maintenant », après le retrait) échoue à
la vérification et reste stockée comme ligne immuable invérifiable ; une preuve
de **dépôt** (fait = fin du dépôt, avant le retrait) se vérifie. La fenêtre dure
quelques millisecondes et l'opération est manuelle : c'est accepté. Retirez la
clé en période de faible activité, ou en mode maintenance (il refuse les
nouveaux dépôts ; les téléchargements continuent). Le fait reste dans le journal
d'audit.

## Sauvegarde et restauration

- Les clés sont dans la **base de données** ; la partie privée est illisible sans
  la **clé maître**. Restaurer une sauvegarde de la base restaure les clés et les
  preuves (restaurez aussi la clé maître : voir [Sauvegarde](../backup.md)).
- Si la base est perdue sans sauvegarde, les clés publiques conservées avec vos
  preuves (`keys.json`) les vérifient toujours.
- La partie privée étant détruite au retrait, restaurer une sauvegarde faite
  **avant** un retrait ramène l'ancienne clé comme clé active : retirez-la de
  nouveau.

## Quand une preuve ne peut pas être écrite

« Pas de fait sans preuve » : la preuve de remise est écrite dans la même
transaction que l'enregistrement du premier téléchargement. Si elle ne peut pas
l'être (problème de clé, problème de clé maître), toute la transaction du premier
téléchargement est **annulée**, y compris la programmation de la suppression
après le premier téléchargement et l'accusé de premier téléchargement. Le
transfert reste téléchargeable jusqu'à ce qu'un téléchargement complet ultérieur
réussisse. L'erreur est journalisée au niveau **error** : les exploitants
devraient alerter dessus.

## Limites

- Une preuve vaut la **confiance accordée à l'exploitant de l'instance** : qui
  détient la base et la clé maître (modèle de menaces, H1) peut signer une
  déclaration. Elle prouve ce que l'instance a enregistré, pas ce qu'un tiers a
  certifié.
- Il n'y a **pas d'horodatage par un tiers** (RFC 3161) en 2.0. Les dates viennent
  de l'horloge de l'instance.
- Le texte visible du PDF est tronqué pour une très longue liste de fichiers
  (« voir statement.json ») : la déclaration jointe contient toujours tout.
