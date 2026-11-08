# Kit de conformité

Ce kit aide l'organisation qui exploite TransTeira (le **responsable de
traitement**) à documenter le service dans ses registres de protection des
données et de sécurité de l'information : une fiche prête à compléter pour le
**registre des activités de traitement RGPD** (article 30) et une
**correspondance avec les mesures de l'annexe A de l'ISO/IEC 27001:2022**. Il
accompagne le [modèle de menaces](../../security/threat-model.md), sur lequel il
s'appuie.

English: [docs/compliance/README.md](../README.md).

> **Important.** Ces documents sont des **modèles** que le responsable de
> traitement adapte. Ils ne constituent **ni un avis juridique ni une
> certification** : les utiliser ne rend pas une organisation conforme au RGPD
> ni certifiée ISO/IEC 27001. Ils décrivent ce que fait le **logiciel** ; la
> base légale, les durées de conservation décidées, les contrats avec les
> sous-traitants et les mesures organisationnelles vous appartiennent. Faites
> relire le résultat par votre délégué à la protection des données (DPO) ou un
> juriste.

Le kit s'applique à **TransTeira 2.0**. Chaque nouvelle version peut changer ce
qui est stocké ou la façon de le faire : relisez les documents à chaque mise à
jour (voir le [CHANGELOG](../../../CHANGELOG.md) et le
[guide de mise à jour](../../operations/upgrade.md), en anglais).

## Documents

| Document | Usage |
|---|---|
| [Registre RGPD](gdpr-processing-record.md) | Une activité de traitement pré-remplie, « Service de transfert de fichiers » : finalités, personnes concernées, catégories de données, destinataires, conservation, mesures de sécurité. Complétez les `<à compléter>` et joignez-la à votre registre. |
| [Correspondance ISO/IEC 27001:2022 annexe A](iso27001-annex-a.md) | Les 93 mesures de l'annexe A, avec pour chacune qui la fournit (TransTeira, partagée, exploitant), le mécanisme et la référence. À utiliser pour la déclaration d'applicabilité (DdA) et pour les audits. |
| [Modèle de menaces](../../security/threat-model.md) | Analyse STRIDE : actifs, frontières de confiance, menaces `T-xxx`, décisions `Pxx`. Les deux documents ci-dessus le citent. |

## Mode d'emploi

1. Copiez les deux documents dans votre système documentaire et complétez les
   champs à renseigner (responsable de traitement, DPO, base légale,
   sous-traitants, transferts hors UE).
2. Vérifiez chaque ligne « Partagée » et « Exploitant » de la correspondance ISO
   au regard de votre organisation : ce sont les mesures que TransTeira ne peut
   pas prendre à votre place.
3. Conservez les copies complétées avec la version de TransTeira qu'elles
   décrivent, et relisez-les au moins une fois par an et à chaque mise à jour
   majeure.

## Documents associés

Les documents ci-dessous sont en anglais, sauf mention contraire.

- [Politique de sécurité et signalement des vulnérabilités](../../../SECURITY.md)
- [Installation avec Docker](../../install/fr/docker.md) (français), dont la
  [vérification de l'image signée](../../install/docker.md#published-signed-image-alternative-to-building)
- [Reverse proxy](../../install/reverse-proxy.md), [SMTP](../../install/fr/smtp.md)
  (français), [PostgreSQL](../../install/postgresql.md)
- [Sauvegarde et restauration](../../operations/backup.md)
- [Clé maître](../../operations/master-key.md) : rotation et effacement cryptographique
- [Journal de sécurité](../../operations/security-log.md) (fail2ban et CrowdSec),
  [export syslog](../../operations/syslog.md), [supervision](../../operations/supervision.md)
- [Antivirus](../../operations/antivirus.md), [authentification unique](../../operations/fr/sso.md)
  (français), [preuves de dépôt et de remise](../../operations/fr/proofs.md) (français)
- [Guide d'administration](../../operations/admin.md), [entités](../../operations/tenants.md)
- [Guide de l'admin délégué](../../user/fr/delegated-admin.md) (français), dont
  l'écran « Données personnelles (RGPD) »
- [Publication d'une version](../../operations/release.md) (guide du mainteneur :
  tags et images signés)
