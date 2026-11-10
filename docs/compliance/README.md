# Compliance kit

This kit helps the organisation that operates TransTeira (the **data
controller**) document the service for its data protection and information
security records: a ready-to-complete sheet for the **GDPR record of
processing activities** (article 30) and a **correspondence with the
ISO/IEC 27001:2022 Annex A controls**. It sits next to the
[threat model](../security/threat-model.md), which it relies on.

Français : [docs/compliance/fr/README.md](fr/README.md).

> **Important.** These documents are **templates** that the controller
> adapts. They are **not legal advice** and **not a certification**: using
> them does not make an organisation compliant with the GDPR or certified
> against ISO/IEC 27001. They describe what the **software** does; the legal
> basis, the retention decisions, the contracts with processors and the
> organisational measures are yours. Have the result reviewed by your data
> protection officer (DPO) or a lawyer.

The kit applies to **TransTeira 2.1**. Each new version may change what is
stored or how: re-read the documents when you upgrade (see the
[CHANGELOG](../../CHANGELOG.md) and the [upgrade guide](../operations/upgrade.md)).

## Documents

| Document | Use |
|---|---|
| [GDPR processing record](gdpr-processing-record.md) | One pre-filled processing activity, "File transfer service", with its second purpose since 2.1, one-time secrets: purposes, data subjects, data categories, recipients, retention, security measures. Fill the `<to be completed>` placeholders and attach it to your register. |
| [ISO/IEC 27001:2022 Annex A mapping](iso27001-annex-a.md) | The 93 controls of Annex A, with for each one who provides it (TransTeira, shared, operator), the mechanism and the reference. Use it for the Statement of Applicability (SoA) and for audits. |
| [Threat model](../security/threat-model.md) (French) | STRIDE analysis: assets, trust boundaries, threats `T-xxx`, decisions `Pxx`. The two documents above cite it. |

## How to use it

1. Copy the two documents into your own records system and fill the
   placeholders (controller, DPO, legal basis, processors, transfers outside
   the EU).
2. Check each "Shared" and "Operator" line of the ISO mapping against your
   own organisation: those are the measures TransTeira cannot take for you.
3. Keep the filled copies with the version of TransTeira they describe, and
   review them at least once a year and at every major upgrade.

## Related documents

- [Security policy and vulnerability reporting](../../SECURITY.md)
- [Installing with Docker](../install/docker.md), including
  [verifying the signed image](../install/docker.md#published-signed-image-alternative-to-building)
- [Reverse proxy](../install/reverse-proxy.md), [SMTP](../install/smtp.md),
  [PostgreSQL](../install/postgresql.md)
- [Backup and restore](../operations/backup.md)
- [Master key](../operations/master-key.md): rotation and crypto-erase
- [Security log](../operations/security-log.md) (fail2ban and CrowdSec),
  [syslog export](../operations/syslog.md), [supervision](../operations/supervision.md)
- [Antivirus](../operations/antivirus.md), [single sign-on](../operations/sso.md),
  [proofs of deposit and delivery](../operations/proofs.md)
- [Administration guide](../operations/admin.md), [tenants](../operations/tenants.md)
- [Secret format](../architecture/e2e-format.md) (section 3.3), and the [depositor](../user/en/depositor.md) and [recipient](../user/en/recipient.md) guides for one-time secrets
- [Delegated admin guide](../user/en/delegated-admin.md), including the
  "Personal data (GDPR)" screen
- [Releasing](../operations/release.md) (maintainer guide: signed tags and images)
