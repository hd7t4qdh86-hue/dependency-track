# EU Cyber Resilience Act (CRA) Compliance Support

Dependency-Track supports organizations in meeting selected obligations of
[Regulation (EU) 2024/2847 (Cyber Resilience Act)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847),
as operationalized by the
[OpenChain CRA Compliance Requirements & Checklist](https://github.com/OpenChain-Project/CRA-Compliance/blob/main/CRA_Checklist_Requirement_latest.md).

This document maps CRA checklist items to Dependency-Track capabilities. It is
a readiness and evidence-management aid, not a conformity assessment, and it
does not constitute legal advice.

## What Dependency-Track provides

### CRA product classification and support period (§2.5, §6.1)

Each project can carry CRA metadata:

* **Product classification** per CRA Art. 6 and Annexes III-IV
  (`DEFAULT`, `IMPORTANT_CLASS_I`, `IMPORTANT_CLASS_II`, `CRITICAL`), which
  determines the conformity assessment route (§2.5.3–2.5.6).
* **End-of-support date** per CRA Art. 13(8) (§6.1.1), including an indicator
  whether the declared support period has expired (§6.1.4).

The metadata is stored as project properties (group `cra`) and exposed via:

| Method | Endpoint | Permission |
| :----- | :------- | :--------- |
| `GET` | `/v1/cra/project/{uuid}` | `PORTFOLIO_MANAGEMENT_READ` |
| `PUT` | `/v1/cra/project/{uuid}/classification` | `PORTFOLIO_MANAGEMENT_UPDATE` |
| `PUT` | `/v1/cra/project/{uuid}/supportPeriod` | `PORTFOLIO_MANAGEMENT_UPDATE` |

### CRA Art. 14 reporting tracker (§4.4, §4.5)

For actively exploited vulnerabilities (CRA Art. 14(1)–(2)) and severe
incidents (CRA Art. 14(3)–(5)), Dependency-Track tracks reporting cases
through the three-stage notification cascade:

| Stage | Deadline | CRA reference |
| :---- | :------- | :------------ |
| Early warning | 24 hours after awareness | Art. 14(2)(a), 14(4)(a) |
| Full notification | 72 hours after awareness | Art. 14(2)(b), 14(4)(b) |
| Final report | 14 days after a fix is available (vulnerabilities); one month after the 72-hour notification (severe incidents) | Art. 14(2)(c), 14(4)(b) |

Deadlines are computed automatically from the recorded moment of awareness
(§4.5.5). Submissions of each stage, customer notification (Art. 14(8)), and
case closure are recorded with timestamps. Cases with overdue, unsubmitted
deadlines are listed via `GET /v1/cra/reporting/overdue`.

| Method | Endpoint | Purpose |
| :----- | :------- | :------ |
| `PUT` | `/v1/cra/reporting/project/{uuid}` | Create a reporting case |
| `GET` | `/v1/cra/reporting/project/{uuid}` | List cases of a project |
| `GET` | `/v1/cra/reporting/{caseUuid}` | Get a single case |
| `GET` | `/v1/cra/reporting/overdue` | List cases with overdue deadlines |
| `POST` | `/v1/cra/reporting/{caseUuid}/earlyWarning` | Record 24h early warning submission |
| `POST` | `/v1/cra/reporting/{caseUuid}/fullNotification` | Record 72h full notification submission |
| `POST` | `/v1/cra/reporting/{caseUuid}/finalReport` | Record final report submission |
| `POST` | `/v1/cra/reporting/{caseUuid}/customerNotification` | Record customer notification (Art. 14(8)) |
| `POST` | `/v1/cra/reporting/{caseUuid}/status` | Update case status (e.g. close) |
| `DELETE` | `/v1/cra/reporting/{caseUuid}` | Delete a case |

The reporting obligation itself (submission to the CRA Single Reporting
Platform) remains a manual process; Dependency-Track records and tracks it.

### SBOM data quality report (§3.1, §3.2)

`GET /v1/cra/sbomQuality/project/{uuid}` assesses the component inventory of
a project against the metadata expected in a CRA-conformant SBOM
(§3.1.6): unique identifiers (PURL, CPE, SWHID), cryptographic hashes
(§3.3.2), and license information. Dependency-Track itself generates
machine-readable CycloneDX and SPDX SBOMs (`/v1/bom/...`), satisfying the
format requirement of §3.1.2.

### Vulnerability monitoring report (§4.1)

`GET /v1/cra/sbomQuality/monitoring/project/{uuid}` reports the number of
distinct vulnerabilities affecting a project, how many are listed in the
CISA KEV catalog (§4.1.6 — a KEV listing is the primary trigger for a CRA
Art. 14 assessment), and the EPSS enrichment rate (§4.1.4).

## Checklist mapping

| CRA checklist item | Dependency-Track support |
| :----------------- | :----------------------- |
| §2.5.3 Product classification | `PUT /v1/cra/project/{uuid}/classification` |
| §6.1.1 Support period definition | `PUT /v1/cra/project/{uuid}/supportPeriod` |
| §6.1.4 End-of-support communication | `supportPeriodExpired` flag in `GET /v1/cra/project/{uuid}` |
| §3.1.2 Machine-readable SBOM format | CycloneDX / SPDX export via `/v1/bom` |
| §3.1.6 SBOM metadata profile | `GET /v1/cra/sbomQuality/project/{uuid}` |
| §3.2.4 SBOM quality metrics | SBOM quality report (identifier/hash/license rates) |
| §4.1.4 EPSS/KEV enrichment | `GET /v1/cra/sbomQuality/monitoring/project/{uuid}` |
| §4.1.6 KEV as Art. 14 trigger | KEV finding count in monitoring report |
| §4.4.2 24h early warning | `POST /v1/cra/reporting/{caseUuid}/earlyWarning` |
| §4.4.3 72h full notification | `POST /v1/cra/reporting/{caseUuid}/fullNotification` |
| §4.4.4 14-day final report | `POST /v1/cra/reporting/{caseUuid}/finalReport` |
| §4.4.5 One-month final report (severe incidents) | Final report deadline per case type |
| §4.4.6 Customer notification | `POST /v1/cra/reporting/{caseUuid}/customerNotification` |
| §4.4.9 CSIRT identification | `csirt` field of a reporting case |
| §4.5.5 Awareness timestamp | `awarenessAt` field; all deadlines derive from it |

## Out of scope

Organizational obligations that cannot be fulfilled by a tool — such as the
CRA policy (§2.1), role assignments (§2.2), training (§2.3), the
cybersecurity risk assessment (§2.6), secure development and testing
practices (§3.4), OSS stewardship (§5), the Technical File and EU Declaration
of Conformity (§7), and the actual SRP submission — remain the
responsibility of the organization. Dependency-Track provides the inventory,
monitoring, and evidence-tracking data these processes build upon.
