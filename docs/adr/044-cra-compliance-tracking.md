| Status   | Date       | Author(s)                                  |
|:---------|:-----------|:-------------------------------------------|
| Proposed | 2026-10-28 | [@vibe](https://github.com/vibe)           |

## Context

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) imposes obligations on
manufacturers of products with digital elements. The OpenChain CRA Compliance
Checklist operationalizes these obligations; several items require per-product
data that Dependency-Track is well positioned to track:

* CRA Art. 6 product classification (Annexes III-IV) and the Art. 13(8) support
  period per product (§2.5, §6.1).
* The CRA Art. 14 three-stage reporting cascade — 24h early warning, 72h full
  notification, final report within 14 days (actively exploited vulnerabilities)
  or one month (severe incidents) — with deadlines derived from the moment of
  awareness (§4.4, §4.5).
* SBOM data quality of the component inventory (§3.1, §3.2) and vulnerability
  monitoring coverage including KEV/EPSS enrichment (§4.1).

Without tooling, organizations track these deadlines and metadata in
spreadsheets, which is error-prone given the hard 24-hour clock.

## Decision

Add CRA compliance tracking to Dependency-Track:

1. **Project-level CRA metadata** stored as project properties (group `cra`):
   `productClass` (CRA Art. 6 classification) and `supportPeriodEnd`
   (CRA Art. 13(8)). Storing them as properties avoids a schema change to the
   `PROJECT` table and reuses the existing, ACL-protected project property
   API surface.
2. **A new `CRA_REPORTING_CASE` table** (Flyway migration) with a JDBI DAO
   (`CraReportingCaseDao`) and a `CraQueryManager` for CRA Art. 14 reporting
   cases. Deadlines are computed from `awarenessAt` by
   `CraReportingDeadlines` (24h / 72h / 14d or 30d depending on case type).
   Submission timestamps, customer notification, and status transitions are
   recorded per case. Cases with overdue unsubmitted deadlines are queryable.
3. **REST endpoints** under `/v1/cra/...`:
   * `/v1/cra/project/{uuid}[/classification|/supportPeriod]` for CRA metadata.
   * `/v1/cra/reporting/...` for reporting case CRUD, submission recording, and
     overdue listing.
   * `/v1/cra/sbomQuality/project/{uuid}` and
     `/v1/cra/sbomQuality/monitoring/project/{uuid}` for SBOM quality and
     vulnerability monitoring reports.
4. **New JDO model** `CraReportingCase` (with enums `CraProductClass`,
   `CraReportingCaseType`, `CraReportingCaseStatus`) following the existing
   model conventions.

Permissions reuse the existing portfolio permissions
(`PORTFOLIO_MANAGEMENT*` for metadata and reporting cases, `VIEW_PORTFOLIO`
for read-only reports), and portfolio ACLs are enforced via `requireAccess`.

## Consequences

* What becomes easier: meeting the CRA Art. 14 deadlines is supported by
  automatically computed due dates and an overdue listing; product
  classification and support periods are recorded per project; SBOM quality
  and KEV/EPSS monitoring coverage are reportable per project.
* What becomes more difficult: nothing existing changes. The new table and
  endpoints are additive.
* Limitations: Dependency-Track records and tracks the reporting process but
  does not submit to the CRA Single Reporting Platform (SRP); the actual
  notification remains a manual step. Final report deadlines are approximated
  from the awareness timestamp because the moment a fix becomes available is
  not known when a case is opened.
