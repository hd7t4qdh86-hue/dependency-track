/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.CraReportingCaseStatus;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Severity;
import org.jdbi.v3.sqlobject.SqlObject;
import org.jdbi.v3.sqlobject.config.RegisterBeanMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * DAO for {@link CraReportingCase} records (CRA Art. 14 reporting tracker).
 *
 * @since 5.4.0
 */
@RegisterBeanMapper(CraReportingCase.class)
public interface CraReportingCaseDao extends SqlObject {

    String COLUMNS = /* language=SQL */ """
            "ID"
          , "UUID"
          , "PROJECT_ID"
          , "VULNERABILITY_ID"
          , "TITLE"
          , "CASE_TYPE"
          , "SEVERITY"
          , "DESCRIPTION"
          , "AWARENESS_AT"
          , "EARLY_WARNING_DUE_AT"
          , "FULL_NOTIFICATION_DUE_AT"
          , "FINAL_REPORT_DUE_AT"
          , "EARLY_WARNING_SUBMITTED_AT"
          , "FULL_NOTIFICATION_SUBMITTED_AT"
          , "FINAL_REPORT_SUBMITTED_AT"
          , "CUSTOMERS_NOTIFIED_AT"
          , "CSIRT"
          , "STATUS"
          , "CREATED_AT"
          , "UPDATED_AT"
            """;

    @SqlQuery("""
            SELECT "ID"
                 , "UUID"
                 , "PROJECT_ID"
                 , "VULNERABILITY_ID"
                 , "TITLE"
                 , "CASE_TYPE"
                 , "SEVERITY"
                 , "DESCRIPTION"
                 , "AWARENESS_AT"
                 , "EARLY_WARNING_DUE_AT"
                 , "FULL_NOTIFICATION_DUE_AT"
                 , "FINAL_REPORT_DUE_AT"
                 , "EARLY_WARNING_SUBMITTED_AT"
                 , "FULL_NOTIFICATION_SUBMITTED_AT"
                 , "FINAL_REPORT_SUBMITTED_AT"
                 , "CUSTOMERS_NOTIFIED_AT"
                 , "CSIRT"
                 , "STATUS"
                 , "CREATED_AT"
                 , "UPDATED_AT"
              FROM "CRA_REPORTING_CASE"
             WHERE "UUID" = :uuid
            """)
    @Nullable
    CraReportingCase getByUuid(@Bind UUID uuid);

    @SqlQuery("""
            SELECT "ID"
                 , "UUID"
                 , "PROJECT_ID"
                 , "VULNERABILITY_ID"
                 , "TITLE"
                 , "CASE_TYPE"
                 , "SEVERITY"
                 , "DESCRIPTION"
                 , "AWARENESS_AT"
                 , "EARLY_WARNING_DUE_AT"
                 , "FULL_NOTIFICATION_DUE_AT"
                 , "FINAL_REPORT_DUE_AT"
                 , "EARLY_WARNING_SUBMITTED_AT"
                 , "FULL_NOTIFICATION_SUBMITTED_AT"
                 , "FINAL_REPORT_SUBMITTED_AT"
                 , "CUSTOMERS_NOTIFIED_AT"
                 , "CSIRT"
                 , "STATUS"
                 , "CREATED_AT"
                 , "UPDATED_AT"
              FROM "CRA_REPORTING_CASE"
             WHERE "PROJECT_ID" = :projectId
             ORDER BY "AWARENESS_AT" DESC
            """)
    List<CraReportingCase> getByProject(@Bind long projectId);

    @SqlQuery("""
            SELECT "ID"
                 , "UUID"
                 , "PROJECT_ID"
                 , "VULNERABILITY_ID"
                 , "TITLE"
                 , "CASE_TYPE"
                 , "SEVERITY"
                 , "DESCRIPTION"
                 , "AWARENESS_AT"
                 , "EARLY_WARNING_DUE_AT"
                 , "FULL_NOTIFICATION_DUE_AT"
                 , "FINAL_REPORT_DUE_AT"
                 , "EARLY_WARNING_SUBMITTED_AT"
                 , "FULL_NOTIFICATION_SUBMITTED_AT"
                 , "FINAL_REPORT_SUBMITTED_AT"
                 , "CUSTOMERS_NOTIFIED_AT"
                 , "CSIRT"
                 , "STATUS"
                 , "CREATED_AT"
                 , "UPDATED_AT"
              FROM "CRA_REPORTING_CASE"
             WHERE "STATUS" IN ('OPEN', 'EARLY_WARNING_SUBMITTED', 'FULL_NOTIFICATION_SUBMITTED')
               AND (
                 ("EARLY_WARNING_SUBMITTED_AT" IS NULL AND "EARLY_WARNING_DUE_AT" < :now)
                 OR ("FULL_NOTIFICATION_SUBMITTED_AT" IS NULL AND "FULL_NOTIFICATION_DUE_AT" < :now)
                 OR ("FINAL_REPORT_SUBMITTED_AT" IS NULL AND "FINAL_REPORT_DUE_AT" < :now)
               )
             ORDER BY
               LEAST(
                 COALESCE("EARLY_WARNING_DUE_AT", "FULL_NOTIFICATION_DUE_AT", "FINAL_REPORT_DUE_AT"),
                 COALESCE("FULL_NOTIFICATION_DUE_AT", "FINAL_REPORT_DUE_AT"),
                 "FINAL_REPORT_DUE_AT"
               )
            """)
    List<CraReportingCase> getOverdue(@Bind Instant now);

    @SqlUpdate("""
            INSERT INTO "CRA_REPORTING_CASE" (
              "UUID"
            , "PROJECT_ID"
            , "VULNERABILITY_ID"
            , "TITLE"
            , "CASE_TYPE"
            , "SEVERITY"
            , "DESCRIPTION"
            , "AWARENESS_AT"
            , "EARLY_WARNING_DUE_AT"
            , "FULL_NOTIFICATION_DUE_AT"
            , "FINAL_REPORT_DUE_AT"
            , "CSIRT"
            , "STATUS"
            , "CREATED_AT"
            , "UPDATED_AT"
            ) VALUES (
              :uuid
            , :projectId
            , :vulnerabilityId
            , :title
            , CAST(:caseType AS VARCHAR)
            , CAST(:severity AS VARCHAR)
            , :description
            , :awarenessAt
            , :earlyWarningDueAt
            , :fullNotificationDueAt
            , :finalReportDueAt
            , :csirt
            , CAST(:status AS VARCHAR)
            , now()
            , now()
            )
            """)
    void create(
            @Bind UUID uuid,
            @Bind long projectId,
            @Bind @Nullable Long vulnerabilityId,
            @Bind String title,
            @Bind CraReportingCaseType caseType,
            @Bind @Nullable Severity severity,
            @Bind @Nullable String description,
            @Bind Instant awarenessAt,
            @Bind @Nullable Instant earlyWarningDueAt,
            @Bind @Nullable Instant fullNotificationDueAt,
            @Bind @Nullable Instant finalReportDueAt,
            @Bind @Nullable String csirt,
            @Bind CraReportingCaseStatus status);

    @SqlUpdate("""
            UPDATE "CRA_REPORTING_CASE"
               SET "EARLY_WARNING_SUBMITTED_AT" = :submittedAt
                 , "STATUS" = CAST(:status AS VARCHAR)
                 , "UPDATED_AT" = now()
             WHERE "ID" = :id
            """)
    int recordEarlyWarningSubmission(@Bind long id, @Bind Instant submittedAt, @Bind CraReportingCaseStatus status);

    @SqlUpdate("""
            UPDATE "CRA_REPORTING_CASE"
               SET "FULL_NOTIFICATION_SUBMITTED_AT" = :submittedAt
                 , "STATUS" = CAST(:status AS VARCHAR)
                 , "UPDATED_AT" = now()
             WHERE "ID" = :id
            """)
    int recordFullNotificationSubmission(
            @Bind long id, @Bind Instant submittedAt, @Bind CraReportingCaseStatus status);

    @SqlUpdate("""
            UPDATE "CRA_REPORTING_CASE"
               SET "FINAL_REPORT_SUBMITTED_AT" = :submittedAt
                 , "STATUS" = CAST(:status AS VARCHAR)
                 , "UPDATED_AT" = now()
             WHERE "ID" = :id
            """)
    int recordFinalReportSubmission(@Bind long id, @Bind Instant submittedAt, @Bind CraReportingCaseStatus status);

    @SqlUpdate("""
            UPDATE "CRA_REPORTING_CASE"
               SET "CUSTOMERS_NOTIFIED_AT" = :notifiedAt
                 , "UPDATED_AT" = now()
             WHERE "ID" = :id
            """)
    int recordCustomerNotification(@Bind long id, @Bind Instant notifiedAt);

    @SqlUpdate("""
            UPDATE "CRA_REPORTING_CASE"
               SET "STATUS" = CAST(:status AS VARCHAR)
                 , "UPDATED_AT" = now()
             WHERE "ID" = :id
            """)
    int updateStatus(@Bind long id, @Bind CraReportingCaseStatus status);

    @SqlUpdate("""
            DELETE
              FROM "CRA_REPORTING_CASE"
             WHERE "ID" = :id
            """)
    int delete(@Bind long id);
}
