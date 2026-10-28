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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.cra.CraReportingDeadlines;
import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.CraReportingCaseStatus;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.UUID;

/// @since 5.4.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CraReportingCaseResponse(
        @Schema(description = "UUID of the reporting case", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID uuid,

        @Schema(description = "UUID of the affected project", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID projectUuid,

        @Schema(description = "UUID of the affected vulnerability") @Nullable
        UUID vulnerabilityUuid,

        @Schema(description = "Vulnerability ID (e.g. CVE-2024-1234)") @Nullable
        String vulnId,

        @Schema(description = "Short title of the reporting case", requiredMode = Schema.RequiredMode.REQUIRED)
        String title,

        @Schema(description = "Type of reporting case", requiredMode = Schema.RequiredMode.REQUIRED)
        CraReportingCaseType caseType,

        @Schema(description = "Severity of the case") @Nullable
        Severity severity,

        @Schema(description = "Description of the case") @Nullable
        String description,

        @Schema(description = "Moment the organization became aware", requiredMode = Schema.RequiredMode.REQUIRED)
        Instant awarenessAt,

        @Schema(description = "Deadline of the 24-hour early warning (CRA Art. 14(2)(a), 14(4)(a))") @Nullable
        Instant earlyWarningDueAt,

        @Schema(description = "Deadline of the 72-hour full notification (CRA Art. 14(2)(b), 14(4)(b))") @Nullable
        Instant fullNotificationDueAt,

        @Schema(description = "Deadline of the final report (CRA Art. 14(2)(c), 14(4)(b))") @Nullable
        Instant finalReportDueAt,

        @Schema(description = "Time the early warning was submitted") @Nullable
        Instant earlyWarningSubmittedAt,

        @Schema(description = "Time the full notification was submitted") @Nullable
        Instant fullNotificationSubmittedAt,

        @Schema(description = "Time the final report was submitted") @Nullable
        Instant finalReportSubmittedAt,

        @Schema(description = "Time affected customers and users were notified (CRA Art. 14(8))") @Nullable
        Instant customersNotifiedAt,

        @Schema(description = "National CSIRT designated as coordinator") @Nullable
        String csirt,

        @Schema(description = "Status of the reporting case", requiredMode = Schema.RequiredMode.REQUIRED)
        CraReportingCaseStatus status,

        @Schema(description = "Whether any unsubmitted notification deadline has passed") boolean overdue,

        @Schema(description = "Creation timestamp", requiredMode = Schema.RequiredMode.REQUIRED)
        Instant createdAt,

        @Schema(description = "Last update timestamp", requiredMode = Schema.RequiredMode.REQUIRED)
        Instant updatedAt) {

    public static CraReportingCaseResponse of(final CraReportingCase reportingCase) {
        final Instant now = Instant.now();
        final boolean overdue =
                (reportingCase.getEarlyWarningSubmittedAt() == null
                                && reportingCase.getEarlyWarningDueAt() != null
                                && CraReportingDeadlines.isOverdue(reportingCase.getEarlyWarningDueAt(), now))
                        || (reportingCase.getFullNotificationSubmittedAt() == null
                                && reportingCase.getFullNotificationDueAt() != null
                                && CraReportingDeadlines.isOverdue(reportingCase.getFullNotificationDueAt(), now))
                        || (reportingCase.getFinalReportSubmittedAt() == null
                                && reportingCase.getFinalReportDueAt() != null
                                && CraReportingDeadlines.isOverdue(reportingCase.getFinalReportDueAt(), now));
        return new CraReportingCaseResponse(
                reportingCase.getUuid(),
                reportingCase.getProject().getUuid(),
                reportingCase.getVulnerability() != null ? reportingCase.getVulnerability().getUuid() : null,
                reportingCase.getVulnerability() != null ? reportingCase.getVulnerability().getVulnId() : null,
                reportingCase.getTitle(),
                reportingCase.getCaseType(),
                reportingCase.getSeverity(),
                reportingCase.getDescription(),
                reportingCase.getAwarenessAt(),
                reportingCase.getEarlyWarningDueAt(),
                reportingCase.getFullNotificationDueAt(),
                reportingCase.getFinalReportDueAt(),
                reportingCase.getEarlyWarningSubmittedAt(),
                reportingCase.getFullNotificationSubmittedAt(),
                reportingCase.getFinalReportSubmittedAt(),
                reportingCase.getCustomersNotifiedAt(),
                reportingCase.getCsirt(),
                reportingCase.getStatus(),
                overdue,
                reportingCase.getCreatedAt(),
                reportingCase.getUpdatedAt());
    }
}
