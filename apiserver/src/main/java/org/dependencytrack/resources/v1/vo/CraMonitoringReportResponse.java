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
import org.dependencytrack.cra.CraMonitoringReport;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.NullMarked;

import java.util.Map;
import java.util.UUID;

/// @since 5.4.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CraMonitoringReportResponse(
        @Schema(description = "UUID of the assessed project", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID projectUuid,

        @Schema(description = "Total number of distinct vulnerabilities affecting the project", requiredMode = Schema.RequiredMode.REQUIRED)
        int vulnerabilityCount,

        @Schema(description = "Number of vulnerabilities listed in the CISA KEV catalog", requiredMode = Schema.RequiredMode.REQUIRED)
        int kevCount,

        @Schema(description = "Number of vulnerabilities enriched with an EPSS score", requiredMode = Schema.RequiredMode.REQUIRED)
        int epssEnrichedCount,

        @Schema(description = "Share of vulnerabilities enriched with an EPSS score (0-1)", requiredMode = Schema.RequiredMode.REQUIRED)
        double epssEnrichmentRate,

        @Schema(description = "Number of vulnerabilities per severity", requiredMode = Schema.RequiredMode.REQUIRED)
        Map<Severity, Integer> vulnerabilitiesBySeverity) {

    public static CraMonitoringReportResponse of(final CraMonitoringReport.Report report) {
        return new CraMonitoringReportResponse(
                report.projectUuid(),
                report.vulnerabilityCount(),
                report.kevCount(),
                report.epssEnrichedCount(),
                report.epssEnrichmentRate(),
                report.vulnerabilitiesBySeverity());
    }
}
