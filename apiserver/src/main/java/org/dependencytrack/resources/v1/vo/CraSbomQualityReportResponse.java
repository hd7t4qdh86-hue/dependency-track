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
import org.dependencytrack.cra.CraSbomQualityReport;
import org.jspecify.annotations.NullMarked;

import java.util.UUID;

/// @since 5.4.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CraSbomQualityReportResponse(
        @Schema(description = "UUID of the assessed project", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID projectUuid,

        @Schema(description = "Total number of components in the project", requiredMode = Schema.RequiredMode.REQUIRED)
        int componentCount,

        @Schema(description = "Number of components carrying a unique identifier (PURL, CPE or SWHID)", requiredMode = Schema.RequiredMode.REQUIRED)
        int componentsWithIdentifier,

        @Schema(description = "Number of components carrying a cryptographic hash", requiredMode = Schema.RequiredMode.REQUIRED)
        int componentsWithHash,

        @Schema(description = "Number of components carrying license information", requiredMode = Schema.RequiredMode.REQUIRED)
        int componentsWithLicense,

        @Schema(description = "Share of components with a unique identifier (0-1)", requiredMode = Schema.RequiredMode.REQUIRED)
        double uniqueIdentifierRate,

        @Schema(description = "Share of components with a cryptographic hash (0-1)", requiredMode = Schema.RequiredMode.REQUIRED)
        double hashRate,

        @Schema(description = "Share of components with license information (0-1)", requiredMode = Schema.RequiredMode.REQUIRED)
        double licenseRate) {

    public static CraSbomQualityReportResponse of(final CraSbomQualityReport.Report report) {
        return new CraSbomQualityReportResponse(
                report.projectUuid(),
                report.componentCount(),
                report.componentsWithIdentifier(),
                report.componentsWithHash(),
                report.componentsWithLicense(),
                report.uniqueIdentifierRate(),
                report.hashRate(),
                report.licenseRate());
    }
}
