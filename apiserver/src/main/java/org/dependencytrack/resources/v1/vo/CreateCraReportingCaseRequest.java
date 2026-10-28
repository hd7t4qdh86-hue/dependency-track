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

import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;

/// @since 5.4.0
@NullMarked
@JsonIgnoreProperties(ignoreUnknown = true)
public record CreateCraReportingCaseRequest(
        @Nullable
        @Schema(description = "Vulnerability ID (e.g. CVE-2024-1234) of the affected vulnerability")
        String vulnId,

        @Nullable
        @Schema(description = "Source of the vulnerability (e.g. NVD)")
        String vulnSource,

        @NotBlank
        @Schema(description = "Short title of the reporting case", requiredMode = Schema.RequiredMode.REQUIRED)
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Pattern(regexp = "\\P{Cc}+", message = "The title must not contain control characters")
        String title,

        @NotNull
        @Schema(description = "Type of reporting case", requiredMode = Schema.RequiredMode.REQUIRED)
        CraReportingCaseType caseType,

        @Nullable @Schema(description = "Severity of the case")
        Severity severity,

        @Nullable
        @Schema(description = "Description of the case")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Pattern(regexp = "\\P{Cc}*", message = "The description must not contain control characters")
        String description,

        @NotNull
        @Schema(
                description = "Moment the organization became aware of the incident or actively exploited vulnerability",
                requiredMode = Schema.RequiredMode.REQUIRED)
        Instant awarenessAt,

        @Nullable
        @Size(max = 255)
        @Schema(description = "National CSIRT designated as coordinator (CRA Art. 14(7))")
        @JsonDeserialize(using = TrimmedStringDeserializer.class)
        @Pattern(regexp = "\\P{Cc}*", message = "The csirt must not contain control characters")
        String csirt) {}
