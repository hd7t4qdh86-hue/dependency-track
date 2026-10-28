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
package org.dependencytrack.resources.v1;

import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.cra.CraMonitoringReport;
import org.dependencytrack.cra.CraSbomQualityReport;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.CraMonitoringReportResponse;
import org.dependencytrack.resources.v1.vo.CraSbomQualityReportResponse;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * JAX-RS resource providing a per-project SBOM data quality report aligned
 * with the OpenChain CRA Compliance Checklist sections 3.1 and 3.2.
 *
 * @since 5.4.0
 */
@Path("/v1/cra/sbomQuality")
@Tag(name = "craSbomQuality")
@SecurityRequirements({@SecurityRequirement(name = "ApiKeyAuth"), @SecurityRequirement(name = "BearerAuth")})
public class CraSbomQualityResource extends AbstractV1ApiResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the SBOM data quality report of the specified project",
            description =
                    "<p>Requires permission <strong>VIEW_PORTFOLIO</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The SBOM data quality report of the specified project",
                        content = @Content(schema = @Schema(implementation = CraSbomQualityReportResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The project could not be found")
            })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getSbomQualityReport(
            @Parameter(
                            description = "The UUID of the project to assess",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The project could not be found.")
                        .build();
            }
            requireAccess(qm, project);
            return Response.ok(CraSbomQualityReportResponse.of(CraSbomQualityReport.compute(qm, project)))
                    .build();
        }
    }

    @GET
    @Path("/monitoring/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the CRA vulnerability monitoring report of the specified project",
            description =
                    "<p>Assesses vulnerability monitoring coverage, EPSS/KEV enrichment, and findings per severity. " +
                            "Requires permission <strong>VIEW_PORTFOLIO</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The CRA vulnerability monitoring report of the specified project",
                        content = @Content(schema = @Schema(implementation = CraMonitoringReportResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The project could not be found")
            })
    @PermissionRequired(Permissions.Constants.VIEW_PORTFOLIO)
    public Response getMonitoringReport(
            @Parameter(
                            description = "The UUID of the project to assess",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The project could not be found.")
                        .build();
            }
            requireAccess(qm, project);
            return Response.ok(CraMonitoringReportResponse.of(CraMonitoringReport.compute(qm, project)))
                    .build();
        }
    }
}
