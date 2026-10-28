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
import org.dependencytrack.model.Project;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.CraClassificationRequest;
import org.dependencytrack.resources.v1.vo.CraComplianceResponse;
import org.dependencytrack.resources.v1.vo.CraSupportPeriodRequest;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;

/**
 * JAX-RS resource for EU Cyber Resilience Act (Regulation (EU) 2024/2847)
 * compliance metadata of projects: product classification (CRA Art. 6,
 * Annexes III-IV) and support period (CRA Art. 13(8)).
 *
 * @since 5.4.0
 */
@Path("/v1/cra/project/{uuid}")
@Tag(name = "craCompliance")
@SecurityRequirements({@SecurityRequirement(name = "ApiKeyAuth"), @SecurityRequirement(name = "BearerAuth")})
public class CraComplianceResource extends AbstractV1ApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns the CRA compliance metadata of the specified project",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_READ</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The CRA compliance metadata of the specified project",
                        content = @Content(schema = @Schema(implementation = CraComplianceResponse.class))),
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
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_READ})
    public Response getComplianceMetadata(
            @Parameter(
                            description = "The UUID of the project to retrieve CRA compliance metadata for",
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

            final var productClass = qm.getCraProductClass(project);
            final var supportPeriodEnd = qm.getCraSupportPeriodEnd(project);
            return Response.ok(new CraComplianceResponse(
                            productClass,
                            supportPeriodEnd,
                            supportPeriodEnd != null && supportPeriodEnd.isBefore(Instant.now())))
                    .build();
        }
    }

    @PUT
    @Path("/classification")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records the CRA product classification of the specified project",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated CRA compliance metadata of the specified project",
                        content = @Content(schema = @Schema(implementation = CraComplianceResponse.class))),
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
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response setClassification(
            @Parameter(
                            description = "The UUID of the project to record the classification for",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid,
            CraClassificationRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "productClass"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build();
                }
                requireAccess(qm, project);

                qm.setCraProductClass(project, request.productClass());
                return Response.ok(complianceResponseOf(qm, project)).build();
            });
        }
    }

    @PUT
    @Path("/supportPeriod")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records the end-of-support date of the specified project",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated CRA compliance metadata of the specified project",
                        content = @Content(schema = @Schema(implementation = CraComplianceResponse.class))),
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
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response setSupportPeriod(
            @Parameter(
                            description = "The UUID of the project to record the end-of-support date for",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid,
            CraSupportPeriodRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "supportPeriodEnd"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return qm.callInTransaction(() -> {
                final Project project = qm.getObjectByUuid(Project.class, uuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build();
                }
                requireAccess(qm, project);

                qm.setCraSupportPeriodEnd(project, request.supportPeriodEnd());
                return Response.ok(complianceResponseOf(qm, project)).build();
            });
        }
    }

    private CraComplianceResponse complianceResponseOf(final QueryManager qm, final Project project) {
        final var supportPeriodEnd = qm.getCraSupportPeriodEnd(project);
        return new CraComplianceResponse(
                qm.getCraProductClass(project), supportPeriodEnd, supportPeriodEnd != null && supportPeriodEnd.isBefore(Instant.now()));
    }
}
