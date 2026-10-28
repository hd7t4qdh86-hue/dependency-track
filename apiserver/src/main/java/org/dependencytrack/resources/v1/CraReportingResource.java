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
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.CreateCraReportingCaseRequest;
import org.dependencytrack.resources.v1.vo.CraReportingCaseResponse;
import org.dependencytrack.resources.v1.vo.CraReportingCaseStatusUpdateRequest;
import org.dependencytrack.resources.v1.vo.CraReportingCaseSubmissionRequest;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.UUID;

/**
 * JAX-RS resource for tracking CRA Art. 14 (Regulation (EU) 2024/2847)
 * reporting cases: actively exploited vulnerabilities and severe incidents,
 * including the 24-hour early warning, 72-hour full notification and final
 * report deadlines.
 *
 * @since 5.4.0
 */
@Path("/v1/cra/reporting")
@Tag(name = "craReporting")
@SecurityRequirements({@SecurityRequirement(name = "ApiKeyAuth"), @SecurityRequirement(name = "BearerAuth")})
public class CraReportingResource extends AbstractV1ApiResource {

    @GET
    @Path("/project/{uuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns all CRA Art. 14 reporting cases of the specified project",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_READ</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "All CRA Art. 14 reporting cases of the specified project",
                        content =
                                @Content(
                                        array =
                                                @ArraySchema(
                                                        schema =
                                                                @Schema(
                                                                        implementation =
                                                                                CraReportingCaseResponse.class)))),
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
    public Response getReportingCases(
            @Parameter(
                            description = "The UUID of the project to retrieve reporting cases for",
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

            final List<CraReportingCase> cases = qm.getCraReportingCases(project);
            return Response.ok(cases.stream().map(CraReportingCaseResponse::of).toList()).build();
        }
    }

    @GET
    @Path("/overdue")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns all CRA Art. 14 reporting cases with overdue notification deadlines",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_READ</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "All CRA Art. 14 reporting cases with overdue notification deadlines",
                        content =
                                @Content(
                                        array =
                                                @ArraySchema(
                                                        schema =
                                                                @Schema(
                                                                        implementation =
                                                                                CraReportingCaseResponse.class)))),
                @ApiResponse(responseCode = "401", description = "Unauthorized")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_READ})
    public Response getOverdueReportingCases() {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            return Response.ok(qm.getOverdueCraReportingCases().stream()
                            .map(CraReportingCaseResponse::of)
                            .toList())
                    .build();
        }
    }

    @PUT
    @Path("/project/{uuid}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Creates a new CRA Art. 14 reporting case for the specified project",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_CREATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "201",
                        description = "The created reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The project or vulnerability could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_CREATE})
    public Response createReportingCase(
            @Parameter(
                            description = "The UUID of the affected project",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("uuid")
                    @ValidUuid
                    String uuid,
            CreateCraReportingCaseRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(
                validator.validateProperty(request, "vulnId"),
                validator.validateProperty(request, "vulnSource"),
                validator.validateProperty(request, "title"),
                validator.validateProperty(request, "caseType"),
                validator.validateProperty(request, "severity"),
                validator.validateProperty(request, "description"),
                validator.validateProperty(request, "awarenessAt"),
                validator.validateProperty(request, "csirt"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The project could not be found.")
                        .build();
            }
            requireAccess(qm, project);

            Vulnerability vulnerability = null;
            if (request.vulnId() != null) {
                final String source =
                        request.vulnSource() != null ? request.vulnSource() : Vulnerability.Source.INTERNAL.name();
                vulnerability = qm.getVulnerabilityByVulnId(source, request.vulnId());
                if (vulnerability == null) {
                    return Response.status(Response.Status.NOT_FOUND)
                            .entity("The vulnerability could not be found.")
                            .build();
                }
            }

            final CraReportingCase reportingCase = qm.createCraReportingCase(
                    project,
                    vulnerability,
                    request.title(),
                    request.caseType(),
                    request.severity(),
                    request.description(),
                    request.awarenessAt(),
                    request.csirt());
            return Response.status(Response.Status.CREATED)
                    .entity(CraReportingCaseResponse.of(reportingCase))
                    .build();
        }
    }

    @GET
    @Path("/{caseUuid}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Returns a single CRA Art. 14 reporting case",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_READ</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The requested reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_READ})
    public Response getReportingCase(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = qm.getCraReportingCase(UUID.fromString(caseUuid));
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            requireAccess(qm, reportingCase.getProject());
            return Response.ok(CraReportingCaseResponse.of(reportingCase)).build();
        }
    }

    @POST
    @Path("/{caseUuid}/earlyWarning")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records the submission of the 24-hour early warning (CRA Art. 14(2)(a), 14(4)(a))",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response recordEarlyWarning(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid,
            CraReportingCaseSubmissionRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "submittedAt"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = getReportingCaseForUpdate(qm, caseUuid);
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            final CraReportingCase updated = qm.recordEarlyWarningSubmission(reportingCase, request.submittedAt());
            return Response.ok(CraReportingCaseResponse.of(updated)).build();
        }
    }

    @POST
    @Path("/{caseUuid}/fullNotification")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records the submission of the 72-hour full notification (CRA Art. 14(2)(b), 14(4)(b))",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response recordFullNotification(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid,
            CraReportingCaseSubmissionRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "submittedAt"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = getReportingCaseForUpdate(qm, caseUuid);
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            final CraReportingCase updated = qm.recordFullNotificationSubmission(reportingCase, request.submittedAt());
            return Response.ok(CraReportingCaseResponse.of(updated)).build();
        }
    }

    @POST
    @Path("/{caseUuid}/finalReport")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records the submission of the final report (CRA Art. 14(2)(c), 14(4)(b))",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response recordFinalReport(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid,
            CraReportingCaseSubmissionRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "submittedAt"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = getReportingCaseForUpdate(qm, caseUuid);
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            final CraReportingCase updated = qm.recordFinalReportSubmission(reportingCase, request.submittedAt());
            return Response.ok(CraReportingCaseResponse.of(updated)).build();
        }
    }

    @POST
    @Path("/{caseUuid}/customerNotification")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records that affected customers and users have been notified (CRA Art. 14(8))",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response recordCustomerNotification(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid,
            CraReportingCaseSubmissionRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "submittedAt"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = getReportingCaseForUpdate(qm, caseUuid);
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            final CraReportingCase updated = qm.recordCustomerNotification(reportingCase, request.submittedAt());
            return Response.ok(CraReportingCaseResponse.of(updated)).build();
        }
    }

    @POST
    @Path("/{caseUuid}/status")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Updates the status of a CRA Art. 14 reporting case",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The updated reporting case",
                        content = @Content(schema = @Schema(implementation = CraReportingCaseResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_UPDATE})
    public Response updateStatus(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid,
            CraReportingCaseStatusUpdateRequest request) {
        final Validator validator = super.getValidator();
        failOnValidationError(validator.validateProperty(request, "status"));
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = getReportingCaseForUpdate(qm, caseUuid);
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            final CraReportingCase updated = qm.updateCraReportingCaseStatus(reportingCase, request.status());
            return Response.ok(CraReportingCaseResponse.of(updated)).build();
        }
    }

    @DELETE
    @Path("/{caseUuid}")
    @Operation(
            summary = "Deletes a CRA Art. 14 reporting case",
            description =
                    "<p>Requires permission <strong>PORTFOLIO_MANAGEMENT</strong> or <strong>PORTFOLIO_MANAGEMENT_DELETE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(responseCode = "204", description = "The reporting case was deleted"),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the affected project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(responseCode = "404", description = "The reporting case could not be found")
            })
    @PermissionRequired({Permissions.Constants.PORTFOLIO_MANAGEMENT, Permissions.Constants.PORTFOLIO_MANAGEMENT_DELETE})
    public Response deleteReportingCase(
            @Parameter(
                            description = "The UUID of the reporting case",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @PathParam("caseUuid")
                    @ValidUuid
                    String caseUuid) {
        try (final var qm = new QueryManager(getAlpineRequest())) {
            final CraReportingCase reportingCase = qm.getCraReportingCase(UUID.fromString(caseUuid));
            if (reportingCase == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The reporting case could not be found.")
                        .build();
            }
            requireAccess(qm, reportingCase.getProject());
            qm.deleteCraReportingCase(reportingCase);
            return Response.status(Response.Status.NO_CONTENT).build();
        }
    }

    private CraReportingCase getReportingCaseForUpdate(final QueryManager qm, final String caseUuid) {
        final CraReportingCase reportingCase = qm.getCraReportingCase(UUID.fromString(caseUuid));
        if (reportingCase != null) {
            requireAccess(qm, reportingCase.getProject());
        }
        return reportingCase;
    }
}
