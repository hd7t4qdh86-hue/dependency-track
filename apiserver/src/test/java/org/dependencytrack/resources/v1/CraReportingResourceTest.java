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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class CraReportingResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig(CraReportingResource.class)
            .register(ApiFilter.class)
            .register(AuthFeature.class));

    @Test
    public void createAndGetReportingCaseTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2021-44228");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(vulnerability);

        Response response = jersey.target("/v1/cra/reporting/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "vulnId": "CVE-2021-44228",
                          "vulnSource": "NVD",
                          "title": "Actively exploited CVE-2021-44228",
                          "caseType": "ACTIVELY_EXPLOITED_VULNERABILITY",
                          "severity": "CRITICAL",
                          "description": "Active exploitation observed",
                          "awarenessAt": "2026-09-11T10:00:00Z",
                          "csirt": "CERT-DE"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "projectUuid": "${json-unit.ignore}",
                  "vulnerabilityUuid": "${json-unit.ignore}",
                  "vulnId": "CVE-2021-44228",
                  "title": "Actively exploited CVE-2021-44228",
                  "caseType": "ACTIVELY_EXPLOITED_VULNERABILITY",
                  "severity": "CRITICAL",
                  "description": "Active exploitation observed",
                  "awarenessAt": "2026-09-11T10:00:00Z",
                  "earlyWarningDueAt": "2026-09-12T10:00:00Z",
                  "fullNotificationDueAt": "2026-09-14T10:00:00Z",
                  "finalReportDueAt": "2026-09-25T10:00:00Z",
                  "csirt": "CERT-DE",
                  "status": "OPEN",
                  "overdue": false,
                  "createdAt": "${json-unit.ignore}",
                  "updatedAt": "${json-unit.ignore}"
                }
                """);

        final List<CraReportingCase> cases = qm.getCraReportingCases(project);
        assertThat(cases).hasSize(1);
        final CraReportingCase reportingCase = cases.get(0);

        Response getResponse = jersey.target("/v1/cra/reporting/" + reportingCase.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(getResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(getResponse)).node("title").isEqualTo("Actively exploited CVE-2021-44228");
    }

    @Test
    public void createReportingCaseProjectNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Response response = jersey.target("/v1/cra/reporting/project/" + java.util.UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "title": "Case",
                          "caseType": "SEVERE_INCIDENT",
                          "awarenessAt": "2026-09-11T10:00:00Z"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void createReportingCaseVulnerabilityNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/reporting/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "vulnId": "CVE-0000-0000",
                          "vulnSource": "NVD",
                          "title": "Case",
                          "caseType": "ACTIVELY_EXPLOITED_VULNERABILITY",
                          "awarenessAt": "2026-09-11T10:00:00Z"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void createReportingCaseValidationErrorTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_CREATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/reporting/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "title": "Case"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void getReportingCasesByProjectTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.createCraReportingCase(
                project,
                null,
                "Severe incident",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                Instant.parse("2026-09-11T10:00:00Z"),
                null);

        Response response = jersey.target("/v1/cra/reporting/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isArray().hasSize(1);
    }

    @Test
    public void getOverdueReportingCasesTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.createCraReportingCase(
                project,
                null,
                "Overdue case",
                CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY,
                Severity.CRITICAL,
                null,
                Instant.parse("2020-01-01T00:00:00Z"),
                null);

        Response response = jersey.target("/v1/cra/reporting/overdue")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isArray().isNotEmpty();
    }

    @Test
    public void recordSubmissionsTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final CraReportingCase reportingCase = qm.createCraReportingCase(
                project,
                null,
                "Case",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                Instant.parse("2026-09-11T10:00:00Z"),
                null);

        Response earlyWarningResponse = jersey.target("/v1/cra/reporting/" + reportingCase.getUuid() + "/earlyWarning")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {"submittedAt": "2026-09-11T11:00:00Z"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(earlyWarningResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(earlyWarningResponse))
                .node("status")
                .isEqualTo("EARLY_WARNING_SUBMITTED");
        assertThatJson(getPlainTextBody(earlyWarningResponse))
                .node("earlyWarningSubmittedAt")
                .isEqualTo("2026-09-11T11:00:00Z");

        Response fullNotificationResponse =
                jersey.target("/v1/cra/reporting/" + reportingCase.getUuid() + "/fullNotification")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .post(Entity.entity(/* language=JSON */ """
                                {"submittedAt": "2026-09-11T12:00:00Z"}
                                """, MediaType.APPLICATION_JSON));
        assertThat(fullNotificationResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(fullNotificationResponse))
                .node("status")
                .isEqualTo("FULL_NOTIFICATION_SUBMITTED");

        Response finalReportResponse = jersey.target("/v1/cra/reporting/" + reportingCase.getUuid() + "/finalReport")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {"submittedAt": "2026-09-11T13:00:00Z"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(finalReportResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(finalReportResponse)).node("status").isEqualTo("FINAL_REPORT_SUBMITTED");

        Response customerNotificationResponse =
                jersey.target("/v1/cra/reporting/" + reportingCase.getUuid() + "/customerNotification")
                        .request()
                        .header(X_API_KEY, apiKey)
                        .post(Entity.entity(/* language=JSON */ """
                                {"submittedAt": "2026-09-11T14:00:00Z"}
                                """, MediaType.APPLICATION_JSON));
        assertThat(customerNotificationResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(customerNotificationResponse))
                .node("customersNotifiedAt")
                .isEqualTo("2026-09-11T14:00:00Z");

        Response statusResponse = jersey.target("/v1/cra/reporting/" + reportingCase.getUuid() + "/status")
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {"status": "CLOSED"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(statusResponse.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(statusResponse)).node("status").isEqualTo("CLOSED");
    }

    @Test
    public void deleteReportingCaseTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_DELETE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final CraReportingCase reportingCase = qm.createCraReportingCase(
                project,
                null,
                "Case",
                CraReportingCaseType.SEVERE_INCIDENT,
                null,
                null,
                Instant.parse("2026-09-11T10:00:00Z"),
                null);

        Response response = jersey.target("/v1/cra/reporting/" + reportingCase.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getCraReportingCase(reportingCase.getUuid())).isNull();
    }

    @Test
    public void getReportingCaseNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Response response = jersey.target("/v1/cra/reporting/" + java.util.UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void unauthorizedTest() {
        Response response = jersey.target("/v1/cra/reporting/overdue")
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(401);
    }
}
