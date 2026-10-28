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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class CraSbomQualityResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig(CraSbomQualityResource.class)
            .register(ApiFilter.class)
            .register(AuthFeature.class));

    @Test
    public void getSbomQualityReportTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final Component complete = new Component();
        complete.setProject(project);
        complete.setName("complete-component");
        complete.setVersion("1.0.0");
        complete.setPurl("pkg:maven/org.acme/complete@1.0.0");
        complete.setSha256("a".repeat(64));
        complete.setLicense("Apache-2.0");
        qm.createComponent(complete, false);

        final Component incomplete = new Component();
        incomplete.setProject(project);
        incomplete.setName("incomplete-component");
        qm.createComponent(incomplete, false);

        Response response = jersey.target("/v1/cra/sbomQuality/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "projectUuid": "${json-unit.ignore}",
                  "componentCount": 2,
                  "componentsWithIdentifier": 1,
                  "componentsWithHash": 1,
                  "componentsWithLicense": 1,
                  "uniqueIdentifierRate": 0.5,
                  "hashRate": 0.5,
                  "licenseRate": 0.5
                }
                """);
    }

    @Test
    public void getSbomQualityReportEmptyProjectTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/sbomQuality/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "projectUuid": "${json-unit.ignore}",
                  "componentCount": 0,
                  "componentsWithIdentifier": 0,
                  "componentsWithHash": 0,
                  "componentsWithLicense": 0,
                  "uniqueIdentifierRate": 0,
                  "hashRate": 0,
                  "licenseRate": 0
                }
                """);
    }

    @Test
    public void getMonitoringReportTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Component component = new Component();
        component.setProject(project);
        component.setName("log4j-core");
        component.setVersion("2.14.1");
        qm.createComponent(component, false);

        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2021-44228");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(vulnerability);
        qm.addVulnerability(vulnerability, component, "test");

        Response response = jersey.target("/v1/cra/sbomQuality/monitoring/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "projectUuid": "${json-unit.ignore}",
                  "vulnerabilityCount": 1,
                  "kevCount": 0,
                  "epssEnrichedCount": 0,
                  "epssEnrichmentRate": 0,
                  "vulnerabilitiesBySeverity": {
                    "CRITICAL": 1
                  }
                }
                """);
    }

    @Test
    public void getSbomQualityReportProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_PORTFOLIO);

        Response response = jersey.target("/v1/cra/sbomQuality/project/" + java.util.UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void unauthorizedTest() {
        Response response = jersey.target("/v1/cra/sbomQuality/project/" + java.util.UUID.randomUUID())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(401);
    }
}
