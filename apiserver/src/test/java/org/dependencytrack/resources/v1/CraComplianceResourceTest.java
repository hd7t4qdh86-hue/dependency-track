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
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class CraComplianceResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(new ResourceConfig(CraComplianceResource.class)
            .register(ApiFilter.class)
            .register(AuthFeature.class));

    @Test
    public void getComplianceMetadataTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        qm.setCraProductClass(project, org.dependencytrack.model.CraProductClass.IMPORTANT_CLASS_II);
        qm.setCraSupportPeriodEnd(project, java.time.Instant.parse("2031-09-11T00:00:00Z"));

        Response response = jersey.target("/v1/cra/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "productClass": "IMPORTANT_CLASS_II",
                  "supportPeriodEnd": "2031-09-11T00:00:00Z",
                  "supportPeriodExpired": false
                }
                """);
    }

    @Test
    public void getComplianceMetadataEmptyTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "supportPeriodExpired": false
                }
                """);
    }

    @Test
    public void getComplianceMetadataProjectNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_READ);

        Response response = jersey.target("/v1/cra/project/" + java.util.UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void setClassificationTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/project/" + project.getUuid() + "/classification")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {"productClass": "CRITICAL"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "productClass": "CRITICAL",
                  "supportPeriodExpired": false
                }
                """);
        assertThat(qm.getCraProductClass(project)).isEqualTo(org.dependencytrack.model.CraProductClass.CRITICAL);
    }

    @Test
    public void setClassificationInvalidTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/project/" + project.getUuid() + "/classification")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {"productClass": "NOT_A_CLASS"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    public void setSupportPeriodTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Response response = jersey.target("/v1/cra/project/" + project.getUuid() + "/supportPeriod")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {"supportPeriodEnd": "2027-01-01T00:00:00Z"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "supportPeriodEnd": "2027-01-01T00:00:00Z",
                  "supportPeriodExpired": false
                }
                """);
        assertThat(qm.getCraSupportPeriodEnd(project)).isEqualTo(java.time.Instant.parse("2027-01-01T00:00:00Z"));
    }

    @Test
    public void setSupportPeriodProjectNotFoundTest() {
        initializeWithPermissions(Permissions.PORTFOLIO_MANAGEMENT_UPDATE);

        Response response = jersey.target("/v1/cra/project/" + java.util.UUID.randomUUID() + "/supportPeriod")
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {"supportPeriodEnd": "2027-01-01T00:00:00Z"}
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    public void unauthorizedTest() {
        Response response = jersey.target("/v1/cra/project/" + java.util.UUID.randomUUID())
                .request()
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(401);
    }
}
