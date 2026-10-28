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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.CraReportingCaseStatus;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class CraReportingCaseDaoTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private CraReportingCaseDao dao;

    @BeforeEach
    void beforeEach() {
        jdbiHandle = openJdbiHandle();
        dao = jdbiHandle.attach(CraReportingCaseDao.class);
    }

    @AfterEach
    void afterEach() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }
    }

    @Test
    void shouldCreateAndRetrieveByUuid() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final UUID uuid = UUID.randomUUID();
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");

        dao.create(
                uuid,
                project.getId(),
                null,
                "Actively exploited log4shell",
                CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY,
                Severity.CRITICAL,
                "CVE-2021-44228 actively exploited in Acme Example 1.0",
                awarenessAt,
                awarenessAt.plusSeconds(24 * 3600),
                awarenessAt.plusSeconds(72 * 3600),
                awarenessAt.plusSeconds(14 * 24 * 3600),
                "CERT-DE",
                CraReportingCaseStatus.OPEN);

        final CraReportingCase reportingCase = dao.getByUuid(uuid);
        assertThat(reportingCase).isNotNull();
        assertThat(reportingCase.getProjectId()).isEqualTo(project.getId());
        assertThat(reportingCase.getTitle()).isEqualTo("Actively exploited log4shell");
        assertThat(reportingCase.getCaseType()).isEqualTo(CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY);
        assertThat(reportingCase.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(reportingCase.getAwarenessAt()).isEqualTo(awarenessAt);
        assertThat(reportingCase.getEarlyWarningDueAt()).isEqualTo(awarenessAt.plusSeconds(24 * 3600));
        assertThat(reportingCase.getFullNotificationDueAt()).isEqualTo(awarenessAt.plusSeconds(72 * 3600));
        assertThat(reportingCase.getFinalReportDueAt()).isEqualTo(awarenessAt.plusSeconds(14 * 24 * 3600));
        assertThat(reportingCase.getCsirt()).isEqualTo("CERT-DE");
        assertThat(reportingCase.getStatus()).isEqualTo(CraReportingCaseStatus.OPEN);
        assertThat(reportingCase.getCreatedAt()).isNotNull();
        assertThat(reportingCase.getUpdatedAt()).isNotNull();
    }

    @Test
    void shouldGetByProject() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Project otherProject = qm.createProject("Other", null, "2.0", null, null, null, null, false);
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");

        dao.create(
                UUID.randomUUID(),
                project.getId(),
                null,
                "Case A",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                awarenessAt,
                null,
                null,
                null,
                null,
                CraReportingCaseStatus.OPEN);
        dao.create(
                UUID.randomUUID(),
                otherProject.getId(),
                null,
                "Case B",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                awarenessAt,
                null,
                null,
                null,
                null,
                CraReportingCaseStatus.OPEN);

        assertThat(dao.getByProject(project.getId())).hasSize(1);
        assertThat(dao.getByProject(project.getId()).get(0).getTitle()).isEqualTo("Case A");
    }

    @Test
    void shouldGetOverdue() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");

        final UUID overdueUuid = UUID.randomUUID();
        dao.create(
                overdueUuid,
                project.getId(),
                null,
                "Overdue case",
                CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY,
                Severity.CRITICAL,
                null,
                awarenessAt,
                awarenessAt.plusSeconds(24 * 3600),
                awarenessAt.plusSeconds(72 * 3600),
                awarenessAt.plusSeconds(14 * 24 * 3600),
                null,
                CraReportingCaseStatus.OPEN);

        final UUID submittedUuid = UUID.randomUUID();
        dao.create(
                submittedUuid,
                project.getId(),
                null,
                "Submitted case",
                CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY,
                Severity.CRITICAL,
                null,
                awarenessAt,
                awarenessAt.plusSeconds(24 * 3600),
                awarenessAt.plusSeconds(72 * 3600),
                awarenessAt.plusSeconds(14 * 24 * 3600),
                null,
                CraReportingCaseStatus.OPEN);
        dao.recordEarlyWarningSubmission(
                dao.getByUuid(submittedUuid).getId(), awarenessAt.plusSeconds(3600), CraReportingCaseStatus.EARLY_WARNING_SUBMITTED);
        dao.recordFullNotificationSubmission(
                dao.getByUuid(submittedUuid).getId(),
                awarenessAt.plusSeconds(2 * 3600),
                CraReportingCaseStatus.FULL_NOTIFICATION_SUBMITTED);
        dao.recordFinalReportSubmission(
                dao.getByUuid(submittedUuid).getId(),
                awarenessAt.plusSeconds(3 * 3600),
                CraReportingCaseStatus.FINAL_REPORT_SUBMITTED);

        final var overdue = dao.getOverdue(Instant.parse("2026-09-12T10:00:01Z"));
        assertThat(overdue).extracting(CraReportingCase::getUuid).containsExactly(overdueUuid);
    }

    @Test
    void shouldRecordSubmissionsAndUpdateStatus() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final UUID uuid = UUID.randomUUID();
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        dao.create(
                uuid,
                project.getId(),
                null,
                "Case",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                awarenessAt,
                awarenessAt.plusSeconds(24 * 3600),
                awarenessAt.plusSeconds(72 * 3600),
                awarenessAt.plusSeconds(30 * 24 * 3600),
                null,
                CraReportingCaseStatus.OPEN);

        final long id = dao.getByUuid(uuid).getId();
        final Instant submittedAt = awarenessAt.plusSeconds(3600);

        assertThat(dao.recordEarlyWarningSubmission(id, submittedAt, CraReportingCaseStatus.EARLY_WARNING_SUBMITTED))
                .isEqualTo(1);
        CraReportingCase reportingCase = dao.getByUuid(uuid);
        assertThat(reportingCase.getEarlyWarningSubmittedAt()).isEqualTo(submittedAt);
        assertThat(reportingCase.getStatus()).isEqualTo(CraReportingCaseStatus.EARLY_WARNING_SUBMITTED);

        assertThat(dao.recordFullNotificationSubmission(
                        id, submittedAt.plusSeconds(3600), CraReportingCaseStatus.FULL_NOTIFICATION_SUBMITTED))
                .isEqualTo(1);
        reportingCase = dao.getByUuid(uuid);
        assertThat(reportingCase.getFullNotificationSubmittedAt()).isEqualTo(submittedAt.plusSeconds(3600));
        assertThat(reportingCase.getStatus()).isEqualTo(CraReportingCaseStatus.FULL_NOTIFICATION_SUBMITTED);

        assertThat(dao.recordFinalReportSubmission(
                        id, submittedAt.plusSeconds(7200), CraReportingCaseStatus.FINAL_REPORT_SUBMITTED))
                .isEqualTo(1);
        reportingCase = dao.getByUuid(uuid);
        assertThat(reportingCase.getFinalReportSubmittedAt()).isEqualTo(submittedAt.plusSeconds(7200));
        assertThat(reportingCase.getStatus()).isEqualTo(CraReportingCaseStatus.FINAL_REPORT_SUBMITTED);

        assertThat(dao.recordCustomerNotification(id, submittedAt.plusSeconds(10800))).isEqualTo(1);
        assertThat(dao.getByUuid(uuid).getCustomersNotifiedAt()).isEqualTo(submittedAt.plusSeconds(10800));

        assertThat(dao.updateStatus(id, CraReportingCaseStatus.CLOSED)).isEqualTo(1);
        assertThat(dao.getByUuid(uuid).getStatus()).isEqualTo(CraReportingCaseStatus.CLOSED);
    }

    @Test
    void shouldDelete() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final UUID uuid = UUID.randomUUID();
        dao.create(
                uuid,
                project.getId(),
                null,
                "Case",
                CraReportingCaseType.SEVERE_INCIDENT,
                null,
                null,
                Instant.parse("2026-09-11T10:00:00Z"),
                null,
                null,
                null,
                null,
                CraReportingCaseStatus.OPEN);

        assertThat(dao.delete(dao.getByUuid(uuid).getId())).isEqualTo(1);
        assertThat(dao.getByUuid(uuid)).isNull();
    }
}
