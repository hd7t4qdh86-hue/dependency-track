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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.CraProductClass;
import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.CraReportingCaseStatus;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CraQueryManagerTest extends PersistenceCapableTest {

    @Test
    void shouldSetAndGetCraProductClass() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        assertThat(qm.getCraProductClass(project)).isNull();

        qm.setCraProductClass(project, CraProductClass.IMPORTANT_CLASS_I);
        assertThat(qm.getCraProductClass(project)).isEqualTo(CraProductClass.IMPORTANT_CLASS_I);

        qm.setCraProductClass(project, CraProductClass.DEFAULT);
        assertThat(qm.getCraProductClass(project)).isEqualTo(CraProductClass.DEFAULT);
    }

    @Test
    void shouldSetAndGetCraSupportPeriodEnd() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Instant supportPeriodEnd = Instant.parse("2031-09-11T00:00:00Z");

        assertThat(qm.getCraSupportPeriodEnd(project)).isNull();

        qm.setCraSupportPeriodEnd(project, supportPeriodEnd);
        assertThat(qm.getCraSupportPeriodEnd(project)).isEqualTo(supportPeriodEnd);
    }

    @Test
    void shouldCreateCraReportingCaseWithComputedDeadlines() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("CVE-2021-44228");
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.createVulnerability(vulnerability);

        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        final CraReportingCase reportingCase = qm.createCraReportingCase(
                project,
                vulnerability,
                "Actively exploited CVE-2021-44228",
                CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY,
                Severity.CRITICAL,
                "Active exploitation observed in the wild",
                awarenessAt,
                "CERT-DE");

        assertThat(reportingCase.getUuid()).isNotNull();
        assertThat(reportingCase.getStatus()).isEqualTo(CraReportingCaseStatus.OPEN);
        assertThat(reportingCase.getAwarenessAt()).isEqualTo(awarenessAt);
        assertThat(reportingCase.getEarlyWarningDueAt()).isEqualTo(awarenessAt.plusSeconds(24 * 3600));
        assertThat(reportingCase.getFullNotificationDueAt()).isEqualTo(awarenessAt.plusSeconds(72 * 3600));
        assertThat(reportingCase.getFinalReportDueAt()).isEqualTo(awarenessAt.plusSeconds(14 * 24 * 3600));
        assertThat(reportingCase.getCsirt()).isEqualTo("CERT-DE");
        assertThat(reportingCase.getVulnerability()).isNotNull();
        assertThat(reportingCase.getVulnerability().getVulnId()).isEqualTo("CVE-2021-44228");

        final CraReportingCase loaded = qm.getCraReportingCase(reportingCase.getUuid());
        assertThat(loaded).isNotNull();
        assertThat(loaded.getTitle()).isEqualTo("Actively exploited CVE-2021-44228");

        final List<CraReportingCase> cases = qm.getCraReportingCases(project);
        assertThat(cases).hasSize(1);
    }

    @Test
    void shouldCreateCraReportingCaseWithoutVulnerability() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");

        final CraReportingCase reportingCase = qm.createCraReportingCase(
                project,
                null,
                "Severe incident",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                awarenessAt,
                null);

        assertThat(reportingCase.getVulnerability()).isNull();
        assertThat(reportingCase.getFinalReportDueAt()).isEqualTo(awarenessAt.plusSeconds(30 * 24 * 3600));
    }

    @Test
    void shouldTrackReportingCaseLifecycle() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        final CraReportingCase reportingCase = qm.createCraReportingCase(
                project,
                null,
                "Case",
                CraReportingCaseType.SEVERE_INCIDENT,
                Severity.HIGH,
                null,
                awarenessAt,
                null);

        final CraReportingCase afterEarlyWarning =
                qm.recordEarlyWarningSubmission(reportingCase, awarenessAt.plusSeconds(3600));
        assertThat(afterEarlyWarning.getStatus()).isEqualTo(CraReportingCaseStatus.EARLY_WARNING_SUBMITTED);
        assertThat(afterEarlyWarning.getEarlyWarningSubmittedAt()).isEqualTo(awarenessAt.plusSeconds(3600));

        final CraReportingCase afterFullNotification =
                qm.recordFullNotificationSubmission(reportingCase, awarenessAt.plusSeconds(2 * 3600));
        assertThat(afterFullNotification.getStatus()).isEqualTo(CraReportingCaseStatus.FULL_NOTIFICATION_SUBMITTED);

        final CraReportingCase afterFinalReport =
                qm.recordFinalReportSubmission(reportingCase, awarenessAt.plusSeconds(3 * 3600));
        assertThat(afterFinalReport.getStatus()).isEqualTo(CraReportingCaseStatus.FINAL_REPORT_SUBMITTED);

        final CraReportingCase afterCustomerNotification =
                qm.recordCustomerNotification(reportingCase, awarenessAt.plusSeconds(4 * 3600));
        assertThat(afterCustomerNotification.getCustomersNotifiedAt()).isEqualTo(awarenessAt.plusSeconds(4 * 3600));

        final CraReportingCase closed = qm.updateCraReportingCaseStatus(reportingCase, CraReportingCaseStatus.CLOSED);
        assertThat(closed.getStatus()).isEqualTo(CraReportingCaseStatus.CLOSED);

        qm.deleteCraReportingCase(reportingCase);
        assertThat(qm.getCraReportingCase(reportingCase.getUuid())).isNull();
    }

    @Test
    void shouldGetOverdueCraReportingCases() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        qm.createCraReportingCase(
                project,
                null,
                "Overdue case",
                CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY,
                Severity.CRITICAL,
                null,
                awarenessAt,
                null);

        assertThat(qm.getOverdueCraReportingCases())
                .isNotEmpty()
                .allSatisfy(reportingCase -> assertThat(reportingCase.getEarlyWarningSubmittedAt()).isNull());
    }
}
