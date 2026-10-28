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
package org.dependencytrack.cra;

import org.dependencytrack.model.CraReportingCaseType;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class CraReportingDeadlinesTest {

    @Test
    void shouldComputeEarlyWarningDeadline24HoursAfterAwareness() {
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        assertThat(CraReportingDeadlines.earlyWarningDueAt(awarenessAt))
                .isEqualTo(Instant.parse("2026-09-12T10:00:00Z"));
    }

    @Test
    void shouldComputeFullNotificationDeadline72HoursAfterAwareness() {
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        assertThat(CraReportingDeadlines.fullNotificationDueAt(awarenessAt))
                .isEqualTo(Instant.parse("2026-09-14T10:00:00Z"));
    }

    @Test
    void shouldComputeFinalReportDeadline14DaysForActivelyExploitedVulnerability() {
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        assertThat(CraReportingDeadlines.finalReportDueAt(awarenessAt, CraReportingCaseType.ACTIVELY_EXPLOITED_VULNERABILITY))
                .isEqualTo(Instant.parse("2026-09-25T10:00:00Z"));
    }

    @Test
    void shouldComputeFinalReportDeadlineOneMonthForSevereIncident() {
        final Instant awarenessAt = Instant.parse("2026-09-11T10:00:00Z");
        assertThat(CraReportingDeadlines.finalReportDueAt(awarenessAt, CraReportingCaseType.SEVERE_INCIDENT))
                .isEqualTo(Instant.parse("2026-10-11T10:00:00Z"));
    }

    @Test
    void shouldDetectOverdueDeadlines() {
        final Instant dueAt = Instant.parse("2026-09-12T10:00:00Z");
        assertThat(CraReportingDeadlines.isOverdue(dueAt, Instant.parse("2026-09-12T09:59:59Z")))
                .isFalse();
        assertThat(CraReportingDeadlines.isOverdue(dueAt, Instant.parse("2026-09-12T10:00:00Z")))
                .isFalse();
        assertThat(CraReportingDeadlines.isOverdue(dueAt, Instant.parse("2026-09-12T10:00:01Z")))
                .isTrue();
    }
}
