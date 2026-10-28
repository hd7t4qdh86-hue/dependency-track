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

import java.time.Duration;
import java.time.Instant;

/**
 * Computes the notification deadlines of the CRA Art. 14 reporting cascade
 * (Regulation (EU) 2024/2847) from the moment the manufacturer becomes aware
 * of an actively exploited vulnerability or a severe incident.
 *
 * @since 5.4.0
 */
public final class CraReportingDeadlines {

    /**
     * Early warning deadline: 24 hours after awareness (CRA Art. 14(2)(a), 14(4)(a)).
     */
    public static final Duration EARLY_WARNING_WINDOW = Duration.ofHours(24);

    /**
     * Full notification / incident notification deadline: 72 hours after
     * awareness (CRA Art. 14(2)(b), 14(4)(b)).
     */
    public static final Duration FULL_NOTIFICATION_WINDOW = Duration.ofHours(72);

    /**
     * Final report deadline for actively exploited vulnerabilities: 14 days
     * after a corrective or mitigating measure becomes available
     * (CRA Art. 14(2)(c)). As the availability of a fix is not known when the
     * case is opened, this is approximated relative to awareness.
     */
    public static final Duration FINAL_REPORT_WINDOW_VULNERABILITY = Duration.ofDays(14);

    /**
     * Final report deadline for severe incidents: one month after submission
     * of the 72-hour incident notification (CRA Art. 14(4)(b)). As the
     * submission time is not known when the case is opened, this is
     * approximated relative to awareness.
     */
    public static final Duration FINAL_REPORT_WINDOW_INCIDENT = Duration.ofDays(30);

    private CraReportingDeadlines() {
    }

    /**
     * Computes the early warning deadline (awareness + 24 hours).
     *
     * @param awarenessAt The moment the organization became aware.
     * @return The early warning deadline.
     */
    public static Instant earlyWarningDueAt(final Instant awarenessAt) {
        return awarenessAt.plus(EARLY_WARNING_WINDOW);
    }

    /**
     * Computes the full notification deadline (awareness + 72 hours).
     *
     * @param awarenessAt The moment the organization became aware.
     * @return The full notification deadline.
     */
    public static Instant fullNotificationDueAt(final Instant awarenessAt) {
        return awarenessAt.plus(FULL_NOTIFICATION_WINDOW);
    }

    /**
     * Computes the final report deadline for the given case type. For
     * actively exploited vulnerabilities this is 14 days after awareness
     * (a proxy for "14 days after a fix becomes available"), for severe
     * incidents one month after awareness (a proxy for "one month after the
     * 72-hour notification").
     *
     * @param awarenessAt The moment the organization became aware.
     * @param caseType    The type of reporting case.
     * @return The final report deadline.
     */
    public static Instant finalReportDueAt(final Instant awarenessAt, final CraReportingCaseType caseType) {
        return awarenessAt.plus(switch (caseType) {
            case ACTIVELY_EXPLOITED_VULNERABILITY -> FINAL_REPORT_WINDOW_VULNERABILITY;
            case SEVERE_INCIDENT -> FINAL_REPORT_WINDOW_INCIDENT;
        });
    }

    /**
     * Returns whether the given deadline has passed at the given point in time.
     *
     * @param dueAt The deadline to check.
     * @param now   The reference time.
     * @return {@code true} if the deadline has passed.
     */
    public static boolean isOverdue(final Instant dueAt, final Instant now) {
        return now.isAfter(dueAt);
    }
}
