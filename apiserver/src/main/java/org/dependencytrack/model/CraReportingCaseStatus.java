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
package org.dependencytrack.model;

/**
 * Lifecycle status of a CRA Art. 14 reporting case, tracking which stages of
 * the notification cascade have been submitted to the CRA Single Reporting
 * Platform (SRP).
 *
 * @since 5.4.0
 */
public enum CraReportingCaseStatus {

    /**
     * The case has been recorded; no notification has been submitted yet.
     */
    OPEN,

    /**
     * The 24-hour early warning has been submitted.
     */
    EARLY_WARNING_SUBMITTED,

    /**
     * The 72-hour full notification (or incident notification) has been
     * submitted.
     */
    FULL_NOTIFICATION_SUBMITTED,

    /**
     * The final report (14 days for actively exploited vulnerabilities, one
     * month for severe incidents) has been submitted.
     */
    FINAL_REPORT_SUBMITTED,

    /**
     * The case is closed; all applicable obligations have been fulfilled.
     */
    CLOSED
}
