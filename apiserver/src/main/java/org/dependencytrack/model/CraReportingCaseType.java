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
 * distributed under the Apache License, Version 2.0 (the "License");
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
 * Type of a CRA Art. 14 reporting case. Determines the applicable
 * notification deadlines: an actively exploited vulnerability triggers the
 * 24h/72h/14-day cascade of Art. 14(1)-(2), while a severe incident triggers
 * the 24h/72h/one-month cascade of Art. 14(3)-(5).
 *
 * @since 5.4.0
 */
public enum CraReportingCaseType {

    /**
     * An actively exploited vulnerability contained in a product with digital
     * elements (CRA Art. 14(1)-(2)): early warning within 24 hours, full
     * notification within 72 hours, final report within 14 days after a
     * corrective or mitigating measure becomes available.
     */
    ACTIVELY_EXPLOITED_VULNERABILITY,

    /**
     * A severe incident affecting the availability, authenticity, integrity or
     * confidentiality of the product (CRA Art. 14(3)-(5)): early warning within
     * 24 hours, incident notification within 72 hours, final report within one
     * month after the 72-hour notification.
     */
    SEVERE_INCIDENT
}
