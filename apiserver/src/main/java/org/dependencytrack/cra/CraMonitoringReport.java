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

import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.VulnerabilityDao;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Computes a per-project vulnerability monitoring report aligned with the
 * OpenChain CRA Compliance Checklist section 4.1 (vulnerability ingestion and
 * monitoring), with emphasis on §4.1.4 (contextual enrichment such as EPSS
 * and KEV) and §4.1.6 (KEV as trigger for CRA Art. 14 assessment).
 *
 * @since 5.4.0
 */
public final class CraMonitoringReport {

    private CraMonitoringReport() {
    }

    /**
     * Computes the vulnerability monitoring report for the given project.
     *
     * @param qm      the QueryManager to use
     * @param project the project to assess
     * @return the report
     */
    public static Report compute(final QueryManager qm, final Project project) {
        final List<Vulnerability> vulnerabilities = withJdbiHandle(
                qm.getAlpineRequest(),
                handle -> handle.attach(VulnerabilityDao.class)
                        .getVulnerabilitiesByProject(project.getId(), /* includeSuppressed */ false));

        final Map<Severity, Integer> bySeverity = new EnumMap<>(Severity.class);
        int kevCount = 0;
        int epssEnrichedCount = 0;
        for (final Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getSeverity() != null) {
                bySeverity.merge(vulnerability.getSeverity(), 1, Integer::sum);
            }
            if (vulnerability.isKev()) {
                kevCount++;
            }
            if (vulnerability.getEpssScore() != null) {
                epssEnrichedCount++;
            }
        }
        return new Report(
                project.getUuid(),
                vulnerabilities.size(),
                kevCount,
                epssEnrichedCount,
                vulnerabilities.size() > 0 ? (double) epssEnrichedCount / vulnerabilities.size() : 0,
                Map.copyOf(bySeverity));
    }

    /**
     * Vulnerability monitoring report of a single project.
     *
     * @param projectUuid        UUID of the assessed project
     * @param vulnerabilityCount total number of distinct vulnerabilities affecting the project
     * @param kevCount           number of vulnerabilities listed in the CISA KEV catalog
     * @param epssEnrichedCount  number of vulnerabilities enriched with an EPSS score
     * @param epssEnrichmentRate share of vulnerabilities enriched with an EPSS score (0-1)
     * @param vulnerabilitiesBySeverity number of vulnerabilities per severity
     */
    public record Report(
            UUID projectUuid,
            int vulnerabilityCount,
            int kevCount,
            int epssEnrichedCount,
            double epssEnrichmentRate,
            Map<Severity, Integer> vulnerabilitiesBySeverity) {}
}
