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

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.QueryManager;

import java.util.List;
import java.util.UUID;

/**
 * Computes a per-project SBOM data quality report aligned with the OpenChain
 * CRA Compliance Checklist sections 3.1 and 3.2 (SBOM generation and data
 * quality). The report assesses whether the component inventory of a project
 * carries the metadata expected in a CRA-conformant SBOM: unique identifiers
 * (PURL, CPE or SWHID), cryptographic hashes, and license information.
 *
 * @since 5.4.0
 */
public final class CraSbomQualityReport {

    private CraSbomQualityReport() {
    }

    /**
     * Computes the SBOM data quality report for the given project.
     *
     * @param qm      the QueryManager to use
     * @param project the project to assess
     * @return the report
     */
    public static Report compute(final QueryManager qm, final Project project) {
        final List<Component> components = qm.getAllComponents(project);
        final int total = components.size();
        int withUniqueIdentifier = 0;
        int withHash = 0;
        int withLicense = 0;
        for (final Component component : components) {
            if (hasUniqueIdentifier(component)) {
                withUniqueIdentifier++;
            }
            if (component.getSha256() != null
                    || component.getSha1() != null
                    || component.getMd5() != null
                    || component.getSha512() != null) {
                withHash++;
            }
            if (component.getLicense() != null
                    || component.getLicenseExpression() != null
                    || component.getLicenseUrl() != null) {
                withLicense++;
            }
        }
        return new Report(
                project.getUuid(),
                total,
                withUniqueIdentifier,
                withHash,
                withLicense,
                total > 0 ? (double) withUniqueIdentifier / total : 0,
                total > 0 ? (double) withHash / total : 0,
                total > 0 ? (double) withLicense / total : 0);
    }

    private static boolean hasUniqueIdentifier(final Component component) {
        return component.getPurlAsString() != null
                || component.getCpe() != null
                || component.getSwidTagId() != null;
    }

    /**
     * SBOM data quality report of a single project.
     *
     * @param projectUuid            UUID of the assessed project
     * @param componentCount         total number of components in the project
     * @param componentsWithIdentifier number of components carrying a unique identifier (PURL, CPE or SWHID)
     * @param componentsWithHash     number of components carrying a cryptographic hash
     * @param componentsWithLicense  number of components carrying license information
     * @param uniqueIdentifierRate   share of components with a unique identifier (0-1)
     * @param hashRate               share of components with a cryptographic hash (0-1)
     * @param licenseRate            share of components with license information (0-1)
     */
    public record Report(
            UUID projectUuid,
            int componentCount,
            int componentsWithIdentifier,
            int componentsWithHash,
            int componentsWithLicense,
            double uniqueIdentifierRate,
            double hashRate,
            double licenseRate) {}
}
