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

import alpine.model.IConfigProperty.PropertyType;
import alpine.resources.AlpineRequest;
import com.fasterxml.uuid.Generators;
import org.dependencytrack.cra.CraReportingDeadlines;
import org.dependencytrack.model.CraProductClass;
import org.dependencytrack.model.CraReportingCase;
import org.dependencytrack.model.CraReportingCaseStatus;
import org.dependencytrack.model.CraReportingCaseType;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.CraReportingCaseDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityDao;
import org.jspecify.annotations.Nullable;

import javax.jdo.PersistenceManager;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * QueryManager for EU Cyber Resilience Act (Regulation (EU) 2024/2847)
 * compliance data: CRA product classification and support period metadata of
 * projects, and CRA Art. 14 reporting cases.
 *
 * @since 5.4.0
 */
public class CraQueryManager extends QueryManager {

    /**
     * Group name under which CRA metadata is stored as project properties.
     */
    public static final String CRA_PROPERTY_GROUP = "cra";

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    CraQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    CraQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns the CRA product classification of the given project, as recorded
     * per CRA Art. 6 and Annexes III-IV.
     *
     * @param project the Project to retrieve the classification for
     * @return the classification, or {@code null} if none has been recorded
     */
    public @Nullable CraProductClass getCraProductClass(final Project project) {
        final var property = getProjectProperty(project, CRA_PROPERTY_GROUP, "productClass");
        if (property == null || property.getPropertyValue() == null) {
            return null;
        }
        try {
            return CraProductClass.valueOf(property.getPropertyValue());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Records the CRA product classification of the given project.
     *
     * @param project      the Project to classify
     * @param productClass the classification per CRA Art. 6 and Annexes III-IV
     * @return the updated Project
     */
    public Project setCraProductClass(final Project project, final CraProductClass productClass) {
        setCraProperty(project, "productClass", productClass.name());
        return project;
    }

    /**
     * Returns the end-of-support date of the given project, as declared per
     * CRA Art. 13(8).
     *
     * @param project the Project to retrieve the end-of-support date for
     * @return the end-of-support date, or {@code null} if none has been recorded
     */
    public @Nullable Instant getCraSupportPeriodEnd(final Project project) {
        final var property = getProjectProperty(project, CRA_PROPERTY_GROUP, "supportPeriodEnd");
        if (property == null || property.getPropertyValue() == null) {
            return null;
        }
        try {
            return Instant.parse(property.getPropertyValue());
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /**
     * Records the end-of-support date of the given project, as required by
     * CRA Art. 13(8) (at least five years after market placement unless the
     * expected product lifetime is shorter).
     *
     * @param project          the Project to record the end-of-support date for
     * @param supportPeriodEnd the end-of-support date
     * @return the updated Project
     */
    public Project setCraSupportPeriodEnd(final Project project, final Instant supportPeriodEnd) {
        setCraProperty(project, "supportPeriodEnd", supportPeriodEnd.toString());
        return project;
    }

    /**
     * Creates a new CRA Art. 14 reporting case for the given project. The
     * notification deadlines of the three-stage cascade are derived from the
     * moment of awareness.
     *
     * @param project       the affected Project
     * @param vulnerability the affected Vulnerability, or {@code null} for severe incidents
     * @param title         a short title for the case
     * @param caseType      the type of reporting case
     * @param severity      the severity of the case, or {@code null}
     * @param description   a description of the case, or {@code null}
     * @param awarenessAt   the moment the organization became aware
     * @param csirt         the national CSIRT designated as coordinator, or {@code null}
     * @return the created CraReportingCase
     */
    public CraReportingCase createCraReportingCase(
            final Project project,
            final @Nullable Vulnerability vulnerability,
            final String title,
            final CraReportingCaseType caseType,
            final @Nullable Severity severity,
            final @Nullable String description,
            final Instant awarenessAt,
            final @Nullable String csirt) {
        final UUID uuid = Generators.timeBasedEpochGenerator().generate();
        final Instant earlyWarningDueAt = CraReportingDeadlines.earlyWarningDueAt(awarenessAt);
        final Instant fullNotificationDueAt = CraReportingDeadlines.fullNotificationDueAt(awarenessAt);
        final Instant finalReportDueAt = CraReportingDeadlines.finalReportDueAt(awarenessAt, caseType);
        return inJdbiTransaction(handle -> {
            final Long projectId = handle.attach(ProjectDao.class).getProjectId(project.getUuid());
            if (projectId == null) {
                throw new IllegalStateException("Project does not exist: " + project.getUuid());
            }
            Long vulnerabilityId = null;
            if (vulnerability != null) {
                final Vulnerability persistentVulnerability = handle
                        .attach(VulnerabilityDao.class)
                        .getByVulnIdAndSource(vulnerability.getVulnId(), vulnerability.getSource());
                if (persistentVulnerability == null) {
                    throw new IllegalStateException("Vulnerability does not exist: " + vulnerability.getVulnId());
                }
                vulnerabilityId = persistentVulnerability.getId();
            }
            handle.attach(CraReportingCaseDao.class)
                    .create(
                            uuid,
                            projectId,
                            vulnerabilityId,
                            title,
                            caseType,
                            severity,
                            description,
                            awarenessAt,
                            earlyWarningDueAt,
                            fullNotificationDueAt,
                            finalReportDueAt,
                            csirt,
                            CraReportingCaseStatus.OPEN);
            final CraReportingCase reportingCase =
                    handle.attach(CraReportingCaseDao.class).getByUuid(uuid);
            attachProjectAndVulnerability(reportingCase);
            return reportingCase;
        });
    }

    /**
     * Returns a CRA Art. 14 reporting case by its UUID.
     *
     * @param uuid the UUID of the case
     * @return the CraReportingCase, or {@code null} if not found
     */
    public @Nullable CraReportingCase getCraReportingCase(final UUID uuid) {
        return withJdbiHandle(handle -> {
            final CraReportingCase reportingCase = handle.attach(CraReportingCaseDao.class).getByUuid(uuid);
            if (reportingCase != null) {
                attachProjectAndVulnerability(reportingCase);
            }
            return reportingCase;
        });
    }

    /**
     * Returns all CRA Art. 14 reporting cases of the given project, most
     * recently recorded awareness first.
     *
     * @param project the Project to retrieve cases for
     * @return a list of CraReportingCase objects, possibly empty
     */
    public List<CraReportingCase> getCraReportingCases(final Project project) {
        return withJdbiHandle(handle -> {
            final List<CraReportingCase> reportingCases =
                    handle.attach(CraReportingCaseDao.class).getByProject(project.getId());
            reportingCases.forEach(this::attachProjectAndVulnerability);
            return reportingCases;
        });
    }

    /**
     * Returns all open CRA Art. 14 reporting cases with at least one overdue
     * notification deadline.
     *
     * @return a list of overdue CraReportingCase objects, possibly empty
     */
    public List<CraReportingCase> getOverdueCraReportingCases() {
        return withJdbiHandle(handle -> {
            final List<CraReportingCase> reportingCases =
                    handle.attach(CraReportingCaseDao.class).getOverdue(Instant.now());
            reportingCases.forEach(this::attachProjectAndVulnerability);
            return reportingCases;
        });
    }

    /**
     * Records the submission of the 24-hour early warning for a reporting case.
     *
     * @param reportingCase the reporting case
     * @param submittedAt   the time of submission
     * @return the updated CraReportingCase, or {@code null} if not found
     */
    public @Nullable CraReportingCase recordEarlyWarningSubmission(
            final CraReportingCase reportingCase, final Instant submittedAt) {
        return inJdbiTransaction(handle -> {
            final int updated = handle
                    .attach(CraReportingCaseDao.class)
                    .recordEarlyWarningSubmission(
                            reportingCase.getId(), submittedAt, CraReportingCaseStatus.EARLY_WARNING_SUBMITTED);
            if (updated == 0) {
                return null;
            }
            final CraReportingCase reloaded =
                    handle.attach(CraReportingCaseDao.class).getByUuid(reportingCase.getUuid());
            attachProjectAndVulnerability(reloaded);
            return reloaded;
        });
    }

    /**
     * Records the submission of the 72-hour full notification for a reporting case.
     *
     * @param reportingCase the reporting case
     * @param submittedAt   the time of submission
     * @return the updated CraReportingCase, or {@code null} if not found
     */
    public @Nullable CraReportingCase recordFullNotificationSubmission(
            final CraReportingCase reportingCase, final Instant submittedAt) {
        return inJdbiTransaction(handle -> {
            final int updated = handle
                    .attach(CraReportingCaseDao.class)
                    .recordFullNotificationSubmission(
                            reportingCase.getId(), submittedAt, CraReportingCaseStatus.FULL_NOTIFICATION_SUBMITTED);
            if (updated == 0) {
                return null;
            }
            final CraReportingCase reloaded =
                    handle.attach(CraReportingCaseDao.class).getByUuid(reportingCase.getUuid());
            attachProjectAndVulnerability(reloaded);
            return reloaded;
        });
    }

    /**
     * Records the submission of the final report for a reporting case.
     *
     * @param reportingCase the reporting case
     * @param submittedAt   the time of submission
     * @return the updated CraReportingCase, or {@code null} if not found
     */
    public @Nullable CraReportingCase recordFinalReportSubmission(
            final CraReportingCase reportingCase, final Instant submittedAt) {
        return inJdbiTransaction(handle -> {
            final int updated = handle
                    .attach(CraReportingCaseDao.class)
                    .recordFinalReportSubmission(
                            reportingCase.getId(), submittedAt, CraReportingCaseStatus.FINAL_REPORT_SUBMITTED);
            if (updated == 0) {
                return null;
            }
            final CraReportingCase reloaded =
                    handle.attach(CraReportingCaseDao.class).getByUuid(reportingCase.getUuid());
            attachProjectAndVulnerability(reloaded);
            return reloaded;
        });
    }

    /**
     * Records that affected customers and users have been notified, as required
     * by CRA Art. 14(8).
     *
     * @param reportingCase the reporting case
     * @param notifiedAt    the time of notification
     * @return the updated CraReportingCase, or {@code null} if not found
     */
    public @Nullable CraReportingCase recordCustomerNotification(
            final CraReportingCase reportingCase, final Instant notifiedAt) {
        return inJdbiTransaction(handle -> {
            final int updated = handle
                    .attach(CraReportingCaseDao.class)
                    .recordCustomerNotification(reportingCase.getId(), notifiedAt);
            if (updated == 0) {
                return null;
            }
            final CraReportingCase reloaded =
                    handle.attach(CraReportingCaseDao.class).getByUuid(reportingCase.getUuid());
            attachProjectAndVulnerability(reloaded);
            return reloaded;
        });
    }

    /**
     * Updates the status of a reporting case, e.g. to close it.
     *
     * @param reportingCase the reporting case
     * @param status        the new status
     * @return the updated CraReportingCase, or {@code null} if not found
     */
    public @Nullable CraReportingCase updateCraReportingCaseStatus(
            final CraReportingCase reportingCase, final CraReportingCaseStatus status) {
        return inJdbiTransaction(handle -> {
            final int updated = handle.attach(CraReportingCaseDao.class).updateStatus(reportingCase.getId(), status);
            if (updated == 0) {
                return null;
            }
            final CraReportingCase reloaded =
                    handle.attach(CraReportingCaseDao.class).getByUuid(reportingCase.getUuid());
            attachProjectAndVulnerability(reloaded);
            return reloaded;
        });
    }

    /**
     * Deletes a CRA Art. 14 reporting case.
     *
     * @param reportingCase the reporting case to delete
     */
    public void deleteCraReportingCase(final CraReportingCase reportingCase) {
        inJdbiTransaction(handle -> {
            handle.attach(CraReportingCaseDao.class).delete(reportingCase.getId());
            return null;
        });
    }

    private void attachProjectAndVulnerability(final CraReportingCase reportingCase) {
        final Project project = getObjectById(Project.class, reportingCase.getProjectId());
        reportingCase.setProject(project);
        if (reportingCase.getVulnerabilityId() != null) {
            reportingCase.setVulnerability(getObjectById(Vulnerability.class, reportingCase.getVulnerabilityId()));
        }
    }

    private void setCraProperty(final Project project, final String propertyName, final String value) {
        callInTransaction(() -> {
            var property = getProjectProperty(project, CRA_PROPERTY_GROUP, propertyName);
            if (property == null) {
                createProjectProperty(
                        project,
                        CRA_PROPERTY_GROUP,
                        propertyName,
                        value,
                        PropertyType.STRING,
                        "CRA (Regulation (EU) 2024/2847) metadata");
            } else {
                property.setPropertyValue(value);
                persist(property);
            }
        });
    }
}
