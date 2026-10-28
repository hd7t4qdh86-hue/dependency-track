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
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.ForeignKey;
import javax.jdo.annotations.ForeignKeyAction;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

/**
 * A reporting case under CRA Art. 14 (Regulation (EU) 2024/2847), tracking an
 * actively exploited vulnerability or a severe incident from the moment of
 * awareness through the notification cascade (early warning, full
 * notification, final report) to closure.
 *
 * @since 5.4.0
 */
@PersistenceCapable(table = "CRA_REPORTING_CASE")
@Unique(name = "CRA_REPORTING_CASE_UUID_UK", members = {"uuid"})
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CraReportingCase implements Serializable {

    private static final long serialVersionUID = 2871430915687153401L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "UUID", allowsNull = "false")
    @NotNull
    private UUID uuid;

    @Persistent
    @ForeignKey(
            name = "CRA_REPORTING_CASE_PROJECT_FK",
            updateAction = ForeignKeyAction.NONE,
            deleteAction = ForeignKeyAction.CASCADE,
            deferred = "true")
    @Column(name = "PROJECT_ID", allowsNull = "false")
    @JsonIgnore
    private Project project;

    @Persistent
    @ForeignKey(
            name = "CRA_REPORTING_CASE_VULN_FK",
            updateAction = ForeignKeyAction.NONE,
            deleteAction = ForeignKeyAction.CASCADE,
            deferred = "true")
    @Column(name = "VULNERABILITY_ID", allowsNull = "true")
    @JsonIgnore
    private Vulnerability vulnerability;

    @Persistent
    @Column(name = "TITLE", jdbcType = "CLOB", allowsNull = "false")
    @NotBlank
    private String title;

    @Persistent
    @Column(name = "CASE_TYPE", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private CraReportingCaseType caseType;

    @Persistent
    @Column(name = "SEVERITY", jdbcType = "VARCHAR", allowsNull = "true")
    private Severity severity;

    @Persistent
    @Column(name = "DESCRIPTION", jdbcType = "CLOB", allowsNull = "true")
    private String description;

    @Persistent
    @Column(name = "AWARENESS_AT", allowsNull = "false")
    @NotNull
    private Instant awarenessAt;

    @Persistent
    @Column(name = "EARLY_WARNING_DUE_AT", allowsNull = "true")
    private Instant earlyWarningDueAt;

    @Persistent
    @Column(name = "FULL_NOTIFICATION_DUE_AT", allowsNull = "true")
    private Instant fullNotificationDueAt;

    @Persistent
    @Column(name = "FINAL_REPORT_DUE_AT", allowsNull = "true")
    private Instant finalReportDueAt;

    @Persistent
    @Column(name = "EARLY_WARNING_SUBMITTED_AT", allowsNull = "true")
    private Instant earlyWarningSubmittedAt;

    @Persistent
    @Column(name = "FULL_NOTIFICATION_SUBMITTED_AT", allowsNull = "true")
    private Instant fullNotificationSubmittedAt;

    @Persistent
    @Column(name = "FINAL_REPORT_SUBMITTED_AT", allowsNull = "true")
    private Instant finalReportSubmittedAt;

    @Persistent
    @Column(name = "CUSTOMERS_NOTIFIED_AT", allowsNull = "true")
    private Instant customersNotifiedAt;

    @Persistent
    @Column(name = "CSIRT", jdbcType = "VARCHAR", allowsNull = "true")
    @Size(max = 255)
    private String csirt;

    @Persistent
    @Column(name = "STATUS", jdbcType = "VARCHAR", allowsNull = "false")
    @NotNull
    private CraReportingCaseStatus status;

    @Persistent
    @Column(name = "CREATED_AT", allowsNull = "false")
    private Instant createdAt;

    @Persistent
    @Column(name = "UPDATED_AT", allowsNull = "false")
    private Instant updatedAt;

    /**
     * Transient ID of the affected project. Populated when the case is loaded
     * through JDBI; not persisted separately.
     */
    @JsonIgnore
    private transient long projectId;

    /**
     * Transient ID of the affected vulnerability. Populated when the case is
     * loaded through JDBI; not persisted separately.
     */
    @JsonIgnore
    private transient Long vulnerabilityId;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public long getProjectId() {
        return projectId;
    }

    public void setProjectId(long projectId) {
        this.projectId = projectId;
    }

    public Long getVulnerabilityId() {
        return vulnerabilityId;
    }

    public void setVulnerabilityId(Long vulnerabilityId) {
        this.vulnerabilityId = vulnerabilityId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public CraReportingCaseType getCaseType() {
        return caseType;
    }

    public void setCaseType(CraReportingCaseType caseType) {
        this.caseType = caseType;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Instant getAwarenessAt() {
        return awarenessAt;
    }

    public void setAwarenessAt(Instant awarenessAt) {
        this.awarenessAt = awarenessAt;
    }

    public Instant getEarlyWarningDueAt() {
        return earlyWarningDueAt;
    }

    public void setEarlyWarningDueAt(Instant earlyWarningDueAt) {
        this.earlyWarningDueAt = earlyWarningDueAt;
    }

    public Instant getFullNotificationDueAt() {
        return fullNotificationDueAt;
    }

    public void setFullNotificationDueAt(Instant fullNotificationDueAt) {
        this.fullNotificationDueAt = fullNotificationDueAt;
    }

    public Instant getFinalReportDueAt() {
        return finalReportDueAt;
    }

    public void setFinalReportDueAt(Instant finalReportDueAt) {
        this.finalReportDueAt = finalReportDueAt;
    }

    public Instant getEarlyWarningSubmittedAt() {
        return earlyWarningSubmittedAt;
    }

    public void setEarlyWarningSubmittedAt(Instant earlyWarningSubmittedAt) {
        this.earlyWarningSubmittedAt = earlyWarningSubmittedAt;
    }

    public Instant getFullNotificationSubmittedAt() {
        return fullNotificationSubmittedAt;
    }

    public void setFullNotificationSubmittedAt(Instant fullNotificationSubmittedAt) {
        this.fullNotificationSubmittedAt = fullNotificationSubmittedAt;
    }

    public Instant getFinalReportSubmittedAt() {
        return finalReportSubmittedAt;
    }

    public void setFinalReportSubmittedAt(Instant finalReportSubmittedAt) {
        this.finalReportSubmittedAt = finalReportSubmittedAt;
    }

    public Instant getCustomersNotifiedAt() {
        return customersNotifiedAt;
    }

    public void setCustomersNotifiedAt(Instant customersNotifiedAt) {
        this.customersNotifiedAt = customersNotifiedAt;
    }

    public String getCsirt() {
        return csirt;
    }

    public void setCsirt(String csirt) {
        this.csirt = csirt;
    }

    public CraReportingCaseStatus getStatus() {
        return status;
    }

    public void setStatus(CraReportingCaseStatus status) {
        this.status = status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
