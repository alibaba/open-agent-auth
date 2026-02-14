/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.core.model.audit;

/**
 * Enumeration of audit event severity levels.
 * <p>
 * This enum defines the severity levels for audit events, enabling prioritization
 * and filtering based on the importance or impact of the event.
 * </p>
 * <p>
 * <b>Severity Levels:</b></p>
 * <ul>
 *   <li><b>INFO:</b> Informational events that indicate normal operation</li>
 *   <li><b>LOW:</b> Low severity events that may require attention</li>
 *   <li><b>MEDIUM:</b> Medium severity events that should be reviewed</li>
 *   <li><b>HIGH:</b> High severity events that require immediate attention</li>
 *   <li><b>CRITICAL:</b> Critical events that indicate a serious problem</li>
 * </ul>
 * </p>
 *
 * @see AuditEvent
 * @see AuditEventType
 */
public enum AuditSeverity {

    /**
     * Informational severity.
     * <p>
     * Indicates normal system operation or routine events that are
     * logged for informational purposes only.
     * </p>
     */
    INFO("Informational"),

    /**
     * Low severity.
     * <p>
     * Indicates minor issues or events that may require attention
     * but do not significantly impact system operation.
     * </p>
     */
    LOW("Low"),

    /**
     * Medium severity.
     * <p>
     * Indicates events that should be reviewed and may require
     * corrective action to prevent future problems.
     * </p>
     */
    MEDIUM("Medium"),

    /**
     * High severity.
     * <p>
     * Indicates significant issues or events that require immediate
     * attention and may impact system operation or security.
     * </p>
     */
    HIGH("High"),

    /**
     * Critical severity.
     * <p>
     * Indicates critical events that represent serious problems
     * requiring immediate action to prevent system failure or
     * security breaches.
     * </p>
     */
    CRITICAL("Critical");

    private final String description;

    /**
     * Creates an audit severity with the given description.
     *
     * @param description the description of the severity level
     */
    AuditSeverity(String description) {
        this.description = description;
    }

    /**
     * Gets the description of this severity level.
     *
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Determines if this severity level requires immediate attention.
     *
     * @return true if the severity is HIGH or CRITICAL
     */
    public boolean requiresImmediateAttention() {
        return this == HIGH || this == CRITICAL;
    }

    /**
     * Determines if this severity level is higher than the given severity.
     *
     * @param other the other severity to compare
     * @return true if this severity is higher
     */
    public boolean isHigherThan(AuditSeverity other) {
        return this.ordinal() > other.ordinal();
    }
}
