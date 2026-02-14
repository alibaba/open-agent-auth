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
package com.alibaba.openagentauth.core.audit.api;

import com.alibaba.openagentauth.core.model.audit.AuditEvent;

/**
 * Interface for filtering audit events.
 * <p>
 * This interface defines the contract for filtering audit events based on
 * various criteria. Implementations can provide filtering logic for
 * event types, severity levels, user IDs, agent IDs, time ranges, and
 * any other custom criteria.
 * </p>
 * <p>
 * <b>Design Pattern:</b></p>
 * <ul>
 *   <li><b>Strategy Pattern:</b> Different filter implementations can be
 *       plugged into the audit pipeline</li>
 *   <li><b>Chain of Responsibility:</b> Multiple filters can be chained
 *       together for complex filtering logic</li>
 * </ul>
 * </p>
 * <p>
 * <b>Implementation Considerations:</b></p>
 * <ul>
 *   <li>Implementations should be stateless and thread-safe</li>
 *   <li>Filters can be composed using logical operators (AND, OR, NOT)</li>
 *   <li>Consider implementing caching for frequently used filters</li>
 * </ul>
 * </p>
 *
 * @see AuditEvent
 * @see AuditProcessor
 */
@FunctionalInterface
public interface AuditFilter {

    /**
     * Determines if an audit event should be included or excluded.
     *
     * @param event the audit event to test
     * @return true if the event should be included, false otherwise
     */
    boolean matches(AuditEvent event);

    /**
     * Creates a composite filter that requires all filters to match.
     *
     * @param other the other filter to combine with
     * @return a composite filter that ANDs the two filters
     */
    default AuditFilter and(AuditFilter other) {
        return event -> this.matches(event) && other.matches(event);
    }

    /**
     * Creates a composite filter that requires at least one filter to match.
     *
     * @param other the other filter to combine with
     * @return a composite filter that ORs the two filters
     */
    default AuditFilter or(AuditFilter other) {
        return event -> this.matches(event) || other.matches(event);
    }

    /**
     * Creates a filter that negates this filter.
     *
     * @return a filter that NOTs this filter
     */
    default AuditFilter not() {
        return event -> !this.matches(event);
    }

}
