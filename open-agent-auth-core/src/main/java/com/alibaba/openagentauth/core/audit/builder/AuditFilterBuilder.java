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
package com.alibaba.openagentauth.core.audit.builder;

import com.alibaba.openagentauth.core.audit.api.AuditFilter;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;

import java.time.Instant;
import java.util.function.Predicate;

/**
 * Builder for creating {@link AuditFilter} instances with fluent API.
 * <p>
 * This builder provides a convenient and fluent API for constructing audit filters
 * with various criteria. It supports method chaining and provides helper methods
 * for common filtering scenarios.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * AuditFilter filter = AuditFilterBuilder.create()
 *     .eventType(AuditEventType.AUTHORIZATION_GRANTED)
 *     .severity(AuditSeverity.HIGH)
 *     .userId("user123")
 *     .build();
 * }</pre>
 * </p>
 *
 * @see AuditFilter
 */
public class AuditFilterBuilder {

    private Predicate<AuditEvent> predicate = event -> true;

    /**
     * Creates a new audit filter builder.
     */
    private AuditFilterBuilder() {
    }

    /**
     * Creates a new audit filter builder.
     *
     * @return a new builder instance
     */
    public static AuditFilterBuilder create() {
        return new AuditFilterBuilder();
    }

    /**
     * Filters by event type.
     *
     * @param eventType the event type to match
     * @return this builder instance
     */
    public AuditFilterBuilder eventType(AuditEventType eventType) {
        if (eventType != null) {
            predicate = predicate.and(event -> eventType.equals(event.getEventType()));
        }
        return this;
    }

    /**
     * Filters by severity.
     *
     * @param severity the severity to match
     * @return this builder instance
     */
    public AuditFilterBuilder severity(AuditSeverity severity) {
        if (severity != null) {
            predicate = predicate.and(event -> severity.equals(event.getSeverity()));
        }
        return this;
    }

    /**
     * Filters by user ID.
     *
     * @param userId the user ID to match
     * @return this builder instance
     */
    public AuditFilterBuilder userId(String userId) {
        if (userId != null) {
            predicate = predicate.and(event -> 
                event.getContext() != null && userId.equals(event.getContext().getUserId()));
        }
        return this;
    }

    /**
     * Filters by agent ID.
     *
     * @param agentId the agent ID to match
     * @return this builder instance
     */
    public AuditFilterBuilder agentId(String agentId) {
        if (agentId != null) {
            predicate = predicate.and(event -> 
                event.getContext() != null && agentId.equals(event.getContext().getAgentId()));
        }
        return this;
    }

    /**
     * Filters by session ID.
     *
     * @param sessionId the session ID to match
     * @return this builder instance
     */
    public AuditFilterBuilder sessionId(String sessionId) {
        if (sessionId != null) {
            predicate = predicate.and(event -> 
                event.getContext() != null && sessionId.equals(event.getContext().getSessionId()));
        }
        return this;
    }

    /**
     * Filters by time range.
     *
     * @param startTime the start of the time range (inclusive)
     * @param endTime   the end of the time range (inclusive)
     * @return this builder instance
     */
    public AuditFilterBuilder timeRange(Instant startTime, Instant endTime) {
        if (startTime != null && endTime != null) {
            predicate = predicate.and(event -> {
                Instant eventTime = Instant.parse(event.getTimestamp());
                return !eventTime.isBefore(startTime) && !eventTime.isAfter(endTime);
            });
        }
        return this;
    }

    /**
     * Filters by custom predicate.
     *
     * @param customPredicate the custom predicate
     * @return this builder instance
     */
    public AuditFilterBuilder custom(Predicate<AuditEvent> customPredicate) {
        if (customPredicate != null) {
            predicate = predicate.and(customPredicate);
        }
        return this;
    }

    /**
     * Filters events that require immediate attention (HIGH or CRITICAL severity).
     *
     * @return this builder instance
     */
    public AuditFilterBuilder requiresImmediateAttention() {
        predicate = predicate.and(event -> event.getSeverity().requiresImmediateAttention());
        return this;
    }

    /**
     * Builds the {@link AuditFilter}.
     *
     * @return the built audit filter
     */
    public AuditFilter build() {
        return predicate::test;
    }
}
