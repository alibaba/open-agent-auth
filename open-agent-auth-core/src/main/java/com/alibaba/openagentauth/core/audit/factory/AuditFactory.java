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
package com.alibaba.openagentauth.core.audit.factory;

import com.alibaba.openagentauth.core.audit.api.AuditStorage;
import com.alibaba.openagentauth.core.audit.builder.AuditEventBuilder;
import com.alibaba.openagentauth.core.audit.builder.AuditFilterBuilder;
import com.alibaba.openagentauth.core.audit.impl.DefaultAuditService;
import com.alibaba.openagentauth.core.audit.impl.InMemoryAuditStorage;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;

/**
 * Factory class for creating audit-related objects.
 * <p>
 * This factory provides convenient methods for creating audit events with
 * common configurations, reducing boilerplate code and ensuring consistency
 * across the application.
 * </p>
 * <p>
 * <b>Design Pattern:</b></p>
 * <ul>
 *   <li><b>Factory Method Pattern:</b> Encapsulates object creation logic</li>
 *   <li><b>Fluent Interface:</b> Provides a fluent API for object creation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * AuditEvent event = AuditFactory.createAuthorizationGrantedEvent()
 *     .userId("user123")
 *     .agentId("agent456")
 *     .message("Authorization granted for API access")
 *     .build();
 * }</pre>
 * </p>
 *
 * @see AuditEvent
 * @see AuditEventBuilder
 */
public final class AuditFactory {

    private AuditFactory() {
        // Prevent instantiation
    }

    /**
     * Creates a new audit event builder.
     *
     * @return a new audit event builder
     */
    public static AuditEventBuilder createEvent() {
        return AuditEventBuilder.create();
    }

    /**
     * Creates a new audit event builder for authorization granted events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createAuthorizationGrantedEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.AUTHORIZATION_GRANTED)
                .severity(AuditSeverity.INFO);
    }

    /**
     * Creates a new audit event builder for authorization denied events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createAuthorizationDeniedEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.AUTHORIZATION_DENIED)
                .severity(AuditSeverity.MEDIUM);
    }

    /**
     * Creates a new audit event builder for policy evaluation success events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createPolicyEvaluationSuccessEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.POLICY_EVALUATION_SUCCESS)
                .severity(AuditSeverity.INFO);
    }

    /**
     * Creates a new audit event builder for policy evaluation failure events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createPolicyEvaluationFailureEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.POLICY_EVALUATION_FAILURE)
                .severity(AuditSeverity.HIGH);
    }

    /**
     * Creates a new audit event builder for resource access granted events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createResourceAccessGrantedEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.RESOURCE_ACCESS_GRANTED)
                .severity(AuditSeverity.INFO);
    }

    /**
     * Creates a new audit event builder for resource access denied events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createResourceAccessDeniedEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.RESOURCE_ACCESS_DENIED)
                .severity(AuditSeverity.HIGH);
    }

    /**
     * Creates a new audit event builder for security violation events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createSecurityViolationEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.SECURITY_VIOLATION)
                .severity(AuditSeverity.CRITICAL);
    }

    /**
     * Creates a new audit event builder for authentication failure events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createAuthenticationFailureEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.AUTHENTICATION_FAILURE)
                .severity(AuditSeverity.HIGH);
    }

    /**
     * Creates a new audit event builder for suspicious activity events.
     *
     * @return a configured audit event builder
     */
    public static AuditEventBuilder createSuspiciousActivityEvent() {
        return AuditEventBuilder.create()
                .type(AuditEventType.SUSPICIOUS_ACTIVITY)
                .severity(AuditSeverity.HIGH);
    }

    /**
     * Creates a new audit filter builder.
     *
     * @return a new audit filter builder
     */
    public static AuditFilterBuilder createFilter() {
        return AuditFilterBuilder.create();
    }

    /**
     * Creates a new audit service with in-memory storage.
     *
     * @return a new audit service instance
     */
    public static DefaultAuditService createInMemoryAuditService() {
        return new DefaultAuditService(new InMemoryAuditStorage());
    }

    /**
     * Creates a new audit service with the specified storage.
     *
     * @param storage the audit storage implementation
     * @return a new audit service instance
     */
    public static DefaultAuditService createAuditService(AuditStorage storage) {
        return new DefaultAuditService(storage);
    }
}
