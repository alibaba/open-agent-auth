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

import com.alibaba.openagentauth.core.model.audit.AuditContext;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import com.alibaba.openagentauth.core.model.audit.AuditTrail;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Builder for creating {@link AuditEvent} instances with fluent API.
 * <p>
 * This builder provides a convenient and fluent API for constructing audit events
 * with all required and optional fields. It supports method chaining and provides
 * helper methods for common scenarios.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * AuditEvent event = AuditEventBuilder.create()
 *     .type(AuditEventType.AUTHORIZATION_GRANTED)
 *     .severity(AuditSeverity.INFO)
 *     .message("Authorization granted for user")
 *     .userId("user123")
 *     .agentId("agent456")
 *     .addData("resource", "/api/orders")
 *     .build();
 * }</pre>
 * </p>
 *
 * @see AuditEvent
 */
public class AuditEventBuilder {

    private final AuditEvent.Builder eventBuilder;
    private final AuditContext.Builder contextBuilder;
    private Map<String, Object> data;

    /**
     * Creates a new audit event builder.
     */
    private AuditEventBuilder() {
        this.eventBuilder = AuditEvent.builder();
        this.contextBuilder = AuditContext.builder();
        this.data = new HashMap<>();
    }

    /**
     * Creates a new audit event builder.
     *
     * @return a new builder instance
     */
    public static AuditEventBuilder create() {
        return new AuditEventBuilder();
    }

    /**
     * Sets the event identifier.
     *
     * @param eventId the event identifier
     * @return this builder instance
     */
    public AuditEventBuilder eventId(String eventId) {
        eventBuilder.eventId(eventId);
        return this;
    }

    /**
     * Sets the event timestamp.
     *
     * @param timestamp the timestamp in ISO 8601 format
     * @return this builder instance
     */
    public AuditEventBuilder timestamp(String timestamp) {
        eventBuilder.timestamp(timestamp);
        return this;
    }

    /**
     * Sets the event timestamp from an {@link Instant}.
     *
     * @param instant the timestamp
     * @return this builder instance
     */
    public AuditEventBuilder timestamp(Instant instant) {
        eventBuilder.timestamp(instant.toString());
        return this;
    }

    /**
     * Sets the event type.
     *
     * @param eventType the event type
     * @return this builder instance
     */
    public AuditEventBuilder type(AuditEventType eventType) {
        eventBuilder.eventType(eventType);
        return this;
    }

    /**
     * Sets the event severity.
     *
     * @param severity the event severity
     * @return this builder instance
     */
    public AuditEventBuilder severity(AuditSeverity severity) {
        eventBuilder.severity(severity);
        return this;
    }

    /**
     * Sets the event message.
     *
     * @param message the event message
     * @return this builder instance
     */
    public AuditEventBuilder message(String message) {
        eventBuilder.message(message);
        return this;
    }

    /**
     * Sets the audit trail.
     *
     * @param trail the audit trail
     * @return this builder instance
     */
    public AuditEventBuilder trail(AuditTrail trail) {
        eventBuilder.trail(trail);
        return this;
    }

    /**
     * Sets the user identifier.
     *
     * @param userId the user identifier
     * @return this builder instance
     */
    public AuditEventBuilder userId(String userId) {
        contextBuilder.userId(userId);
        return this;
    }

    /**
     * Sets the agent identifier.
     *
     * @param agentId the agent identifier
     * @return this builder instance
     */
    public AuditEventBuilder agentId(String agentId) {
        contextBuilder.agentId(agentId);
        return this;
    }

    /**
     * Sets the session identifier.
     *
     * @param sessionId the session identifier
     * @return this builder instance
     */
    public AuditEventBuilder sessionId(String sessionId) {
        contextBuilder.sessionId(sessionId);
        return this;
    }

    /**
     * Sets the request identifier.
     *
     * @param requestId the request identifier
     * @return this builder instance
     */
    public AuditEventBuilder requestId(String requestId) {
        contextBuilder.requestId(requestId);
        return this;
    }

    /**
     * Sets the client IP address.
     *
     * @param clientIpAddress the client IP address
     * @return this builder instance
     */
    public AuditEventBuilder clientIpAddress(String clientIpAddress) {
        contextBuilder.clientIpAddress(clientIpAddress);
        return this;
    }

    /**
     * Sets the user agent string.
     *
     * @param userAgent the user agent string
     * @return this builder instance
     */
    public AuditEventBuilder userAgent(String userAgent) {
        contextBuilder.userAgent(userAgent);
        return this;
    }

    /**
     * Adds a context metadata key-value pair.
     *
     * @param key   the metadata key
     * @param value the metadata value
     * @return this builder instance
     */
    public AuditEventBuilder addContextMetadata(String key, Object value) {
        contextBuilder.addMetadata(key, value);
        return this;
    }

    /**
     * Adds an event data key-value pair.
     *
     * @param key   the data key
     * @param value the data value
     * @return this builder instance
     */
    public AuditEventBuilder addData(String key, Object value) {
        data.put(key, value);
        return this;
    }

    /**
     * Sets all event data.
     *
     * @param data the data map
     * @return this builder instance
     */
    public AuditEventBuilder data(Map<String, Object> data) {
        this.data = new HashMap<>(data);
        return this;
    }

    /**
     * Applies a consumer function to configure the builder.
     *
     * @param consumer the consumer function
     * @return this builder instance
     */
    public AuditEventBuilder configure(Consumer<AuditEventBuilder> consumer) {
        consumer.accept(this);
        return this;
    }

    /**
     * Builds the {@link AuditEvent}.
     *
     * @return the built audit event
     */
    public AuditEvent build() {
        // Build context if any fields were set
        AuditContext context = contextBuilder.build();
        eventBuilder.context(context);
        
        // Set data if not empty
        if (!data.isEmpty()) {
            eventBuilder.data(data);
        }
        
        return eventBuilder.build();
    }
}
