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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents an audit event in the Agent Operation Authorization framework.
 * <p>
 * An audit event captures a single occurrence of interest in the system,
 * such as an authorization decision, policy evaluation, resource access,
 * or security incident. Each event is timestamped, categorized, and
 * associated with contextual information to provide a comprehensive
 * audit trail.
 * </p>
 * <p>
 * <b>Event Structure:</b></p>
 * <ul>
 *   <li><b>Event ID:</b> Unique identifier for the event</li>
 *   <li><b>Timestamp:</b> When the event occurred (ISO 8601 UTC)</li>
 *   <li><b>Type:</b> The type of event (e.g., AUTHORIZATION_GRANTED)</li>
 *   <li><b>Severity:</b> The severity level (e.g., HIGH, CRITICAL)</li>
 *   <li><b>Context:</b> Contextual information about the event</li>
 *   <li><b>Trail:</b> The semantic audit trail (if applicable)</li>
 *   <li><b>Data:</b> Additional event-specific data</li>
 * </ul>
 * </p>
 *
 * @see AuditEventType
 * @see AuditSeverity
 * @see AuditContext
 * @see AuditTrail
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(builder = AuditEvent.Builder.class)
public class AuditEvent {

    /**
     * Unique event identifier.
     * <p>
     * A universally unique identifier (UUID) for this audit event.
     * This identifier can be used to reference the event in logs,
     * reports, and other systems.
     * </p>
     */
    private final String eventId;

    /**
     * Event timestamp.
     * <p>
     * The timestamp when the event occurred, in ISO 8601 UTC format.
     * This field is REQUIRED.
     * </p>
     */
    private final String timestamp;

    /**
     * Event type.
     * <p>
     * The type of audit event, categorized by its purpose and nature.
     * This field is REQUIRED.
     * </p>
     */
    private final AuditEventType eventType;

    /**
     * Event severity.
     * <p>
     * The severity level of the event, indicating its importance or impact.
     * This field is REQUIRED.
     * </p>
     */
    private final AuditSeverity severity;

    /**
     * Event message.
     * <p>
     * A human-readable description of the event.
     * This field is OPTIONAL.
     * </p>
     */
    private final String message;

    /**
     * Audit context.
     * <p>
     * Contextual information about the event, including user, agent,
     * session, and other metadata.
     * This field is OPTIONAL.
     * </p>
     */
    private final AuditContext context;

    /**
     * Audit trail.
     * <p>
     * The semantic audit trail associated with this event, providing
     * a traceable chain from user intent to system action.
     * This field is OPTIONAL.
     * </p>
     */
    private final AuditTrail trail;

    /**
     * Event data.
     * <p>
     * Additional event-specific data as key-value pairs.
     * This field is OPTIONAL.
     * </p>
     */
    private final Map<String, Object> data;

    private AuditEvent(Builder builder) {
        this.eventId = builder.eventId != null ? builder.eventId : UUID.randomUUID().toString();
        this.timestamp = builder.timestamp != null ? builder.timestamp : Instant.now().toString();
        this.eventType = builder.eventType;
        this.severity = builder.severity;
        this.message = builder.message;
        this.context = builder.context;
        this.trail = builder.trail;
        this.data = builder.data != null ? new HashMap<>(builder.data) : null;
    }

    /**
     * Gets the event identifier.
     *
     * @return the event identifier
     */
    public String getEventId() {
        return eventId;
    }

    /**
     * Gets the event timestamp.
     *
     * @return the timestamp in ISO 8601 format
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Gets the event type.
     *
     * @return the event type
     */
    public AuditEventType getEventType() {
        return eventType;
    }

    /**
     * Gets the event severity.
     *
     * @return the event severity
     */
    public AuditSeverity getSeverity() {
        return severity;
    }

    /**
     * Gets the event message.
     *
     * @return the event message
     */
    public String getMessage() {
        return message;
    }

    /**
     * Gets the audit context.
     *
     * @return the audit context
     */
    public AuditContext getContext() {
        return context;
    }

    /**
     * Gets the audit trail.
     *
     * @return the audit trail
     */
    public AuditTrail getTrail() {
        return trail;
    }

    /**
     * Gets the event data.
     *
     * @return an unmodifiable view of the data map
     */
    public Map<String, Object> getData() {
        return data != null ? new HashMap<>(data) : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditEvent auditEvent = (AuditEvent) o;
        return Objects.equals(eventId, auditEvent.eventId) &&
               Objects.equals(timestamp, auditEvent.timestamp) &&
               eventType == auditEvent.eventType &&
               severity == auditEvent.severity &&
               Objects.equals(message, auditEvent.message) &&
               Objects.equals(context, auditEvent.context) &&
               Objects.equals(trail, auditEvent.trail) &&
               Objects.equals(data, auditEvent.data);
    }

    @Override
    public int hashCode() {
        return Objects.hash(eventId, timestamp, eventType, severity, message, 
                          context, trail, data);
    }

    @Override
    public String toString() {
        return "AuditEvent{" +
                "eventId='" + eventId + '\'' +
                ", timestamp='" + timestamp + '\'' +
                ", eventType=" + eventType +
                ", severity=" + severity +
                ", message='" + message + '\'' +
                ", context=" + context +
                ", trail=" + trail +
                ", data=" + data +
                '}';
    }

    /**
     * Creates a new builder for {@link AuditEvent}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AuditEvent}.
     */
    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {

        private String eventId;
        private String timestamp;
        private AuditEventType eventType;
        private AuditSeverity severity;
        private String message;
        private AuditContext context;
        private AuditTrail trail;
        private Map<String, Object> data;

        /**
         * Sets the event identifier.
         * <p>
         * If not specified, a random UUID will be generated.
         * </p>
         *
         * @param eventId the event identifier
         * @return this builder instance
         */
        public Builder eventId(String eventId) {
            this.eventId = eventId;
            return this;
        }

        /**
         * Sets the event timestamp.
         * <p>
         * The value MUST conform to ISO 8601 UTC format.
         * If not specified, the current time will be used.
         * </p>
         *
         * @param timestamp the timestamp in ISO 8601 format
         * @return this builder instance
         */
        public Builder timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        /**
         * Sets the event type.
         *
         * @param eventType the event type
         * @return this builder instance
         */
        public Builder eventType(AuditEventType eventType) {
            this.eventType = eventType;
            return this;
        }

        /**
         * Sets the event severity.
         *
         * @param severity the event severity
         * @return this builder instance
         */
        public Builder severity(AuditSeverity severity) {
            this.severity = severity;
            return this;
        }

        /**
         * Sets the event message.
         *
         * @param message the event message
         * @return this builder instance
         */
        public Builder message(String message) {
            this.message = message;
            return this;
        }

        /**
         * Sets the audit context.
         *
         * @param context the audit context
         * @return this builder instance
         */
        public Builder context(AuditContext context) {
            this.context = context;
            return this;
        }

        /**
         * Sets the audit trail.
         *
         * @param trail the audit trail
         * @return this builder instance
         */
        public Builder trail(AuditTrail trail) {
            this.trail = trail;
            return this;
        }

        /**
         * Adds a data key-value pair.
         *
         * @param key   the data key
         * @param value the data value
         * @return this builder instance
         */
        public Builder addData(String key, Object value) {
            if (this.data == null) {
                this.data = new HashMap<>();
            }
            this.data.put(key, value);
            return this;
        }

        /**
         * Sets all event data.
         *
         * @param data the data map
         * @return this builder instance
         */
        public Builder data(Map<String, Object> data) {
            this.data = data;
            return this;
        }

        /**
         * Builds the {@link AuditEvent}.
         *
         * @return the built audit event
         * @throws IllegalStateException if eventType or severity is not set
         */
        public AuditEvent build() {
            if (eventType == null) {
                throw new IllegalStateException("eventType is required");
            }
            if (severity == null) {
                throw new IllegalStateException("severity is required");
            }
            return new AuditEvent(this);
        }
    }
}
