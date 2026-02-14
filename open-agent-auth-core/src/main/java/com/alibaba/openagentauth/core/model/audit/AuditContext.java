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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents the context information associated with an audit event.
 * <p>
 * The audit context provides additional metadata about the environment,
 * participants, and conditions under which an audit event occurred.
 * This includes information about the user, agent, session, and any
 * additional contextual data relevant to the event.
 * </p>
 * <p>
 * <b>Context Information:</b></p>
 * <ul>
 *   <li><b>User:</b> User identifier and authentication information</li>
 *   <li><b>Agent:</b> Agent identifier and workload information</li>
 *   <li><b>Session:</b> Session identifier and creation time</li>
 *   <li><b>Metadata:</b> Additional key-value metadata</li>
 * </ul>
 * </p>
 *
 * @see AuditEvent
 * @see AuditTrail
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditContext {

    /**
     * User identifier.
     * <p>
     * The unique identifier of the user who initiated or is associated
     * with the audit event. This is typically the subject identifier
     * from an authenticated identity token.
     * </p>
     */
    private final String userId;

    /**
     * Agent identifier.
     * <p>
     * The unique identifier of the agent involved in the audit event.
     * This corresponds to the agent_identity claim in the authorization token.
     * </p>
     */
    private final String agentId;

    /**
     * Session identifier.
     * <p>
     * The unique identifier of the session in which the event occurred.
     * This can be used to correlate multiple events within the same session.
     * </p>
     */
    private final String sessionId;

    /**
     * Request identifier.
     * <p>
     * The unique identifier of the request that triggered the audit event.
     * This can be used to correlate audit events with specific requests.
     * </p>
     */
    private final String requestId;

    /**
     * Client IP address.
     * <p>
     * The IP address of the client that initiated the request.
     * This is useful for security analysis and fraud detection.
     * </p>
     */
    private final String clientIpAddress;

    /**
     * User agent string.
     * <p>
     * The user agent string of the client, providing information about
     * the client software and version.
     * </p>
     */
    private final String userAgent;

    /**
     * Additional metadata.
     * <p>
     * Additional key-value pairs that provide context-specific information
     * about the audit event. This allows for flexible extension of the
     * context without modifying the schema.
     * </p>
     */
    private final Map<String, Object> metadata;

    private AuditContext(Builder builder) {
        this.userId = builder.userId;
        this.agentId = builder.agentId;
        this.sessionId = builder.sessionId;
        this.requestId = builder.requestId;
        this.clientIpAddress = builder.clientIpAddress;
        this.userAgent = builder.userAgent;
        this.metadata = builder.metadata != null ? new HashMap<>(builder.metadata) : null;
    }

    /**
     * Gets the user identifier.
     *
     * @return the user identifier
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Gets the agent identifier.
     *
     * @return the agent identifier
     */
    public String getAgentId() {
        return agentId;
    }

    /**
     * Gets the session identifier.
     *
     * @return the session identifier
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Gets the request identifier.
     *
     * @return the request identifier
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * Gets the client IP address.
     *
     * @return the client IP address
     */
    public String getClientIpAddress() {
        return clientIpAddress;
    }

    /**
     * Gets the user agent string.
     *
     * @return the user agent string
     */
    public String getUserAgent() {
        return userAgent;
    }

    /**
     * Gets the additional metadata.
     *
     * @return an unmodifiable view of the metadata map
     */
    public Map<String, Object> getMetadata() {
        return metadata != null ? new HashMap<>(metadata) : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditContext that = (AuditContext) o;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(agentId, that.agentId) &&
               Objects.equals(sessionId, that.sessionId) &&
               Objects.equals(requestId, that.requestId) &&
               Objects.equals(clientIpAddress, that.clientIpAddress) &&
               Objects.equals(userAgent, that.userAgent) &&
               Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, agentId, sessionId, requestId, 
                          clientIpAddress, userAgent, metadata);
    }

    @Override
    public String toString() {
        return "AuditContext{" +
                "userId='" + userId + '\'' +
                ", agentId='" + agentId + '\'' +
                ", sessionId='" + sessionId + '\'' +
                ", requestId='" + requestId + '\'' +
                ", clientIpAddress='" + clientIpAddress + '\'' +
                ", userAgent='" + userAgent + '\'' +
                ", metadata=" + metadata +
                '}';
    }

    /**
     * Creates a new builder for {@link AuditContext}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AuditContext}.
     */
    public static class Builder {

        private String userId;
        private String agentId;
        private String sessionId;
        private String requestId;
        private String clientIpAddress;
        private String userAgent;
        private Map<String, Object> metadata;

        /**
         * Sets the user identifier.
         *
         * @param userId the user identifier
         * @return this builder instance
         */
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        /**
         * Sets the agent identifier.
         *
         * @param agentId the agent identifier
         * @return this builder instance
         */
        public Builder agentId(String agentId) {
            this.agentId = agentId;
            return this;
        }

        /**
         * Sets the session identifier.
         *
         * @param sessionId the session identifier
         * @return this builder instance
         */
        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        /**
         * Sets the request identifier.
         *
         * @param requestId the request identifier
         * @return this builder instance
         */
        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        /**
         * Sets the client IP address.
         *
         * @param clientIpAddress the client IP address
         * @return this builder instance
         */
        public Builder clientIpAddress(String clientIpAddress) {
            this.clientIpAddress = clientIpAddress;
            return this;
        }

        /**
         * Sets the user agent string.
         *
         * @param userAgent the user agent string
         * @return this builder instance
         */
        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        /**
         * Adds a metadata key-value pair.
         *
         * @param key   the metadata key
         * @param value the metadata value
         * @return this builder instance
         */
        public Builder addMetadata(String key, Object value) {
            if (this.metadata == null) {
                this.metadata = new HashMap<>();
            }
            this.metadata.put(key, value);
            return this;
        }

        /**
         * Sets all metadata.
         *
         * @param metadata the metadata map
         * @return this builder instance
         */
        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        /**
         * Builds the {@link AuditContext}.
         *
         * @return the built audit context
         */
        public AuditContext build() {
            return new AuditContext(this);
        }
    }
}
