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
package com.alibaba.openagentauth.core.model.oauth2.authorization;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Represents an OAuth 2.0 Authorization Request with associated metadata.
 * <p>
 * This class decouples the state parameter from business semantics (flow type, session ID, etc.)
 * by storing authorization request metadata server-side, keyed by an opaque state value.
 * This follows the approach used by Spring Security's {@code OAuth2AuthorizationRequest} and
 * aligns with RFC 6749 Section 10.12, which recommends the state parameter be an opaque,
 * unguessable value used solely for CSRF protection.
 * </p>
 *
 * <h3>Design Rationale</h3>
 * <p>
 * Previously, the framework encoded flow type and session ID directly into the state parameter
 * (e.g., {@code agent:UUID:sessionId}). This approach had several drawbacks:
 * </p>
 * <ul>
 *   <li>Violated RFC 6749's recommendation for opaque state values</li>
 *   <li>Limited extensibility — adding new metadata required changing the state format</li>
 *   <li>Exposed internal routing information to external parties</li>
 *   <li>Created tight coupling between state generation and state parsing</li>
 * </ul>
 * <p>
 * The new design stores all metadata server-side in an
 * {@link com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage},
 * making the state parameter a pure CSRF token.
 * </p>
 *
 * @since 1.1
 * @see com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage
 */
public class OAuth2AuthorizationRequest implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String state;
    private final FlowType flowType;
    private final String sessionId;
    private final Instant createdAt;
    private final Map<String, Object> additionalParameters;

    private OAuth2AuthorizationRequest(Builder builder) {
        this.state = Objects.requireNonNull(builder.state, "state cannot be null");
        this.flowType = Objects.requireNonNull(builder.flowType, "flowType cannot be null");
        this.sessionId = builder.sessionId;
        this.createdAt = builder.createdAt != null ? builder.createdAt : Instant.now();
        this.additionalParameters = builder.additionalParameters != null
                ? Map.copyOf(builder.additionalParameters)
                : Collections.emptyMap();
    }

    /**
     * Returns the opaque state parameter used for CSRF protection.
     * <p>
     * Per RFC 6749 Section 10.12, this value is an unguessable, opaque string
     * that is bound to the user-agent's authenticated state.
     * </p>
     *
     * @return the state parameter
     */
    public String getState() {
        return state;
    }

    /**
     * Returns the authorization flow type.
     * <p>
     * This determines how the callback should be processed:
     * </p>
     * <ul>
     *   <li>{@link FlowType#USER_AUTHENTICATION}: OIDC user authentication via User IDP</li>
     *   <li>{@link FlowType#AGENT_OPERATION_AUTH}: Agent Operation Authorization per
     *       draft-liu-agent-operation-authorization-01</li>
     * </ul>
     *
     * @return the flow type
     */
    public FlowType getFlowType() {
        return flowType;
    }

    /**
     * Returns the session ID for cross-domain session restoration.
     * <p>
     * This is primarily used in the Agent Operation Authorization flow where
     * the authorization redirect may cross domain boundaries, requiring explicit
     * session restoration rather than relying on HTTP cookies.
     * </p>
     *
     * @return the session ID, or null if not applicable
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Returns the timestamp when this authorization request was created.
     *
     * @return the creation timestamp
     */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Returns additional parameters associated with this authorization request.
     * <p>
     * This extensible map allows framework users to attach custom metadata
     * to authorization requests without modifying the core model.
     * </p>
     *
     * @return an unmodifiable map of additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    /**
     * Creates a new builder for constructing {@link OAuth2AuthorizationRequest} instances.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Authorization flow type.
     * <p>
     * Defines the type of OAuth 2.0 authorization flow, which determines
     * how the callback response should be processed.
     * </p>
     *
     * @since 1.1
     */
    public enum FlowType {

        /**
         * User authentication flow via OIDC/OAuth 2.0.
         * <p>
         * The callback exchanges the authorization code for an ID Token
         * and establishes user authentication state in the HTTP session.
         * </p>
         */
        USER_AUTHENTICATION,

        /**
         * Agent Operation Authorization flow per draft-liu-agent-operation-authorization-01.
         * <p>
         * The callback exchanges the authorization code for an Agent Operation
         * Authorization Token (AOAT) via {@code Agent.handleAuthorizationCallback()}.
         * </p>
         */
        AGENT_OPERATION_AUTH,

        /**
         * Unknown or unrecognized flow type.
         * <p>
         * Used as a fallback when the authorization request cannot be resolved
         * from the storage. The callback service will treat this as a
         * default user authentication flow.
         * </p>
         */
        UNKNOWN
    }

    /**
     * Builder for {@link OAuth2AuthorizationRequest}.
     */
    public static class Builder {

        private String state;
        private FlowType flowType;
        private String sessionId;
        private Instant createdAt;
        private Map<String, Object> additionalParameters;

        /**
         * Sets the opaque state parameter.
         *
         * @param state the state value
         * @return this builder
         */
        public Builder state(String state) {
            this.state = state;
            return this;
        }

        /**
         * Sets the authorization flow type.
         *
         * @param flowType the flow type
         * @return this builder
         */
        public Builder flowType(FlowType flowType) {
            this.flowType = flowType;
            return this;
        }

        /**
         * Sets the session ID for cross-domain session restoration.
         *
         * @param sessionId the session ID (nullable)
         * @return this builder
         */
        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        /**
         * Sets the creation timestamp.
         *
         * @param createdAt the creation time (defaults to now if not set)
         * @return this builder
         */
        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        /**
         * Sets additional parameters.
         *
         * @param additionalParameters the additional parameters map
         * @return this builder
         */
        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }

        /**
         * Builds the {@link OAuth2AuthorizationRequest} instance.
         *
         * @return the constructed authorization request
         * @throws NullPointerException if state or flowType is null
         */
        public OAuth2AuthorizationRequest build() {
            return new OAuth2AuthorizationRequest(this);
        }
    }
}
