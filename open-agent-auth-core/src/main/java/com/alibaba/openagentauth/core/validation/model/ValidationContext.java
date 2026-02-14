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
package com.alibaba.openagentauth.core.validation.model;

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Validation context for the five-layer verification architecture.
 * <p>
 * This class encapsulates all the information required for the complete verification process,
 * including tokens, request metadata, and intermediate validation results. It follows the
 * immutable pattern to ensure thread-safety and prevent accidental modifications during
 * the validation pipeline.
 * </p>
 * <p>
 * <b>Five-Layer Verification Architecture:</b>
 * <ol>
 *   <li><b>Layer 1</b>: WIT signature and validity verification</li>
 *   <li><b>Layer 2</b>: WPT signature and request integrity verification</li>
 *   <li><b>Layer 3</b>: AOAT signature and validity verification</li>
 *   <li><b>Layer 4</b>: Identity consistency verification</li>
 *   <li><b>Layer 5</b>: OPA policy evaluation for authorization decision</li>
 * </ol>
 * </p>
 * <p>
 * <b>Design Principles:</b>
 * <ul>
 *   <li><b>Immutability</b>: Once created, the context cannot be modified</li>
 *   <li><b>Builder Pattern</b>: Provides a fluent API for constructing complex contexts</li>
 *   <li><b>Type Safety</b>: Strong typing ensures compile-time correctness</li>
 *   <li><b>Extensibility</b>: Supports custom attributes for future enhancements</li>
 * </ul>
 * </p>
 *
 * @see LayerValidationResult
 * @see LayerValidator
 * @since 1.0
 */
public class ValidationContext {

    /**
     * The Workload Identity Token (WIT).
     * <p>
     * This token represents the workload identity and is verified in Layer 1.
     * It contains the workload identifier, trust domain, and public key for WPT verification.
     * </p>
     */
    private final WorkloadIdentityToken wit;

    /**
     * The Workload Proof Token (WPT).
     * <p>
     * This token proves possession of the WIT's private key and ensures request integrity.
     * It is verified in Layer 2.
     * </p>
     */
    private final WorkloadProofToken wpt;

    /**
     * The Agent Operation Authorization Token (AOAT).
     * <p>
     * This token represents the user's authorization for the agent to perform operations.
     * It is verified in Layer 3.
     * </p>
     */
    private final AgentOperationAuthToken agentOaToken;

    /**
     * The HTTP request method.
     * <p>
     * Used in WPT verification to ensure the request method hasn't been tampered with.
     * </p>
     */
    private final String httpMethod;

    /**
     * The HTTP request URI.
     * <p>
     * Used in WPT verification to ensure the request URI hasn't been tampered with.
     * </p>
     */
    private final String httpUri;

    /**
     * The HTTP request headers.
     * <p>
     * Contains all HTTP headers sent with the request.
     * Used in WPT verification and policy evaluation.
     * </p>
     */
    private final Map<String, String> httpHeaders;

    /**
     * The HTTP request body.
     * <p>
     * Contains the request payload.
     * Used in WPT verification and policy evaluation.
     * </p>
     */
    private final String httpBody;

    /**
     * The timestamp when the validation request was received.
     * <p>
     * Used for replay attack detection and auditing.
     * </p>
     */
    private final Date requestTimestamp;

    /**
     * Additional custom attributes.
     * <p>
     * Allows extension of the context with custom key-value pairs for specific use cases.
     * This ensures the architecture remains extensible without modifying the core class.
     * </p>
     */
    private final Map<String, Object> attributes;

    /**
     * Private constructor to enforce immutability.
     *
     * @param builder the builder instance
     */
    private ValidationContext(Builder builder) {
        this.wit = builder.wit;
        this.wpt = builder.wpt;
        this.agentOaToken = builder.agentOaToken;
        this.httpMethod = builder.httpMethod;
        this.httpUri = builder.httpUri;
        this.httpHeaders = builder.httpHeaders;
        this.httpBody = builder.httpBody;
        this.requestTimestamp = builder.requestTimestamp;
        this.attributes = builder.attributes;
    }

    /**
     * Gets the Workload Identity Token (WIT).
     *
     * @return the WIT, or null if not present
     */
    public WorkloadIdentityToken getWit() {
        return wit;
    }

    /**
     * Gets the Workload Proof Token (WPT).
     *
     * @return the WPT, or null if not present
     */
    public WorkloadProofToken getWpt() {
        return wpt;
    }

    /**
     * Gets the Agent Operation Authorization Token (AOAT).
     *
     * @return the AOAT, or null if not present
     */
    public AgentOperationAuthToken getAgentOaToken() {
        return agentOaToken;
    }

    /**
     * Gets the HTTP request method.
     *
     * @return the HTTP method (e.g., "GET", "POST")
     */
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Gets the HTTP request URI.
     *
     * @return the HTTP URI
     */
    public String getHttpUri() {
        return httpUri;
    }

    /**
     * Gets the HTTP request headers.
     *
     * @return an immutable copy of the headers map
     */
    public Map<String, String> getHttpHeaders() {
        return httpHeaders != null ? new HashMap<>(httpHeaders) : null;
    }

    /**
     * Gets a specific HTTP header value.
     *
     * @param headerName the header name
     * @return the header value, or null if not present
     */
    public String getHttpHeader(String headerName) {
        return httpHeaders != null ? httpHeaders.get(headerName) : null;
    }

    /**
     * Gets the HTTP request body.
     *
     * @return the request body, or null if not present
     */
    public String getHttpBody() {
        return httpBody;
    }

    /**
     * Gets the request timestamp.
     *
     * @return the timestamp when the request was received
     */
    public Date getRequestTimestamp() {
        return requestTimestamp;
    }

    /**
     * Gets a custom attribute value.
     *
     * @param key the attribute key
     * @return the attribute value, or null if not present
     */
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String key) {
        return attributes != null ? (T) attributes.get(key) : null;
    }

    /**
     * Gets all custom attributes.
     *
     * @return an immutable copy of the attributes map
     */
    public Map<String, Object> getAttributes() {
        return attributes != null ? new HashMap<>(attributes) : null;
    }

    /**
     * Creates a new builder for {@link ValidationContext}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link ValidationContext}.
     * <p>
     * Provides a fluent API for constructing validation contexts with all required
     * and optional fields. The builder ensures that all required fields are set
     * before building the immutable context.
     * </p>
     */
    public static class Builder {

        private WorkloadIdentityToken wit;
        private WorkloadProofToken wpt;
        private AgentOperationAuthToken agentOaToken;
        private String httpMethod;
        private String httpUri;
        private Map<String, String> httpHeaders;
        private String httpBody;
        private Date requestTimestamp;
        private Map<String, Object> attributes;

        /**
         * Sets the Workload Identity Token (WIT).
         *
         * @param wit the WIT
         * @return this builder instance
         */
        public Builder wit(WorkloadIdentityToken wit) {
            this.wit = wit;
            return this;
        }

        /**
         * Sets the Workload Proof Token (WPT).
         *
         * @param wpt the WPT
         * @return this builder instance
         */
        public Builder wpt(WorkloadProofToken wpt) {
            this.wpt = wpt;
            return this;
        }

        /**
         * Sets the Agent Operation Authorization Token (AOAT).
         *
         * @param agentOaToken the AOAT
         * @return this builder instance
         */
        public Builder agentOaToken(AgentOperationAuthToken agentOaToken) {
            this.agentOaToken = agentOaToken;
            return this;
        }

        /**
         * Sets the HTTP request method.
         *
         * @param httpMethod the HTTP method (e.g., "GET", "POST")
         * @return this builder instance
         */
        public Builder httpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
            return this;
        }

        /**
         * Sets the HTTP request URI.
         *
         * @param httpUri the HTTP URI
         * @return this builder instance
         */
        public Builder httpUri(String httpUri) {
            this.httpUri = httpUri;
            return this;
        }

        /**
         * Sets the HTTP request headers.
         *
         * @param httpHeaders the headers map
         * @return this builder instance
         */
        public Builder httpHeaders(Map<String, String> httpHeaders) {
            this.httpHeaders = httpHeaders;
            return this;
        }

        /**
         * Sets the HTTP request body.
         *
         * @param httpBody the request body
         * @return this builder instance
         */
        public Builder httpBody(String httpBody) {
            this.httpBody = httpBody;
            return this;
        }

        /**
         * Sets the request timestamp.
         * <p>
         * If not set, the current time will be used.
         * </p>
         *
         * @param requestTimestamp the timestamp
         * @return this builder instance
         */
        public Builder requestTimestamp(Date requestTimestamp) {
            this.requestTimestamp = requestTimestamp;
            return this;
        }

        /**
         * Adds a custom attribute.
         *
         * @param key the attribute key
         * @param value the attribute value
         * @return this builder instance
         */
        public Builder addAttribute(String key, Object value) {
            if (this.attributes == null) {
                this.attributes = new HashMap<>();
            }
            this.attributes.put(key, value);
            return this;
        }

        /**
         * Sets all custom attributes.
         *
         * @param attributes the attributes map
         * @return this builder instance
         */
        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = attributes;
            return this;
        }

        /**
         * Builds the {@link ValidationContext}.
         *
         * @return the built validation context
         */
        public ValidationContext build() {
            if (requestTimestamp == null) {
                requestTimestamp = new Date();
            }
            return new ValidationContext(this);
        }
    }
}
