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
package com.alibaba.openagentauth.framework.model.context;

import com.alibaba.openagentauth.framework.web.authorization.AuthorizationRequestContext;

import java.util.Collections;
import java.util.Map;

/**
 * Authorization context for agent execution.
 * <p>
 * This class encapsulates all necessary authorization credentials for tool execution,
 * including Workload Identity Token, Workload Proof Token, and Agent Operation
 * Authorization Token. Protocol-specific adapters (MCP, FC, API, etc.) should use
 * this context to inject credentials into their respective transport layers.
 * </p>
 *
 * <h3>Core Components:</h3>
 * <ul>
 *   <li><b>WIT (Workload Identity Token):</b> Identifies and authenticates the workload</li>
 *   <li><b>WPT (Workload Proof Token):</b> Proves the integrity and authenticity of the request</li>
 *   <li><b>AOAT (Agent Operation Authorization Token):</b> Contains user identity, operation authorization, and audit information</li>
 * </ul>
 *
 * <h3>Thread Safety:</h3>
 * <p>
 * This class is immutable and therefore thread-safe. All fields are declared {@code final}
 * and the additional headers map is wrapped in an unmodifiable collection. Instances can be
 * safely shared across multiple threads without synchronization.
 * </p>
 *
 * <h3>Security Considerations:</h3>
 * <ul>
 *   <li>Tokens contained in this context are sensitive security credentials</li>
 *   <li>Context instances should not be logged or serialized to insecure storage</li>
 *   <li>Instances should have a limited lifecycle matching the token expiration times</li>
 *   <li>The unmodifiable map prevents external modification but does not protect contained values</li>
 * </ul>
 *
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * // Build authorization context
 * AgentAuthorizationContext context = AgentAuthorizationContext.builder()
 *     .wit(workloadIdentityToken)
 *     .wpt(workloadProofToken)
 *     .aoat(agentOperationAuthToken)
 *     .additionalHeaders(customHeaders)
 *     .build();
 *
 * // MCP Protocol Adapter injection
 * HttpRequest request = HttpRequest.newBuilder()
 *     .uri(URI.create("https://api.example.com/tool"))
 *     .header("Authorization", "Bearer " + context.getAoat())
 *     .header("X-Workload-Identity", context.getWit())
 *     .header("X-Workload-Proof", context.getWpt())
 *     .build();
 *
 * // Additional headers can be merged with protocol-specific headers
 * Map<String, String> allHeaders = new HashMap<>();
 * allHeaders.putAll(context.getAdditionalHeaders());
 * allHeaders.put("X-Custom-Header", "value");
 * }</pre>
 *
 * <h3>Related Specifications:</h3>
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc6750">RFC 6750 - OAuth 2.0 Bearer Token Usage</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc9700">RFC 9700 - OAuth 2.0 Security Best Current Practice</a></li>
 *   <li>draft-liu-agent-operation-authorization-01 - Agent Operation Authorization Protocol</li>
 * </ul>
 *
 * @see Builder
 * @see AuthorizationRequestContext
 * @since 1.0
 */
public class AgentAuthorizationContext {

    private final String wit;
    private final String wpt;
    private final String aoat;
    private final Map<String, String> additionalHeaders;

    private AgentAuthorizationContext(Builder builder) {
        this.wit = builder.wit;
        this.wpt = builder.wpt;
        this.aoat = builder.aoat;
        this.additionalHeaders = builder.additionalHeaders != null 
            ? Map.copyOf(builder.additionalHeaders)
            : Collections.emptyMap();
    }

    /**
     * Gets the Workload Identity Token (WIT).
     * <p>
     * The WIT identifies and authenticates the workload making the request.
     * This token is typically issued by the Workload Identity Management system
     * and contains claims about the workload's identity and attributes.
     * </p>
     *
     * @return the WIT, or {@code null} if not set
     */
    public String getWit() {
        return wit;
    }

    /**
     * Gets the Workload Proof Token (WPT).
     * <p>
     * The WPT proves the integrity and authenticity of the request by demonstrating
     * that the request originated from the authenticated workload. This token is
     * cryptographically bound to the workload and the specific request context.
     * </p>
     *
     * @return the WPT, or {@code null} if not set
     */
    public String getWpt() {
        return wpt;
    }

    /**
     * Gets the Agent Operation Authorization Token (AOAT).
     * <p>
     * The AOAT contains user identity, operation authorization, and audit information.
     * It represents the user's consent for the agent to perform a specific operation
     * and includes all necessary claims for authorization decisions.
     * </p>
     * <p>
     * This token should be transmitted using the {@code Authorization} header with
     * the {@code Bearer} scheme, as specified in RFC 6750.
     * </p>
     *
     * @return the AOAT, or {@code null} if not set
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6750">RFC 6750</a>
     */
    public String getAoat() {
        return aoat;
    }

    /**
     * Gets additional authorization headers.
     * <p>
     * Returns an unmodifiable map of additional headers that should be included
     * in authorization requests. This allows protocol-specific extensions and
     * custom headers to be passed through the authorization layer.
     * </p>
     * <p>
     * The returned map is unmodifiable; attempts to modify it will result in an
     * {@code UnsupportedOperationException}.
     * </p>
     *
     * @return an unmodifiable map of additional headers, or an empty map if none
     */
    public Map<String, String> getAdditionalHeaders() {
        return additionalHeaders;
    }

    /**
     * Creates a new builder for AgentAuthorizationContext.
     * <p>
     * The builder provides a fluent API for constructing authorization context
     * instances with all required and optional fields.
     * </p>
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for AgentAuthorizationContext.
     * <p>
     * This builder follows the fluent interface pattern, allowing method chaining
     * for readable and concise object construction. All setter methods return
     * the builder instance for chaining.
     * </p>
     * <p>
     * <b>Usage Example:</b></p>
     * <pre>{@code
     * AgentAuthorizationContext context = AgentAuthorizationContext.builder()
     *     .wit("workload-identity-token")
     *     .wpt("workload-proof-token")
     *     .aoat("agent-operation-auth-token")
     *     .additionalHeaders(Map.of("X-Custom-Header", "value"))
     *     .build();
     * }</pre>
     *
     * @see AgentAuthorizationContext
     */
    public static class Builder {
        private String wit;
        private String wpt;
        private String aoat;
        private Map<String, String> additionalHeaders;

        /**
         * Sets the Workload Identity Token (WIT).
         *
         * @param wit the WIT, may be {@code null}
         * @return this builder instance for method chaining
         */
        public Builder wit(String wit) {
            this.wit = wit;
            return this;
        }

        /**
         * Sets the Workload Proof Token (WPT).
         *
         * @param wpt the WPT, may be {@code null}
         * @return this builder instance for method chaining
         */
        public Builder wpt(String wpt) {
            this.wpt = wpt;
            return this;
        }

        /**
         * Sets the Agent Operation Authorization Token (AOAT).
         *
         * @param aoat the AOAT, may be {@code null}
         * @return this builder instance for method chaining
         */
        public Builder aoat(String aoat) {
            this.aoat = aoat;
            return this;
        }

        /**
         * Sets additional authorization headers.
         * <p>
         * The provided map will be defensively copied and wrapped in an
         * unmodifiable collection when the context is built.
         * </p>
         *
         * @param additionalHeaders the additional headers, may be {@code null}
         * @return this builder instance for method chaining
         */
        public Builder additionalHeaders(Map<String, String> additionalHeaders) {
            this.additionalHeaders = additionalHeaders;
            return this;
        }

        /**
         * Builds the AgentAuthorizationContext.
         * <p>
         * This method creates an immutable instance of {@code AgentAuthorizationContext}
         * with the values configured in this builder. All fields are optional,
         * allowing partial context construction for scenarios where only
         * certain tokens are available.
         * </p>
         *
         * @return a new, immutable {@code AgentAuthorizationContext} instance
         */
        public AgentAuthorizationContext build() {
            return new AgentAuthorizationContext(this);
        }
    }
}