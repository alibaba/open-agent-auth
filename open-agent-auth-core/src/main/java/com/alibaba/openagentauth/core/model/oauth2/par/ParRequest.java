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
package com.alibaba.openagentauth.core.model.oauth2.par;

import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.Map;

/**
 * Represents a Pushed Authorization Request according to RFC 9126.
 * <p>
 * This class encapsulates the authorization request parameters that will be
 * sent to the Authorization Server's PAR endpoint. The request is typically
 * serialized as a JWT (JAR - JWT-Secured Authorization Request) per RFC 9101.
 * </p>
 * <p>
 * <b>Standard OAuth 2.0 Parameters:</b></p>
 * <ul>
 *   <li><b>response_type:</b> REQUIRED - The response type (e.g., "code")</li>
 *   <li><b>client_id:</b> REQUIRED - The client identifier</li>
 *   <li><b>redirect_uri:</b> REQUIRED - The redirect URI</li>
 *   <li><b>scope:</b> OPTIONAL - The requested scope(s)</li>
 *   <li><b>state:</b> RECOMMENDED - Opaque value to maintain state between request and callback</li>
 * </ul>
 * <p>
 * <b>Additional Parameters (RFC 9101 JAR):</b></p>
 * <ul>
 *   <li><b>request:</b> The JWT containing the authorization request</li>
 *   <li><b>request_uri:</b> Reference to a previously stored authorization request</li>
 * </ul>
 * <p>
 * <b>Agent Operation Authorization Extension:</b></p>
 * <ul>
 *   <li><b>evidence:</b> JWT-VC proving the user's original input</li>
 *   <li><b>agent_user_binding_proposal:</b> Proposed binding between agent and user</li>
 *   <li><b>agent_operation_proposal:</b> Rego policy defining authorization scope</li>
 *   <li><b>context:</b> Runtime context for policy evaluation</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9101">RFC 9101 - JWT-Secured Authorization Request (JAR)</a>
 * @since 1.0
 */
public class ParRequest {

    /**
     * The response type (e.g., "code", "token").
     */
    private final String responseType;

    /**
     * The client identifier.
     */
    private final String clientId;

    /**
     * The redirect URI.
     */
    private final String redirectUri;

    /**
     * The requested scope(s).
     */
    private final String scope;

    /**
     * The state parameter for CSRF protection.
     */
    private final String state;

    /**
     * The authorization request JWT (JAR format).
     */
    private final String requestJwt;

    /**
     * Additional parameters not covered by standard fields.
     */
    private final Map<String, Object> additionalParameters;

    private ParRequest(Builder builder) {
        this.responseType = builder.responseType;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.scope = builder.scope;
        this.state = builder.state;
        this.requestJwt = builder.requestJwt;
        this.additionalParameters = builder.additionalParameters;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getState() {
        return state;
    }

    public String getRequestJwt() {
        return requestJwt;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    /**
     * Creates a new builder for constructing ParRequest instances.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing ParRequest instances.
     */
    public static class Builder {
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String requestJwt;
        private Map<String, Object> additionalParameters;

        /**
         * Sets the response type.
         *
         * @param responseType the response type (e.g., "code")
         * @return this builder instance
         */
        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        /**
         * Sets the client identifier.
         *
         * @param clientId the client identifier
         * @return this builder instance
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the redirect URI.
         *
         * @param redirectUri the redirect URI
         * @return this builder instance
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        /**
         * Sets the requested scope(s).
         *
         * @param scope the scope(s)
         * @return this builder instance
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Sets the state parameter.
         *
         * @param state the state parameter
         * @return this builder instance
         */
        public Builder state(String state) {
            this.state = state;
            return this;
        }

        /**
         * Sets the authorization request JWT.
         *
         * @param requestJwt the JWT containing the authorization request
         * @return this builder instance
         */
        public Builder requestJwt(String requestJwt) {
            this.requestJwt = requestJwt;
            return this;
        }

        /**
         * Sets additional parameters.
         *
         * @param additionalParameters additional parameters
         * @return this builder instance
         */
        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }

        /**
         * Builds the ParRequest instance.
         *
         * @return the constructed ParRequest
         * @throws IllegalArgumentException if required fields are missing
         */
        public ParRequest build() {
            ValidationUtils.validateNotNull(responseType, "response_type is required");
            ValidationUtils.validateNotNull(clientId, "client_id is required");
            ValidationUtils.validateNotNull(redirectUri, "redirect_uri is required");
            return new ParRequest(this);
        }
    }
}