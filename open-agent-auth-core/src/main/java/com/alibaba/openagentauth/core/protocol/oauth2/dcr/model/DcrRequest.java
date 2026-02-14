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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Dynamic Client Registration (DCR) request according to RFC 7591.
 * <p>
 * This class represents a client registration request submitted to the
 * Authorization Server's registration endpoint. It includes standard OAuth 2.0
 * client metadata and can be extended with custom parameters.
 * </p>
 * <p>
 * <b>Standard Metadata Fields (RFC 7591):</b></p>
 * <ul>
 *   <li><b>redirect_uris</b>: REQUIRED array of redirect URIs</li>
 *   <li><b>client_name</b>: OPTIONAL human-readable name</li>
 *   <li><b>grant_types</b>: OPTIONAL array of grant types</li>
 *   <li><b>response_types</b>: OPTIONAL array of response types</li>
 *   <li><b>token_endpoint_auth_method</b>: OPTIONAL authentication method</li>
 *   <li><b>scope</b>: OPTIONAL scope string</li>
 * </ul>
 * <p>
 * <b>Extensions:</b></p>
 * <p>
 * Protocol-specific extensions (e.g., WIMSE, SPIFFE) should use the
 * {@code additionalParameters} field or extend this class.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DcrRequest {

    /**
     * Array of redirection URI strings for use in redirect-based flows.
     * REQUIRED by RFC 7591.
     */
    @JsonProperty("redirect_uris")
    private final List<String> redirectUris;

    /**
     * Human-readable string name of the client to be presented to the end-user.
     * OPTIONAL by RFC 7591.
     */
    @JsonProperty("client_name")
    private final String clientName;

    /**
     * Array of OAuth 2.0 grant type strings that the client can use.
     * OPTIONAL by RFC 7591. Default value is ["authorization_code"].
     */
    @JsonProperty("grant_types")
    private final List<String> grantTypes;

    /**
     * Array of OAuth 2.0 response type strings that the client can use.
     * OPTIONAL by RFC 7591. Default value is ["code"].
     */
    @JsonProperty("response_types")
    private final List<String> responseTypes;

    /**
     * String specifying a token endpoint authentication method.
     * OPTIONAL by RFC 7591. Default value is "client_secret_basic".
     * For WIMSE-based authentication, use "private_key_jwt" or "client_secret_jwt".
     */
    @JsonProperty("token_endpoint_auth_method")
    private final String tokenEndpointAuthMethod;

    /**
     * String containing a space-separated list of scope values.
     * OPTIONAL by RFC 7591.
     */
    @JsonProperty("scope")
    private final String scope;

    /**
     * Additional custom parameters for the registration request.
     * This field allows extensions for protocol-specific features (e.g., WIMSE, SPIFFE).
     */
    @JsonProperty("additional_parameters")
    private final Map<String, Object> additionalParameters;

    private DcrRequest(Builder builder) {
        this.redirectUris = builder.redirectUris;
        this.clientName = builder.clientName;
        this.grantTypes = builder.grantTypes;
        this.responseTypes = builder.responseTypes;
        this.tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod;
        this.scope = builder.scope;
        this.additionalParameters = builder.additionalParameters;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public String getScope() {
        return scope;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    /**
     * Creates a new builder for DcrRequest.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for DcrRequest.
     */
    public static class Builder {

        private List<String> redirectUris;
        private String clientName;
        private List<String> grantTypes;
        private List<String> responseTypes;
        private String tokenEndpointAuthMethod;
        private String scope;
        private Map<String, Object> additionalParameters;

        public Builder redirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public Builder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public Builder grantTypes(List<String> grantTypes) {
            this.grantTypes = grantTypes;
            return this;
        }

        public Builder responseTypes(List<String> responseTypes) {
            this.responseTypes = responseTypes;
            return this;
        }

        public Builder tokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
            this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }

        /**
         * Builds the DcrRequest.
         *
         * @return the built request
         * @throws IllegalStateException if redirectUris is null or empty
         */
        public DcrRequest build() {
            if (redirectUris == null || redirectUris.isEmpty()) {
                throw new IllegalStateException("redirect_uris is REQUIRED");
            }
            return new DcrRequest(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DcrRequest that = (DcrRequest) o;
        return Objects.equals(redirectUris, that.redirectUris) &&
               Objects.equals(clientName, that.clientName) &&
               Objects.equals(grantTypes, that.grantTypes) &&
               Objects.equals(responseTypes, that.responseTypes) &&
               Objects.equals(tokenEndpointAuthMethod, that.tokenEndpointAuthMethod) &&
               Objects.equals(scope, that.scope);
    }

    @Override
    public int hashCode() {
        return Objects.hash(redirectUris, clientName, grantTypes, responseTypes, 
                          tokenEndpointAuthMethod, scope);
    }
}
