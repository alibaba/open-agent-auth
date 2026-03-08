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
package com.alibaba.openagentauth.core.protocol.oauth2.client.model;

import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a registered OAuth 2.0 client with standard metadata.
 * <p>
 * This model contains the standard OAuth 2.0 client metadata fields as defined
 * in RFC 6749. It is independent of any specific registration mechanism (e.g., DCR)
 * and serves as the common client representation used by the authorization server
 * for client validation during OAuth 2.0 flows.
 * </p>
 * <p>
 * <b>Standard Fields (RFC 6749 Section 2):</b></p>
 * <ul>
 *   <li><b>client_id</b>: REQUIRED unique client identifier</li>
 *   <li><b>client_secret</b>: OPTIONAL client secret for confidential clients</li>
 *   <li><b>redirect_uris</b>: REQUIRED array of registered redirect URIs</li>
 *   <li><b>client_name</b>: OPTIONAL human-readable client name</li>
 *   <li><b>grant_types</b>: OPTIONAL array of supported grant types</li>
 *   <li><b>response_types</b>: OPTIONAL array of supported response types</li>
 *   <li><b>token_endpoint_auth_method</b>: OPTIONAL authentication method</li>
 *   <li><b>scope</b>: OPTIONAL scope string</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2">RFC 6749 - Client Registration</a>
 * @since 1.0
 */
public class OAuth2RegisteredClient {

    private final String clientId;
    private final String clientSecret;
    private final List<String> redirectUris;
    private final String clientName;
    private final List<String> grantTypes;
    private final List<String> responseTypes;
    private final String tokenEndpointAuthMethod;
    private final String scope;
    private final String jwksUri;
    private final Map<String, Object> jwks;

    private OAuth2RegisteredClient(Builder builder) {
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.redirectUris = builder.redirectUris;
        this.clientName = builder.clientName;
        this.grantTypes = builder.grantTypes;
        this.responseTypes = builder.responseTypes;
        this.tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod;
        this.scope = builder.scope;
        this.jwksUri = builder.jwksUri;
        this.jwks = builder.jwks;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
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

    public String getJwksUri() {
        return jwksUri;
    }

    /**
     * Returns the client's inline JSON Web Key Set (RFC 7517).
     * <p>
     * Contains the public keys used for {@code private_key_jwt} client authentication.
     * Mutually exclusive with {@code jwksUri}.
     * </p>
     *
     * @return the inline JWKS map, or null if not set
     */
    public Map<String, Object> getJwks() {
        return jwks;
    }

    /**
     * Creates a new builder for OAuth2RegisteredClient.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuth2RegisteredClient that = (OAuth2RegisteredClient) o;
        return Objects.equals(clientId, that.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId);
    }

    /**
     * Builder for OAuth2RegisteredClient.
     */
    public static class Builder {

        private String clientId;
        private String clientSecret;
        private List<String> redirectUris;
        private String clientName;
        private List<String> grantTypes;
        private List<String> responseTypes;
        private String tokenEndpointAuthMethod;
        private String scope;
        private String jwksUri;
        private Map<String, Object> jwks;

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

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

        public Builder jwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        public Builder jwks(Map<String, Object> jwks) {
            this.jwks = jwks;
            return this;
        }

        /**
         * Builds the OAuth2RegisteredClient.
         *
         * @return the built client
         * @throws IllegalStateException if clientId is null or empty
         */
        public OAuth2RegisteredClient build() {
            if (ValidationUtils.isNullOrEmpty(clientId)) {
                throw new IllegalStateException("client_id is REQUIRED");
            }
            return new OAuth2RegisteredClient(this);
        }
    }
}
