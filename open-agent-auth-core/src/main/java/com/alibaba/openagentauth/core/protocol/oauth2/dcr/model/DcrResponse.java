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

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Dynamic Client Registration (DCR) response according to RFC 7591.
 * <p>
 * This class represents the response from a successful client registration
 * request. It contains the registered client's metadata and credentials.
 * </p>
 * <p>
 * <b> Response Fields (RFC 7591):</b></p>
 * <ul>
 *   <li><b>client_id</b>: REQUIRED client identifier</li>
 *   <li><b>client_secret</b>: OPTIONAL client secret (if registered)</li>
 *   <li><b>client_id_issued_at</b>: OPTIONAL timestamp of client ID issuance</li>
 *   <li><b>client_secret_expires_at</b>: OPTIONAL timestamp of client secret expiration</li>
 *   <li><b>registration_access_token</b>: REQUIRED token for managing registration</li>
 *   <li><b>registration_client_uri</b>: REQUIRED URI for managing registration</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DcrResponse {

    /**
     * Client identifier issued by the Authorization Server.
     * REQUIRED by RFC 7591.
     */
    @JsonProperty("client_id")
    private final String clientId;

    /**
     * Client secret issued by the Authorization Server.
     * OPTIONAL by RFC 7591. Present if the client is confidential.
     */
    @JsonProperty("client_secret")
    private final String clientSecret;

    /**
     * Time at which the client_id was issued.
     * OPTIONAL by RFC 7591. Represented as seconds since epoch.
     */
    @JsonProperty("client_id_issued_at")
    private final Long clientIdIssuedAt;

    /**
     * Time at which the client_secret will expire.
     * OPTIONAL by RFC 7591. Represented as seconds since epoch.
     * 0 indicates the secret does not expire.
     */
    @JsonProperty("client_secret_expires_at")
    private final Long clientSecretExpiresAt;

    /**
     * Access token that can be used to manage the registration.
     * REQUIRED by RFC 7591.
     */
    @JsonProperty("registration_access_token")
    private final String registrationAccessToken;

    /**
     * URI that can be used to manage the registration.
     * REQUIRED by RFC 7591.
     */
    @JsonProperty("registration_client_uri")
    private final String registrationClientUri;

    /**
     * Array of redirection URI strings.
     */
    @JsonProperty("redirect_uris")
    private final List<String> redirectUris;

    /**
     * Human-readable name of the client.
     */
    @JsonProperty("client_name")
    private final String clientName;

    /**
     * Array of OAuth 2.0 grant type strings.
     */
    @JsonProperty("grant_types")
    private final List<String> grantTypes;

    /**
     * Array of OAuth 2.0 response type strings.
     */
    @JsonProperty("response_types")
    private final List<String> responseTypes;

    /**
     * String specifying a token endpoint authentication method.
     */
    @JsonProperty("token_endpoint_auth_method")
    private final String tokenEndpointAuthMethod;

    /**
     * Scope string.
     */
    @JsonProperty("scope")
    private final String scope;

    /**
     * Additional metadata returned by the Authorization Server.
     */
    @JsonProperty("additional_metadata")
    private final Map<String, Object> additionalMetadata;

    /**
     * Constructor for JSON deserialization.
     * This constructor is used by Jackson to deserialize JSON responses.
     */
    @JsonCreator
    private DcrResponse(
            @JsonProperty("client_id") String clientId,
            @JsonProperty("client_secret") String clientSecret,
            @JsonProperty("client_id_issued_at") Long clientIdIssuedAt,
            @JsonProperty("client_secret_expires_at") Long clientSecretExpiresAt,
            @JsonProperty("registration_access_token") String registrationAccessToken,
            @JsonProperty("registration_client_uri") String registrationClientUri,
            @JsonProperty("redirect_uris") List<String> redirectUris,
            @JsonProperty("client_name") String clientName,
            @JsonProperty("grant_types") List<String> grantTypes,
            @JsonProperty("response_types") List<String> responseTypes,
            @JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthMethod,
            @JsonProperty("scope") String scope,
            @JsonProperty("additional_metadata") Map<String, Object> additionalMetadata
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientIdIssuedAt = clientIdIssuedAt;
        this.clientSecretExpiresAt = clientSecretExpiresAt;
        this.registrationAccessToken = registrationAccessToken;
        this.registrationClientUri = registrationClientUri;
        this.redirectUris = redirectUris;
        this.clientName = clientName;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.scope = scope;
        this.additionalMetadata = additionalMetadata;
    }

    /**
     * Constructor for Builder pattern.
     */
    private DcrResponse(Builder builder) {
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.clientIdIssuedAt = builder.clientIdIssuedAt;
        this.clientSecretExpiresAt = builder.clientSecretExpiresAt;
        this.registrationAccessToken = builder.registrationAccessToken;
        this.registrationClientUri = builder.registrationClientUri;
        this.redirectUris = builder.redirectUris;
        this.clientName = builder.clientName;
        this.grantTypes = builder.grantTypes;
        this.responseTypes = builder.responseTypes;
        this.tokenEndpointAuthMethod = builder.tokenEndpointAuthMethod;
        this.scope = builder.scope;
        this.additionalMetadata = builder.additionalMetadata;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public Long getClientIdIssuedAt() {
        return clientIdIssuedAt;
    }

    public Long getClientSecretExpiresAt() {
        return clientSecretExpiresAt;
    }

    public String getRegistrationAccessToken() {
        return registrationAccessToken;
    }

    public String getRegistrationClientUri() {
        return registrationClientUri;
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

    public Map<String, Object> getAdditionalMetadata() {
        return additionalMetadata;
    }

    /**
     * Checks if the client secret will expire.
     *
     * @return true if the client secret expires, false otherwise
     */
    public boolean isClientSecretExpiring() {
        return clientSecretExpiresAt != null && clientSecretExpiresAt > 0;
    }

    /**
     * Converts this DcrResponse to an OAuth2RegisteredClient.
     *
     * @return the converted OAuth2RegisteredClient
     */
    public OAuth2RegisteredClient toRegisteredClient() {
        return OAuth2RegisteredClient.builder()
                .clientId(this.clientId)
                .clientSecret(this.clientSecret)
                .redirectUris(this.redirectUris)
                .clientName(this.clientName)
                .grantTypes(this.grantTypes)
                .responseTypes(this.responseTypes)
                .tokenEndpointAuthMethod(this.tokenEndpointAuthMethod)
                .scope(this.scope)
                .build();
    }

    /**
     * Creates a new builder for DcrResponse.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for DcrResponse.
     */
    public static class Builder {
        private String clientId;
        private String clientSecret;
        private Long clientIdIssuedAt;
        private Long clientSecretExpiresAt;
        private String registrationAccessToken;
        private String registrationClientUri;
        private List<String> redirectUris;
        private String clientName;
        private List<String> grantTypes;
        private List<String> responseTypes;
        private String tokenEndpointAuthMethod;
        private String scope;
        private Map<String, Object> additionalMetadata;

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder clientIdIssuedAt(Long clientIdIssuedAt) {
            this.clientIdIssuedAt = clientIdIssuedAt;
            return this;
        }

        public Builder clientSecretExpiresAt(Long clientSecretExpiresAt) {
            this.clientSecretExpiresAt = clientSecretExpiresAt;
            return this;
        }

        public Builder registrationAccessToken(String registrationAccessToken) {
            this.registrationAccessToken = registrationAccessToken;
            return this;
        }

        public Builder registrationClientUri(String registrationClientUri) {
            this.registrationClientUri = registrationClientUri;
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

        public Builder additionalMetadata(Map<String, Object> additionalMetadata) {
            this.additionalMetadata = additionalMetadata;
            return this;
        }

        /**
         * Builds the DcrResponse.
         *
         * @return the built response
         * @throws IllegalStateException if clientId is null or empty
         */
        public DcrResponse build() {
            if (ValidationUtils.isNullOrEmpty(clientId)) {
                throw new IllegalStateException("client_id is REQUIRED");
            }
            return new DcrResponse(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DcrResponse that = (DcrResponse) o;
        return Objects.equals(clientId, that.clientId) &&
               Objects.equals(clientSecret, that.clientSecret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, clientSecret);
    }
}