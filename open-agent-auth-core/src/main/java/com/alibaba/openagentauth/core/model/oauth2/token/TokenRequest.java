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
package com.alibaba.openagentauth.core.model.oauth2.token;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;
import java.util.Objects;

/**
 * Represents an OAuth 2.0 Token Request according to RFC 6749.
 * <p>
 * This class encapsulates the parameters sent by a client to the Token Endpoint
 * to exchange an authorization code for an access token. The request follows
 * the OAuth 2.0 Authorization Code Grant flow.
 * </p>
 * <p>
 * <b>Standard OAuth 2.0 Parameters (RFC 6749 Section 4.1.3):</b></p>
 * <ul>
 *   <li><b>grant_type:</b> REQUIRED - Value MUST be "authorization_code"</li>
 *   <li><b>code:</b> REQUIRED - The authorization code received from the authorization server</li>
 *   <li><b>redirect_uri:</b> REQUIRED - The redirect URI used in the authorization request</li>
 *   <li><b>client_id:</b> REQUIRED - The client identifier</li>
 * </ul>
 * <p>
 * <b>Client Authentication:</b></p>
 * <p>
 * According to RFC 6749, clients MUST authenticate to the token endpoint using
 * one of the following methods:
 * </p>
 * <ul>
 *   <li><b>client_secret_basic:</b> HTTP Basic authentication (client_id:client_secret)</li>
 *   <li><b>client_secret_post:</b> client_id and client_secret in request body</li>
 *   <li><b>private_key_jwt:</b> JWT assertion signed with client's private key</li>
 *   <li><b>client_secret_jwt:</b> JWT assertion using client secret</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenRequest {

    /**
     * The grant type.
     * <p>
     * Value MUST be "authorization_code" for the authorization code grant flow.
     * </p>
     */
    @JsonProperty("grant_type")
    private final String grantType;

    /**
     * The authorization code.
     * <p>
     * The authorization code received from the authorization server.
     * </p>
     */
    @JsonProperty("code")
    private final String code;

    /**
     * The redirect URI.
     * <p>
     * The redirect URI used in the authorization request.
     * This MUST match exactly the redirect_uri used in the authorization request.
     * </p>
     */
    @JsonProperty("redirect_uri")
    private final String redirectUri;

    /**
     * The client identifier.
     * <p>
     * The client identifier. This is required when using client_secret_post
     * authentication method. When using client_secret_basic, the client_id
     * is included in the HTTP Basic authentication header.
     * </p>
     */
    @JsonProperty("client_id")
    private final String clientId;

    /**
     * The client secret.
     * <p>
     * The client secret. This is required when using client_secret_post
     * authentication method. When using client_secret_basic, the client_secret
     * is included in the HTTP Basic authentication header.
     * </p>
     */
    @JsonProperty("client_secret")
    private final String clientSecret;

    /**
     * The client assertion.
     * <p>
     * A JWT assertion used for client authentication when using private_key_jwt
     * or client_secret_jwt authentication methods.
     * </p>
     */
    @JsonProperty("client_assertion")
    private final String clientAssertion;

    /**
     * The client assertion type.
     * <p>
     * The type of the client assertion. For JWT assertions, this MUST be
     * "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
     * </p>
     */
    @JsonProperty("client_assertion_type")
    private final String clientAssertionType;

    /**
     * Additional parameters.
     * <p>
     * Additional parameters not covered by standard fields.
     * This can be used for extensions or custom parameters.
     * </p>
     */
    @JsonProperty("additional_parameters")
    private final Map<String, Object> additionalParameters;

    private TokenRequest(Builder builder) {
        this.grantType = builder.grantType;
        this.code = builder.code;
        this.redirectUri = builder.redirectUri;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.clientAssertion = builder.clientAssertion;
        this.clientAssertionType = builder.clientAssertionType;
        this.additionalParameters = builder.additionalParameters;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getClientAssertion() {
        return clientAssertion;
    }

    public String getClientAssertionType() {
        return clientAssertionType;
    }

    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }

    /**
     * Checks if this request uses client_secret_post authentication.
     *
     * @return true if using client_secret_post
     */
    public boolean usesClientSecretPost() {
        return clientId != null && clientSecret != null;
    }

    /**
     * Checks if this request uses JWT-based authentication.
     *
     * @return true if using JWT assertion
     */
    public boolean usesJwtAssertion() {
        return clientAssertion != null && clientAssertionType != null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenRequest that = (TokenRequest) o;
        return Objects.equals(grantType, that.grantType) &&
                Objects.equals(code, that.code) &&
                Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(clientSecret, that.clientSecret) &&
                Objects.equals(clientAssertion, that.clientAssertion) &&
                Objects.equals(clientAssertionType, that.clientAssertionType) &&
                Objects.equals(additionalParameters, that.additionalParameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(grantType, code, redirectUri, clientId, clientSecret,
                clientAssertion, clientAssertionType, additionalParameters);
    }

    @Override
    public String toString() {
        return "TokenRequest{" +
                "grantType='" + grantType + '\'' +
                ", code='" + code + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='[PROTECTED]'" +
                ", clientAssertion='" + clientAssertion + '\'' +
                ", clientAssertionType='" + clientAssertionType + '\'' +
                ", additionalParameters=" + additionalParameters +
                '}';
    }

    /**
     * Creates a new builder for {@link TokenRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link TokenRequest}.
     */
    public static class Builder {
        private String grantType = "authorization_code";
        private String code;
        private String redirectUri;
        private String clientId;
        private String clientSecret;
        private String clientAssertion;
        private String clientAssertionType;
        private Map<String, Object> additionalParameters;

        /**
         * Sets the grant type.
         * <p>
         * Default value is "authorization_code".
         * </p>
         *
         * @param grantType the grant type
         * @return this builder instance
         */
        public Builder grantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        /**
         * Sets the authorization code.
         *
         * @param code the authorization code
         * @return this builder instance
         */
        public Builder code(String code) {
            this.code = code;
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
         * Sets the client identifier.
         *
         * @param clientId the client ID
         * @return this builder instance
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret
         * @return this builder instance
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Sets the client assertion.
         *
         * @param clientAssertion the client assertion JWT
         * @return this builder instance
         */
        public Builder clientAssertion(String clientAssertion) {
            this.clientAssertion = clientAssertion;
            return this;
        }

        /**
         * Sets the client assertion type.
         *
         * @param clientAssertionType the client assertion type
         * @return this builder instance
         */
        public Builder clientAssertionType(String clientAssertionType) {
            this.clientAssertionType = clientAssertionType;
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
         * Builds the {@link TokenRequest}.
         *
         * @return the built token request
         * @throws IllegalStateException if required fields are missing
         */
        public TokenRequest build() {
            if (ValidationUtils.isNullOrEmpty(grantType)) {
                throw new IllegalStateException("grant_type is required");
            }
            if (!"authorization_code".equals(grantType)) {
                throw new IllegalStateException("grant_type must be 'authorization_code'");
            }
            if (ValidationUtils.isNullOrEmpty(code)) {
                throw new IllegalStateException("code is required");
            }
            if (ValidationUtils.isNullOrEmpty(redirectUri)) {
                throw new IllegalStateException("redirect_uri is required");
            }
            return new TokenRequest(this);
        }
    }
}
