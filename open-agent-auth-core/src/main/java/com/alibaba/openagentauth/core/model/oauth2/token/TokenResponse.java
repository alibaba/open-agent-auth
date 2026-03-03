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

import java.util.Objects;

/**
 * Represents an OAuth 2.0 Token Response according to RFC 6749.
 * <p>
 * This class encapsulates the response returned by the Authorization Server's
 * Token Endpoint after successfully processing a token request. The response
 * contains the access token and related information.
 * </p>
 * <p>
 * <b>Standard OAuth 2.0 Response Fields (RFC 6749 Section 5.1):</b></p>
 * <ul>
 *   <li><b>access_token:</b> REQUIRED - The access token issued by the authorization server</li>
 *   <li><b>token_type:</b> REQUIRED - The type of the token issued (e.g., "Bearer")</li>
 *   <li><b>expires_in:</b> RECOMMENDED - The lifetime in seconds of the access token</li>
 *   <li><b>refresh_token:</b> OPTIONAL - The refresh token</li>
 *   <li><b>scope:</b> OPTIONAL - The scope of the access token</li>
 * </ul>
 * <p>
 * <b>OpenID Connect Extension (OIDC Core 1.0 Section 3.1.3.3):</b></p>
 * <ul>
 *   <li><b>id_token:</b> REQUIRED when scope includes "openid" - The ID Token</li>
 * </ul>
 * <p>
 * <b>Agent Operation Authorization Extension:</b></p>
 * <p>
 * For the Agent Operation Authorization framework, the access_token is an
 * Agent Operation Authorization Token (AOAT), which is an enhanced OAuth access token
 * containing agent-specific claims.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">RFC 6749 - Successful Token Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenResponse {

    /**
     * The access token.
     * <p>
     * The access token issued by the authorization server. In the Agent Operation
     * Authorization framework, this is an Agent Operation Authorization Token (AOAT).
     * </p>
     */
    @JsonProperty("access_token")
    private final String accessToken;

    /**
     * The token type.
     * <p>
     * The type of the token issued. Value is case-insensitive. The recommended
     * value is "Bearer" per RFC 6750.
     * </p>
     */
    @JsonProperty("token_type")
    private final String tokenType;

    /**
     * The token expiration time in seconds.
     * <p>
     * The lifetime in seconds of the access token. For example, the value "3600"
     * denotes that the access token will expire in one hour from the time the
     * response was generated.
     * </p>
     */
    @JsonProperty("expires_in")
    private final Long expiresIn;

    /**
     * The refresh token.
     * <p>
     * The refresh token, which can be used to obtain a new access token using
     * the same grant type as the original token request.
     * </p>
     */
    @JsonProperty("refresh_token")
    private final String refreshToken;

    /**
     * The scope of the access token.
     * <p>
     * The scope of the access token, as described by RFC 6749 Section 3.3.
     * If omitted, the scope is the same as the scope requested by the client.
     * </p>
     */
    @JsonProperty("scope")
    private final String scope;

    /**
     * The ID Token.
     * <p>
     * REQUIRED when the authorization request scope includes "openid".
     * The ID Token is a JSON Web Token (JWT) that contains claims about the
     * authentication event and the authenticated subject, as defined in
     * OpenID Connect Core 1.0 Section 3.1.3.3.
     * </p>
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">OIDC Core 1.0 - Token Response</a>
     */
    @JsonProperty("id_token")
    private final String idToken;

    private TokenResponse(Builder builder) {
        this.accessToken = builder.accessToken;
        this.tokenType = builder.tokenType;
        this.expiresIn = builder.expiresIn;
        this.refreshToken = builder.refreshToken;
        this.scope = builder.scope;
        this.idToken = builder.idToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getScope() {
        return scope;
    }

    /**
     * Gets the ID Token.
     *
     * @return the ID Token, or null if scope does not include "openid"
     */
    public String getIdToken() {
        return idToken;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenResponse that = (TokenResponse) o;
        return Objects.equals(accessToken, that.accessToken) &&
                Objects.equals(tokenType, that.tokenType) &&
                Objects.equals(expiresIn, that.expiresIn) &&
                Objects.equals(refreshToken, that.refreshToken) &&
                Objects.equals(scope, that.scope) &&
                Objects.equals(idToken, that.idToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken, tokenType, expiresIn, refreshToken, scope, idToken);
    }

    @Override
    public String toString() {
        return "TokenResponse{" +
                "accessToken='" + accessToken + '\'' +
                ", tokenType='" + tokenType + '\'' +
                ", expiresIn=" + expiresIn +
                ", refreshToken='" + refreshToken + '\'' +
                ", scope='" + scope + '\'' +
                ", idToken='" + (idToken != null ? "[PRESENT]" : "null") + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link TokenResponse}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link TokenResponse}.
     */
    public static class Builder {
        private String accessToken;
        private String tokenType = "Bearer";
        private Long expiresIn;
        private String refreshToken;
        private String scope;
        private String idToken;

        /**
         * Sets the access token.
         *
         * @param accessToken the access token
         * @return this builder instance
         */
        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        /**
         * Sets the token type.
         * <p>
         * Default value is "Bearer".
         * </p>
         *
         * @param tokenType the token type
         * @return this builder instance
         */
        public Builder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        /**
         * Sets the expiration time in seconds.
         *
         * @param expiresIn the expiration time
         * @return this builder instance
         */
        public Builder expiresIn(Long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        /**
         * Sets the refresh token.
         *
         * @param refreshToken the refresh token
         * @return this builder instance
         */
        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        /**
         * Sets the scope.
         *
         * @param scope the scope
         * @return this builder instance
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Sets the ID Token.
         * <p>
         * Required when the authorization request scope includes "openid"
         * (OIDC Core 1.0 Section 3.1.3.3).
         * </p>
         *
         * @param idToken the ID Token
         * @return this builder instance
         */
        public Builder idToken(String idToken) {
            this.idToken = idToken;
            return this;
        }

        /**
         * Builds the {@link TokenResponse}.
         *
         * @return the built token response
         * @throws IllegalStateException if required fields are missing
         */
        public TokenResponse build() {
            if (ValidationUtils.isNullOrEmpty(accessToken)) {
                throw new IllegalStateException("access_token is required");
            }
            if (ValidationUtils.isNullOrEmpty(tokenType)) {
                throw new IllegalStateException("token_type is required");
            }
            return new TokenResponse(this);
        }
    }
}
