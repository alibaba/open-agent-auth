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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents an OAuth 2.0 Authorization Code according to RFC 6749.
 * <p>
 * An authorization code is a temporary credential issued by the Authorization Server
 * to the client, which can be exchanged for an access token. The code is bound to
 * the specific client, redirect URI, and authorization request.
 * </p>
 * <p>
 * <b>Security Requirements (RFC 6749 Section 4.1.2):</b></p>
 * <ul>
 *   <li>Authorization codes MUST expire shortly after issuance (recommended: 10 minutes)</li>
 *   <li>Authorization codes MUST be single-use</li>
 *   <li>Authorization codes MUST be bound to the client_id and redirect_uri</li>
 *   <li>Authorization codes SHOULD be high-entropy cryptographic random values</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">RFC 6749 - Authorization Code</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationCode {

    /**
     * The authorization code string.
     * <p>
     * The actual authorization code value that will be returned to the client.
     * This value MUST be unique, unpredictable, and single-use.
     * </p>
     */
    @JsonProperty("code")
    private final String code;

    /**
     * The client identifier to which this code is bound.
     * <p>
     * The client_id that was used in the authorization request.
     * The code can only be exchanged by this specific client.
     * </p>
     */
    @JsonProperty("client_id")
    private final String clientId;

    /**
     * The redirect URI used in the authorization request.
     * <p>
     * The redirect_uri parameter from the original authorization request.
     * This MUST match the redirect_uri used when exchanging the code.
     * </p>
     */
    @JsonProperty("redirect_uri")
    private final String redirectUri;

    /**
     * The associated request URI from PAR.
     * <p>
     * The request_uri returned by the PAR flow, which references the original
     * authorization request. This is used to retrieve the full authorization
     * context when exchanging the code.
     * </p>
     */
    @JsonProperty("request_uri")
    private final String requestUri;

    /**
     * The state parameter from the authorization request.
     * <p>
     * Opaque value used to maintain state between the request and callback.
     * This value MUST be returned unchanged to the client.
     * </p>
     */
    @JsonProperty("state")
    private final String state;

    /**
     * The user subject identifier.
     * <p>
     * The ID of the user who authorized the request.
     * This will be used as the subject (sub) claim in the access token.
     * </p>
     */
    @JsonProperty("subject")
    private final String subject;

    /**
     * The scope granted to the authorization.
     * <p>
     * The scope of access granted by the user authorization.
     * This may be a subset of the originally requested scope.
     * </p>
     */
    @JsonProperty("scope")
    private final String scope;

    /**
     * The time when this authorization code was issued.
     * <p>
     * Used to enforce the code expiration time.
     * </p>
     */
    @JsonProperty("issued_at")
    private final Instant issuedAt;

    /**
     * The time when this authorization code expires.
     * <p>
     * Authorization codes SHOULD expire within 10 minutes of issuance.
     * </p>
     */
    @JsonProperty("expires_at")
    private final Instant expiresAt;

    /**
     * Whether this authorization code has been used.
     * <p>
     * Authorization codes MUST be single-use. Once exchanged, this flag
     * should be set to true to prevent reuse.
     * </p>
     */
    @JsonProperty("used")
    private boolean used;

    private AuthorizationCode(Builder builder) {
        this.code = builder.code;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.requestUri = builder.requestUri;
        this.state = builder.state;
        this.subject = builder.subject;
        this.scope = builder.scope;
        this.issuedAt = builder.issuedAt;
        this.expiresAt = builder.expiresAt;
        this.used = builder.used;
    }

    public String getCode() {
        return code;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public String getState() {
        return state;
    }

    public String getSubject() {
        return subject;
    }

    public String getScope() {
        return scope;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isUsed() {
        return used;
    }

    /**
     * Marks this authorization code as used.
     * <p>
     * This method should be called after the code has been successfully exchanged
     * for an access token to prevent reuse.
     * </p>
     */
    public void markAsUsed() {
        this.used = true;
    }

    /**
     * Checks if this authorization code is expired.
     *
     * @return true if the code has expired, false otherwise
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Checks if this authorization code is valid.
     * <p>
     * A code is valid if it has not expired and has not been used.
     * </p>
     *
     * @return true if the code is valid, false otherwise
     */
    public boolean isValid() {
        return !isExpired() && !used;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationCode that = (AuthorizationCode) o;
        return used == that.used &&
                Objects.equals(code, that.code) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(requestUri, that.requestUri) &&
                Objects.equals(state, that.state) &&
                Objects.equals(subject, that.subject) &&
                Objects.equals(scope, that.scope) &&
                Objects.equals(issuedAt, that.issuedAt) &&
                Objects.equals(expiresAt, that.expiresAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, clientId, redirectUri, requestUri, state, subject, scope, issuedAt, expiresAt, used);
    }

    @Override
    public String toString() {
        return "AuthorizationCode{" +
                "code='" + code + '\'' +
                ", clientId='" + clientId + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", requestUri='" + requestUri + '\'' +
                ", state='" + state + '\'' +
                ", subject='" + subject + '\'' +
                ", scope='" + scope + '\'' +
                ", issuedAt=" + issuedAt +
                ", expiresAt=" + expiresAt +
                ", used=" + used +
                '}';
    }

    /**
     * Creates a new builder for {@link AuthorizationCode}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AuthorizationCode}.
     */
    public static class Builder {
        private String code;
        private String clientId;
        private String redirectUri;
        private String requestUri;
        private String state;
        private String subject;
        private String scope;
        private Instant issuedAt;
        private Instant expiresAt;
        private boolean used = false;

        /**
         * Sets the authorization code string.
         *
         * @param code the authorization code
         * @return this builder instance
         */
        public Builder code(String code) {
            this.code = code;
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
         * Sets the request URI from PAR.
         *
         * @param requestUri the request URI
         * @return this builder instance
         */
        public Builder requestUri(String requestUri) {
            this.requestUri = requestUri;
            return this;
        }

        /**
         * Sets the state parameter.
         *
         * @param state the state
         * @return this builder instance
         */
        public Builder state(String state) {
            this.state = state;
            return this;
        }

        /**
         * Sets the user subject.
         *
         * @param subject the subject
         * @return this builder instance
         */
        public Builder subject(String subject) {
            this.subject = subject;
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
         * Sets the issued at time.
         *
         * @param issuedAt the issued at time
         * @return this builder instance
         */
        public Builder issuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        /**
         * Sets the expiration time.
         *
         * @param expiresAt the expiration time
         * @return this builder instance
         */
        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        /**
         * Sets whether the code has been used.
         *
         * @param used true if used, false otherwise
         * @return this builder instance
         */
        public Builder used(boolean used) {
            this.used = used;
            return this;
        }

        /**
         * Builds the {@link AuthorizationCode}.
         *
         * @return the built authorization code
         * @throws IllegalStateException if required fields are missing
         */
        public AuthorizationCode build() {
            if (ValidationUtils.isNullOrEmpty(code)) {
                throw new IllegalStateException("code is required");
            }
            if (ValidationUtils.isNullOrEmpty(clientId)) {
                throw new IllegalStateException("client_id is required");
            }
            if (ValidationUtils.isNullOrEmpty(redirectUri)) {
                throw new IllegalStateException("redirect_uri is required");
            }
            if (issuedAt == null) {
                throw new IllegalStateException("issued_at is required");
            }
            if (expiresAt == null) {
                throw new IllegalStateException("expires_at is required");
            }
            return new AuthorizationCode(this);
        }
    }
}
