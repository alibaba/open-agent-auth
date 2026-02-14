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
package com.alibaba.openagentauth.core.model.oidc;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Represents an OpenID Connect ID Token.
 * <p>
 * An ID Token is a security token that contains Claims about the authentication
 * event and other Claims requested by the Client. The ID Token is represented as
 * a JSON Web Token (JWT) and must be digitally signed.
 * </p>
 * <p>
 * <b>ID Token Structure:</b></p>
 * <ul>
 *   <li><b>Header:</b> Algorithm and token type</li>
 *   <li><b>Payload:</b> Claims about the authentication event</li>
 *   <li><b>Signature:</b> Digital signature for verification</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>ID Tokens MUST be signed using JWS</li>
 *   <li>ID Tokens MAY be encrypted using JWE</li>
 *   <li>ID Tokens MUST be validated before use</li>
 *   <li>ID Tokens MUST have a limited lifetime</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
 * @see IdTokenClaims
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdToken {

    /**
     * The ID token value.
     * <p>
     * The signed JWT representation of the ID token. This is the actual token
     * string that is transmitted between parties.
     * </p>
     */
    private final String tokenValue;

    /**
     * The parsed claims from the ID token.
     * <p>
     * The claims extracted from the JWT payload, providing structured access to
     * the token's content.
     * </p>
     */
    private final IdTokenClaims claims;

    private IdToken(Builder builder) {
        this.tokenValue = builder.tokenValue;
        this.claims = builder.claims;
    }

    /**
     * Gets the ID token value.
     *
     * @return the JWT string representation
     */
    public String getTokenValue() {
        return tokenValue;
    }

    /**
     * Gets the ID token claims.
     *
     * @return the parsed claims
     */
    public IdTokenClaims getClaims() {
        return claims;
    }

    /**
     * Checks if the ID token is expired.
     *
     * @return true if the token is expired, false otherwise
     */
    public boolean isExpired() {
        if (claims == null || claims.getExp() == null) {
            return false;
        }
        return System.currentTimeMillis() / 1000 > claims.getExp();
    }

    /**
     * Gets the remaining lifetime of the ID token in seconds.
     *
     * @return the remaining lifetime, or 0 if expired
     */
    public long getRemainingLifetime() {
        if (claims == null || claims.getExp() == null) {
            return 0;
        }
        long now = System.currentTimeMillis() / 1000;
        long remaining = claims.getExp() - now;
        return Math.max(0, remaining);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IdToken idToken = (IdToken) o;
        return tokenValue.equals(idToken.tokenValue) &&
               claims.equals(idToken.claims);
    }

    @Override
    public int hashCode() {
        return tokenValue.hashCode();
    }

    @Override
    public String toString() {
        return "IdToken{" +
                "tokenValue='" + tokenValue + '\'' +
                ", claims=" + claims +
                '}';
    }

    /**
     * Creates a new builder for {@link IdToken}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link IdToken}.
     */
    public static class Builder {
        private String tokenValue;
        private IdTokenClaims claims;

        /**
         * Sets the ID token value.
         *
         * @param tokenValue the JWT string
         * @return this builder instance
         */
        public Builder tokenValue(String tokenValue) {
            this.tokenValue = tokenValue;
            return this;
        }

        /**
         * Sets the ID token claims.
         *
         * @param claims the claims
         * @return this builder instance
         */
        public Builder claims(IdTokenClaims claims) {
            this.claims = claims;
            return this;
        }

        /**
         * Builds the {@link IdToken}.
         *
         * @return the built ID token
         * @throws IllegalStateException if tokenValue or claims is null
         */
        public IdToken build() {
            if (ValidationUtils.isNullOrEmpty(tokenValue)) {
                throw new IllegalStateException("tokenValue is required");
            }
            if (claims == null) {
                throw new IllegalStateException("claims are required");
            }
            return new IdToken(this);
        }
    }
}