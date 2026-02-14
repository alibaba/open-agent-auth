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

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Represents the claims in an OpenID Connect ID Token.
 * <p>
 * ID Tokens are JSON Web Tokens (JWT) that contain claims about the authentication
 * event and the authenticated subject. This class encapsulates all standard OIDC
 * claims as defined in OpenID Connect Core 1.0 specification.
 * </p>
 * <p>
 * <b>Standard Claims (OpenID Connect Core 1.0):</b></p>
 * <ul>
 *   <li><b>iss:</b> REQUIRED - Issuer identifier</li>
 *   <li><b>sub:</b> REQUIRED - Subject identifier</li>
 *   <li><b>aud:</b> REQUIRED - Audience(s)</li>
 *   <li><b>exp:</b> REQUIRED - Expiration time</li>
 *   <li><b>iat:</b> REQUIRED - Issued at time</li>
 *   <li><b>auth_time:</b> RECOMMENDED - Time when authentication occurred</li>
 *   <li><b>nonce:</b> OPTIONAL - Value used to associate a client session with an ID token</li>
 *   <li><b>acr:</b> OPTIONAL - Authentication Context Class Reference</li>
 *   <li><b>amr:</b> OPTIONAL - Authentication Methods References</li>
 *   <li><b>azp:</b> OPTIONAL - Authorized party</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdTokenClaims {

    /**
     * Issuer identifier.
     * <p>
     * REQUIRED. The Issuer identifier for the issuer of the response.
     * The iss value is a case-sensitive URL using the https scheme that contains
     * scheme, host, and optionally, port number and path components.
     * </p>
     */
    private final String iss;

    /**
     * Subject identifier.
     * <p>
     * REQUIRED. A locally unique and never reassigned identifier within the Issuer
     * for the End-User, which is intended to be consumed by the Client.
     * </p>
     */
    private final String sub;

    /**
     * Audience(s).
     * <p>
     * REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain
     * the OAuth 2.0 client_id of the Relying Party as an audience value.
     * </p>
     */
    private final String aud;

    /**
     * Expiration time.
     * <p>
     * REQUIRED. The expiration time on or after which the ID Token MUST NOT be
     * accepted for processing. The value is the number of seconds from 1970-01-01T00:00:00Z
     * as measured in UTC until the desired date/time.
     * </p>
     */
    private final Long exp;

    /**
     * Issued at time.
     * <p>
     * REQUIRED. The time at which the JWT was issued. The value is the number of
     * seconds from 1970-01-01T00:00:00Z as measured in UTC until the desired date/time.
     * </p>
     */
    private final Long iat;

    /**
     * Authentication time.
     * <p>
     * RECOMMENDED. Time when the End-User authentication occurred. The value is
     * the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the
     * date/time.
     * </p>
     */
    private final Long authTime;

    /**
     * Nonce.
     * <p>
     * OPTIONAL. String value used to associate a Client session with an ID Token,
     * and to mitigate replay attacks. The value is passed through unmodified from
     * the Authentication Request to the ID Token.
     * </p>
     */
    private final String nonce;

    /**
     * Authentication Context Class Reference.
     * <p>
     * OPTIONAL. String specifying an Authentication Context Class Reference value
     * that identifies the Authentication Context Class that the authentication performed
     * satisfied.
     * </p>
     */
    private final String acr;

    /**
     * Authentication Methods References.
     * <p>
     * OPTIONAL. JSON array of strings that are identifiers for authentication
     * methods used in the authentication.
     * </p>
     */
    private final String[] amr;

    /**
     * Authorized party.
     * <p>
     * OPTIONAL. The azp (authorized party) claim identifies the party to which
     * the ID Token was issued. If present, it MUST contain the OAuth 2.0 Client ID
     * of this party.
     * </p>
     */
    private final String azp;

    /**
     * Additional claims.
     * <p>
     * OPTIONAL. Additional custom claims that may be included in the ID Token.
     * </p>
     */
    private final Map<String, Object> additionalClaims;

    private IdTokenClaims(Builder builder) {
        this.iss = builder.iss;
        this.sub = builder.sub;
        this.aud = builder.aud;
        this.exp = builder.exp;
        this.iat = builder.iat;
        this.authTime = builder.authTime;
        this.nonce = builder.nonce;
        this.acr = builder.acr;
        this.amr = builder.amr;
        this.azp = builder.azp;
        this.additionalClaims = builder.additionalClaims;
    }

    public String getIss() {
        return iss;
    }

    public String getSub() {
        return sub;
    }

    public String getAud() {
        return aud;
    }

    public Long getExp() {
        return exp;
    }

    public Long getIat() {
        return iat;
    }

    public Long getAuthTime() {
        return authTime;
    }

    public String getNonce() {
        return nonce;
    }

    public String getAcr() {
        return acr;
    }

    public String[] getAmr() {
        return amr;
    }

    public String getAzp() {
        return azp;
    }

    public Map<String, Object> getAdditionalClaims() {
        return additionalClaims;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IdTokenClaims that = (IdTokenClaims) o;
        return Objects.equals(iss, that.iss) &&
               Objects.equals(sub, that.sub) &&
               Objects.equals(aud, that.aud) &&
               Objects.equals(exp, that.exp) &&
               Objects.equals(iat, that.iat) &&
               Objects.equals(authTime, that.authTime) &&
               Objects.equals(nonce, that.nonce) &&
               Objects.equals(acr, that.acr) &&
               Objects.equals(azp, that.azp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(iss, sub, aud, exp, iat, authTime, nonce, acr, azp);
    }

    @Override
    public String toString() {
        return "IdTokenClaims{" +
                "iss='" + iss + '\'' +
                ", sub='" + sub + '\'' +
                ", aud='" + aud + '\'' +
                ", exp=" + exp +
                ", iat=" + iat +
                ", authTime=" + authTime +
                ", nonce='" + nonce + '\'' +
                ", acr='" + acr + '\'' +
                ", azp='" + azp + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link IdTokenClaims}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link IdTokenClaims}.
     */
    public static class Builder {
        private String iss;
        private String sub;
        private String aud;
        private Long exp;
        private Long iat;
        private Long authTime;
        private String nonce;
        private String acr;
        private String[] amr;
        private String azp;
        private Map<String, Object> additionalClaims;

        /**
         * Sets the issuer identifier.
         *
         * @param iss the issuer identifier
         * @return this builder instance
         */
        public Builder iss(String iss) {
            this.iss = iss;
            return this;
        }

        /**
         * Sets the subject identifier.
         *
         * @param sub the subject identifier
         * @return this builder instance
         */
        public Builder sub(String sub) {
            this.sub = sub;
            return this;
        }

        /**
         * Sets the audience.
         *
         * @param aud the audience
         * @return this builder instance
         */
        public Builder aud(String aud) {
            this.aud = aud;
            return this;
        }

        /**
         * Sets the expiration time.
         *
         * @param exp the expiration time in seconds since epoch
         * @return this builder instance
         */
        public Builder exp(Long exp) {
            this.exp = exp;
            return this;
        }

        /**
         * Sets the expiration time from an Instant.
         *
         * @param instant the expiration time
         * @return this builder instance
         */
        public Builder exp(Instant instant) {
            this.exp = instant.getEpochSecond();
            return this;
        }

        /**
         * Sets the issued at time.
         *
         * @param iat the issued at time in seconds since epoch
         * @return this builder instance
         */
        public Builder iat(Long iat) {
            this.iat = iat;
            return this;
        }

        /**
         * Sets the issued at time from an Instant.
         *
         * @param instant the issued at time
         * @return this builder instance
         */
        public Builder iat(Instant instant) {
            this.iat = instant.getEpochSecond();
            return this;
        }

        /**
         * Sets the authentication time.
         *
         * @param authTime the authentication time in seconds since epoch
         * @return this builder instance
         */
        public Builder authTime(Long authTime) {
            this.authTime = authTime;
            return this;
        }

        /**
         * Sets the authentication time from an Instant.
         *
         * @param instant the authentication time
         * @return this builder instance
         */
        public Builder authTime(Instant instant) {
            this.authTime = instant.getEpochSecond();
            return this;
        }

        /**
         * Sets the nonce.
         *
         * @param nonce the nonce value
         * @return this builder instance
         */
        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        /**
         * Sets the Authentication Context Class Reference.
         *
         * @param acr the ACR value
         * @return this builder instance
         */
        public Builder acr(String acr) {
            this.acr = acr;
            return this;
        }

        /**
         * Sets the Authentication Methods References.
         *
         * @param amr the AMR values
         * @return this builder instance
         */
        public Builder amr(String[] amr) {
            this.amr = amr;
            return this;
        }

        /**
         * Sets the authorized party.
         *
         * @param azp the authorized party
         * @return this builder instance
         */
        public Builder azp(String azp) {
            this.azp = azp;
            return this;
        }

        /**
         * Sets additional claims.
         *
         * @param additionalClaims the additional claims map
         * @return this builder instance
         */
        public Builder additionalClaims(Map<String, Object> additionalClaims) {
            this.additionalClaims = additionalClaims;
            return this;
        }

        /**
         * Builds the {@link IdTokenClaims}.
         *
         * @return the built ID token claims
         * @throws IllegalStateException if required fields are missing
         */
        public IdTokenClaims build() {
            if (ValidationUtils.isNullOrEmpty(iss)) {
                throw new IllegalStateException("iss (issuer) is required");
            }
            if (ValidationUtils.isNullOrEmpty(sub)) {
                throw new IllegalStateException("sub (subject) is required");
            }
            if (ValidationUtils.isNullOrEmpty(aud)) {
                throw new IllegalStateException("aud (audience) is required");
            }
            if (exp == null) {
                throw new IllegalStateException("exp (expiration) is required");
            }
            if (iat == null) {
                throw new IllegalStateException("iat (issued at) is required");
            }
            return new IdTokenClaims(this);
        }
    }
}