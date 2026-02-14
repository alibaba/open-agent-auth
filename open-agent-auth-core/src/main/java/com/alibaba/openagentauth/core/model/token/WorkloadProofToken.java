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
package com.alibaba.openagentauth.core.model.token;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a Workload Proof Token (WPT) as defined in draft-ietf-wimse-wpt.
 * <p>
 * A WPT is a JWT that proves possession of the private key corresponding to the public key
 * in the associated Workload Identity Token (WIT). It is signed by the workload using its
 * private key and contains claims that bind it to the WIT and optionally to other tokens.
 * <p>
 * The WPT consists of a JOSE header and claims (payload). The header specifies the media type
 * ({@code wpt+jwt}) and the signature algorithm. The claims include the workload token hash
 * (wth) which binds the WPT to a specific WIT, and optionally hashes of other tokens.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkloadProofToken {

    /**
     * The JOSE header of the WPT.
     */
    private final Header header;

    /**
     * The claims (payload) of the WPT.
     */
    private final Claims claims;

    /**
     * The JWS signature of the WPT.
     * <p>
     * This field stores the base64url-encoded signature value that is generated
     * during the signing process. The signature is computed over the header and
     * claims using the algorithm specified in the header.
     * </p>
     * <p>
     * According to RFC 7515, the signature is part of the JWS Compact Serialization
     * format: header.payload.signature
     * </p>
     */
    @JsonProperty("signature")
    private final String signature;

    /**
     * The JWT string representation of the WPT.
     * <p>
     * This field stores the complete JWT string (header.payload.signature) as it was
     * generated during the signing process. This is used during validation to ensure
     * signature verification uses the exact same serialization that was signed,
     * avoiding serialization inconsistencies that could cause verification failures.
     * </p>
     */
    @JsonProperty("jwtString")
    private final String jwtString;

    private WorkloadProofToken(Builder builder) {
        this.header = builder.header;
        this.claims = builder.claims;
        this.signature = builder.signature;
        this.jwtString = builder.jwtString;
    }

    /**
     * Gets the JOSE header of the WPT.
     *
     * @return the header
     */
    public Header getHeader() {
        return header;
    }

    /**
     * Gets the claims (payload) of the WPT.
     *
     * @return the claims
     */
    public Claims getClaims() {
        return claims;
    }

    /**
     * Gets the signature of the WPT.
     *
     * @return the base64url-encoded signature value, or null if not yet signed
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Gets the audience (aud) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getAudience()}.
     * </p>
     *
     * @return the audience, or null if not present
     */
    public String getAudience() {
        return claims != null ? claims.getAudience() : null;
    }

    /**
     * Gets the expiration time (exp) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getExpirationTime()}.
     * </p>
     *
     * @return the expiration time, or null if not present
     */
    public Date getExpirationTime() {
        return claims != null ? claims.getExpirationTime() : null;
    }

    /**
     * Gets the JWT ID (jti) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getJwtId()}.
     * </p>
     *
     * @return the JWT ID, or null if not present
     */
    public String getJwtId() {
        return claims != null ? claims.getJwtId() : null;
    }

    /**
     * Gets the Workload Identity Token Hash (wth) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getWorkloadTokenHash()}.
     * </p>
     *
     * @return the base64url-encoded WIT hash (never null for valid WPT)
     */
    public String getWorkloadTokenHash() {
        return claims != null ? claims.getWorkloadTokenHash() : null;
    }

    /**
     * Gets the Access Token Hash (ath) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getAccessTokenHash()}.
     * </p>
     *
     * @return the base64url-encoded access token hash, or null if not present
     */
    public String getAccessTokenHash() {
        return claims != null ? claims.getAccessTokenHash() : null;
    }

    /**
     * Gets the Transaction Token Hash (tth) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getTransactionTokenHash()}.
     * </p>
     *
     * @return the base64url-encoded transaction token hash, or null if not present
     */
    public String getTransactionTokenHash() {
        return claims != null ? claims.getTransactionTokenHash() : null;
    }

    /**
     * Gets the Other Tokens Hashes (oth) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getOtherTokenHashes()}.
     * </p>
     *
     * @return a map of token type to hash, or null if not present
     */
    public Map<String, String> getOtherTokenHashes() {
        return claims != null ? claims.getOtherTokenHashes() : null;
    }

    /**
     * Gets the JWT string representation of this token.
     * <p>
     * This field stores the complete JWT string (header.payload.signature) as it was
     * originally signed. This is useful for verification purposes to avoid
     * serialization inconsistencies.
     * </p>
     *
     * @return the JWT string, or null if not available
     */
    public String getJwtString() {
        return jwtString;
    }

    /**
     * Checks if the WPT is expired.
     *
     * @return true if the WPT is expired, false otherwise
     */
    public boolean isExpired() {
        return claims != null && claims.isExpired();
    }

    /**
     * Checks if the WPT is currently valid (not expired).
     *
     * @return true if the WPT is valid, false otherwise
     */
    public boolean isValid() {
        return claims != null && claims.isValid();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WorkloadProofToken that = (WorkloadProofToken) o;
        return Objects.equals(header, that.header) &&
               Objects.equals(claims, that.claims) &&
               Objects.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(header, claims, signature);
    }

    @Override
    public String toString() {
        return "WorkloadProofToken{" +
                "header=" + header +
                ", claims=" + claims +
                ", signature='" + signature + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link WorkloadProofToken}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link WorkloadProofToken}.
     */
    public static class Builder {
        private Header header;
        private Claims claims;
        private String signature;
        private String jwtString;

        /**
         * Sets the JOSE header.
         *
         * @param header the header
         * @return this builder instance
         */
        public Builder header(Header header) {
            this.header = header;
            return this;
        }

        /**
         * Sets the claims (payload).
         *
         * @param claims the claims
         * @return this builder instance
         */
        public Builder claims(Claims claims) {
            this.claims = claims;
            return this;
        }

        /**
         * Sets the signature of the WPT.
         * <p>
         * The signature is the base64url-encoded JWS signature value.
         * </p>
         *
         * @param signature the base64url-encoded signature value
         * @return this builder instance
         */
        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Sets the JWT string of the WPT.
         * <p>
         * The JWT string is the complete header.payload.signature representation
         * that was generated during the signing process.
         * </p>
         *
         * @param jwtString the complete JWT string
         * @return this builder instance
         */
        public Builder jwtString(String jwtString) {
            this.jwtString = jwtString;
            return this;
        }

        /**
         * Builds the {@link WorkloadProofToken}.
         * <p>
         * Validates that the required header and claims are present.
         * </p>
         *
         * @return the built token
         * @throws IllegalStateException if the required header or claims are not set
         */
        public WorkloadProofToken build() {
            if (header == null) {
                throw new IllegalStateException("header is REQUIRED for WPT");
            }
            if (claims == null) {
                throw new IllegalStateException("claims is REQUIRED for WPT");
            }
            return new WorkloadProofToken(this);
        }
    }

    /**
     * Claims (Payload) for Workload Proof Token (WPT).
     * <p>
     * The WPT claims contain the following fields as defined in draft-ietf-wimse-wpt Section 2:
     * </p>
     * <table border="1">
     *   <tr><th>Claim</th><th>Description</th><th>Status</th></tr>
     *   <tr><td>aud</td><td>Audience - the target URI of the request</td><td>OPTIONAL</td></tr>
     *   <tr><td>exp</td><td>Expiration Time - when the WPT expires</td><td>OPTIONAL (RECOMMENDED)</td></tr>
     *   <tr><td>jti</td><td>JWT ID - unique identifier for replay protection</td><td>OPTIONAL (SHOULD use)</td></tr>
     *   <tr><td>wth</td><td>Workload Identity Token Hash - SHA-256 hash of the WIT</td><td>REQUIRED</td></tr>
     *   <tr><td>ath</td><td>Access Token Hash - SHA-256 hash of the OAuth access token</td><td>OPTIONAL</td></tr>
     *   <tr><td>tth</td><td>Transaction Token Hash - SHA-256 hash of the transaction token</td><td>OPTIONAL</td></tr>
     *   <tr><td>oth</td><td>Other Tokens Hashes - JSON object with key-value pairs for each token</td><td>OPTIONAL</td></tr>
     * </table>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt</a>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Claims {

        /**
         * Audience claim (aud).
         * <p>
         * The target URI of the request. According to draft-ietf-wimse-wpt Section 2,
         * this claim is OPTIONAL. When validating the WPT, the aud claim MUST match
         * the target URI, or an acceptable alias or normalization thereof.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</a>
         */
        @JsonProperty("aud")
        private final String audience;

        /**
         * Expiration Time claim (exp).
         * <p>
         * The expiration time on or after which the WPT MUST NOT be accepted for processing.
         * According to draft-ietf-wimse-wpt Section 2, this claim is OPTIONAL but RECOMMENDED.
         * The proof of possession MUST be time-limited, typically on the order of minutes.
         * WPTs received outside their validity time MUST be rejected.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</a>
         */
        @JsonProperty("exp")
        private final Date expirationTime;

        /**
         * JWT ID claim (jti).
         * <p>
         * A unique identifier for the WPT. According to draft-ietf-wimse-wpt Section 2,
         * this claim is OPTIONAL but SHOULD be used. The jti MUST uniquely identify the WPT
         * within the scope of a particular sender. This claim SHOULD be used by the receiver
         * to perform basic replay protection against tokens it has already seen.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 Section 4.1.7</a>
         */
        @JsonProperty("jti")
        private final String jwtId;

        /**
         * Workload Identity Token Hash claim (wth).
         * <p>
         * The base64url-encoded SHA-256 hash of the WIT that this WPT is bound to.
         * According to draft-ietf-wimse-wpt Section 2, this claim is REQUIRED.
         * </p>
         * <p>
         * The wth claim binds the WPT to a specific WIT, ensuring that the WPT was created by
         * the workload identified by that WIT. When validating the WPT, the wth claim MUST match
         * the hash of the WIT presented in the Workload-Identity-Token header.
         * </p>
         * <p>
         * Hash computation: {@code BASE64URL(SHA-256(ASCII(WIT)))}
         * </p>
         */
        @JsonProperty("wth")
        private final String workloadTokenHash;

        /**
         * Access Token Hash claim (ath).
         * <p>
         * The base64url-encoded SHA-256 hash of the OAuth access token.
         * According to draft-ietf-wimse-wpt Section 2, this claim is OPTIONAL.
         * However, if presented in conjunction with an OAuth access token, the value
         * of the ath claim MUST match the hash of that token's value.
         * </p>
         * <p>
         * Hash computation: {@code BASE64URL(SHA-256(ASCII(access_token)))}
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.2">RFC 9449 Section 4.2</a>
         */
        @JsonProperty("ath")
        private final String accessTokenHash;

        /**
         * Transaction Token Hash claim (tth).
         * <p>
         * The base64url-encoded SHA-256 hash of the transaction token.
         * According to draft-ietf-wimse-wpt Section 2, this claim is OPTIONAL.
         * However, if presented in conjunction with a transaction token, the value
         * of the tth claim MUST match the hash of that token's value.
         * </p>
         * <p>
         * Hash computation: {@code BASE64URL(SHA-256(ASCII(transaction_token)))}
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/">draft-ietf-oauth-transaction-tokens</a>
         */
        @JsonProperty("tth")
        private final String transactionTokenHash;

        /**
         * Other Tokens Hashes claim (oth).
         * <p>
         * A JSON object containing hashes of other tokens that this WPT is bound to.
         * The value is a JSON object with a key-value pair for each such token, where
         * the key is a token type identifier and the value is the base64url-encoded
         * SHA-256 hash of that token.
         * </p>
         * <p>
         * According to draft-ietf-wimse-wpt Section 2, this claim is OPTIONAL.
         * The oth claim allows the WPT to be bound to additional tokens beyond the WIT.
         * If the oth claim contains entries that are not understood by the recipient,
         * the WPT MUST be rejected. Conversely, additional tokens not covered by the
         * oth claim MUST NOT be used by the recipient to make authorization decisions.
         * </p>
         * <p>
         * Each hash is computed as: {@code BASE64URL(SHA-256(ASCII(token)))}
         * </p>
         */
        @JsonProperty("oth")
        private final Map<String, String> otherTokenHashes;

        private Claims(ClaimsBuilder builder) {
            this.audience = builder.audience;
            this.expirationTime = builder.expirationTime;
            this.jwtId = builder.jwtId;
            this.workloadTokenHash = builder.workloadTokenHash;
            this.accessTokenHash = builder.accessTokenHash;
            this.transactionTokenHash = builder.transactionTokenHash;
            this.otherTokenHashes = builder.otherTokenHashes;
        }

        /**
         * Gets the audience (aud) claim.
         *
         * @return the audience, or null if not present
         */
        public String getAudience() {
            return audience;
        }

        /**
         * Gets the expiration time (exp) claim.
         *
         * @return the expiration time, or null if not present
         */
        public Date getExpirationTime() {
            return expirationTime;
        }

        /**
         * Gets the JWT ID (jti) claim.
         *
         * @return the JWT ID, or null if not present
         */
        public String getJwtId() {
            return jwtId;
        }

        /**
         * Gets the Workload Identity Token Hash (wth) claim.
         *
         * @return the base64url-encoded WIT hash (never null for valid claims)
         */
        public String getWorkloadTokenHash() {
            return workloadTokenHash;
        }

        /**
         * Gets the Access Token Hash (ath) claim.
         *
         * @return the base64url-encoded access token hash, or null if not present
         */
        public String getAccessTokenHash() {
            return accessTokenHash;
        }

        /**
         * Gets the Transaction Token Hash (tth) claim.
         *
         * @return the base64url-encoded transaction token hash, or null if not present
         */
        public String getTransactionTokenHash() {
            return transactionTokenHash;
        }

        /**
         * Gets the Other Tokens Hashes (oth) claim.
         *
         * @return a map of token type to hash, or null if not present
         */
        public Map<String, String> getOtherTokenHashes() {
            return otherTokenHashes;
        }

        /**
         * Checks if the claims indicate the token is expired.
         *
         * @return true if expired, false otherwise
         */
        public boolean isExpired() {
            if (expirationTime == null) {
                return false;
            }
            return expirationTime.before(new Date());
        }

        /**
         * Checks if the claims indicate the token is currently valid (not expired).
         *
         * @return true if valid, false otherwise
         */
        public boolean isValid() {
            Date now = new Date();
            if (expirationTime != null && now.after(expirationTime)) {
                return false;
            }
            return true;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Claims claims = (Claims) o;
            return Objects.equals(audience, claims.audience) &&
                   Objects.equals(expirationTime, claims.expirationTime) &&
                   Objects.equals(jwtId, claims.jwtId) &&
                   Objects.equals(workloadTokenHash, claims.workloadTokenHash) &&
                   Objects.equals(accessTokenHash, claims.accessTokenHash) &&
                   Objects.equals(transactionTokenHash, claims.transactionTokenHash) &&
                   Objects.equals(otherTokenHashes, claims.otherTokenHashes);
        }

        @Override
        public int hashCode() {
            return Objects.hash(audience, expirationTime, jwtId, workloadTokenHash,
                              accessTokenHash, transactionTokenHash, otherTokenHashes);
        }

        @Override
        public String toString() {
            return "Claims{" +
                    "audience='" + audience + '\'' +
                    ", expirationTime=" + expirationTime +
                    ", jwtId='" + jwtId + '\'' +
                    ", workloadTokenHash='" + workloadTokenHash + '\'' +
                    ", accessTokenHash='" + accessTokenHash + '\'' +
                    ", transactionTokenHash='" + transactionTokenHash + '\'' +
                    ", otherTokenHashes=" + otherTokenHashes +
                    '}';
        }

        /**
         * Creates a new builder for {@link Claims}.
         *
         * @return a new builder instance
         */
        public static ClaimsBuilder builder() {
            return new ClaimsBuilder();
        }

        /**
         * Builder for {@link Claims}.
         */
        public static class ClaimsBuilder {
            private String audience;
            private Date expirationTime;
            private String jwtId;
            private String workloadTokenHash;
            private String accessTokenHash;
            private String transactionTokenHash;
            private Map<String, String> otherTokenHashes;

            /**
             * Sets the audience (aud) claim.
             *
             * @param audience the audience
             * @return this builder instance
             */
            public ClaimsBuilder audience(String audience) {
                this.audience = audience;
                return this;
            }

            /**
             * Sets the expiration time (exp) claim.
             *
             * @param expirationTime the expiration time
             * @return this builder instance
             */
            public ClaimsBuilder expirationTime(Date expirationTime) {
                this.expirationTime = expirationTime;
                return this;
            }

            /**
             * Sets the JWT ID (jti) claim.
             *
             * @param jwtId the JWT ID
             * @return this builder instance
             */
            public ClaimsBuilder jwtId(String jwtId) {
                this.jwtId = jwtId;
                return this;
            }

            /**
             * Sets the Workload Identity Token Hash (wth) claim.
             * <p>
             * This claim is REQUIRED. The value must be a base64url-encoded SHA-256 hash of the WIT.
             * </p>
             *
             * @param workloadTokenHash the base64url-encoded WIT hash (required)
             * @return this builder instance
             */
            public ClaimsBuilder workloadTokenHash(String workloadTokenHash) {
                this.workloadTokenHash = workloadTokenHash;
                return this;
            }

            /**
             * Sets the Access Token Hash (ath) claim.
             * <p>
             * The value must be a base64url-encoded SHA-256 hash of the OAuth access token.
             * </p>
             *
             * @param accessTokenHash the base64url-encoded access token hash
             * @return this builder instance
             */
            public ClaimsBuilder accessTokenHash(String accessTokenHash) {
                this.accessTokenHash = accessTokenHash;
                return this;
            }

            /**
             * Sets the Transaction Token Hash (tth) claim.
             * <p>
             * The value must be a base64url-encoded SHA-256 hash of the transaction token.
             * </p>
             *
             * @param transactionTokenHash the base64url-encoded transaction token hash
             * @return this builder instance
             */
            public ClaimsBuilder transactionTokenHash(String transactionTokenHash) {
                this.transactionTokenHash = transactionTokenHash;
                return this;
            }

            /**
             * Sets the Other Tokens Hashes (oth) claim.
             * <p>
             * The value is a JSON object with a key-value pair for each token,
             * where the key is a token type identifier and the value is the
             * base64url-encoded SHA-256 hash of that token.
             * </p>
             *
             * @param otherTokenHashes a map of token type to base64url-encoded hash
             * @return this builder instance
             */
            public ClaimsBuilder otherTokenHashes(Map<String, String> otherTokenHashes) {
                this.otherTokenHashes = otherTokenHashes;
                return this;
            }

            /**
             * Builds the {@link Claims}.
             * <p>
             * Validates that the required {@code wth} claim is present.
             * </p>
             *
             * @return the built claims
             * @throws IllegalStateException if the required {@code wth} claim is not set
             */
            public Claims build() {
                if (workloadTokenHash == null || workloadTokenHash.isEmpty()) {
                    throw new IllegalStateException("workloadTokenHash (wth) is REQUIRED according to draft-ietf-wimse-wpt");
                }
                return new Claims(this);
            }
        }
    }

    /**
     * JOSE Header for Workload Proof Token (WPT).
     * <p>
     * The WPT JOSE header contains the following parameters:
     * </p>
     * <ul>
     *   <li><b>typ</b>: Media type, MUST be {@code wpt+jwt}</li>
     *   <li><b>alg</b>: JWS asymmetric digital signature algorithm corresponding to
     *       the confirmation key in the associated WIT</li>
     * </ul>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 - JSON Web Signature (JWS)</a>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Header {

        /**
         * The media type for WPT.
         */
        public static final String MEDIA_TYPE = "wpt+jwt";

        /**
         * Type parameter (typ).
         * <p>
         * The typ JOSE header parameter of the WPT conveys a media type of {@code wpt+jwt}.
         * This is used to declare the media type of the complete JWT.
         * </p>
         */
        @JsonProperty("typ")
        private final String type;

        /**
         * Algorithm parameter (alg).
         * <p>
         * An identifier for an appropriate JWS asymmetric digital signature algorithm
         * corresponding to the confirmation key in the associated WIT.
         * The algorithm MUST be an asymmetric signature algorithm.
         * </p>
         *
         * @see <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">IANA JOSE Algorithms</a>
         */
        @JsonProperty("alg")
        private final String algorithm;

        private Header(HeaderBuilder builder) {
            this.type = builder.type;
            this.algorithm = builder.algorithm;
        }

        /**
         * Gets the type (typ) parameter.
         *
         * @return the type, should be {@code wpt+jwt}
         */
        public String getType() {
            return type;
        }

        /**
         * Gets the algorithm (alg) parameter.
         *
         * @return the algorithm identifier
         */
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Header header = (Header) o;
            return Objects.equals(type, header.type) &&
                   Objects.equals(algorithm, header.algorithm);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, algorithm);
        }

        @Override
        public String toString() {
            return "Header{" +
                    "type='" + type + '\'' +
                    ", algorithm='" + algorithm + '\'' +
                    '}';
        }

        /**
         * Creates a new builder for {@link Header}.
         *
         * @return a new builder instance
         */
        public static HeaderBuilder builder() {
            return new HeaderBuilder();
        }

        /**
         * Builder for {@link Header}.
         */
        public static class HeaderBuilder {
            private String type = MEDIA_TYPE;
            private String algorithm;

            /**
             * Sets the type (typ) parameter.
             * <p>
             * Default value is {@code wpt+jwt}.
             * </p>
             *
             * @param type the type
             * @return this builder instance
             */
            public HeaderBuilder type(String type) {
                this.type = type;
                return this;
            }

            /**
             * Sets the algorithm (alg) parameter.
             * <p>
             * The algorithm MUST be an asymmetric signature algorithm corresponding to
             * the confirmation key in the associated WIT.
             * </p>
             *
             * @param algorithm the algorithm identifier (e.g., "ES256", "RS256")
             * @return this builder instance
             */
            public HeaderBuilder algorithm(String algorithm) {
                this.algorithm = algorithm;
                return this;
            }

            /**
             * Builds the {@link Header}.
             *
             * @return the built header
             * @throws IllegalStateException if required parameters are not set
             */
            public Header build() {
                if (ValidationUtils.isNullOrEmpty(type)) {
                    throw new IllegalStateException("type (typ) is REQUIRED and should be 'wpt+jwt'");
                }
                if (ValidationUtils.isNullOrEmpty(algorithm)) {
                    throw new IllegalStateException("algorithm (alg) is REQUIRED");
                }
                return new Header(this);
            }
        }
    }
}
