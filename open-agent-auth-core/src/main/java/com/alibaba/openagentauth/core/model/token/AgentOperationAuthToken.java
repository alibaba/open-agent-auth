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

import com.alibaba.openagentauth.core.model.audit.AuditTrail;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.References;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.OthBindableToken;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JOSEException;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Represents an Agent Operation Authorization Token (AOAT) that authorizes an agent
 * to perform specific operations on behalf of a user.
 * <p>
 * This token is a JWT that contains claims for agent identity, authorization metadata,
 * evidence, context, audit trail, and optional delegation chain. It follows the
 * draft-liu-agent-operation-authorization specification and includes standard JWT claims
 * (iss, sub, aud, iat, exp, jti) along with agent-specific claims.
 * <p>
 * The token is issued by an Authorization Server and consumed by Resource Servers
 * to validate agent operations. It provides cryptographic proof of the user's original
 * intent through the evidence claim and maintains a semantic audit trail for accountability.
 * <p>
 * This class implements {@link OthBindableToken} to allow AOAT to be cryptographically bound
 * to a Workload Proof Token (WPT) via the oth (other tokens hashes) claim. This enables the WPT
 * to prove that the workload presenting it also possesses the corresponding AOAT authorization.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt-00.html">draft-ietf-wimse-wpt-00</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentOperationAuthToken implements OthBindableToken {

    /**
     * The JOSE header of the AOAT.
     */
    private final Header header;

    /**
     * The claims (payload) of the AOAT.
     */
    private final Claims claims;

    /**
     * The signature of the AOAT.
     * <p>
     * This field stores the base64url-encoded signature of the JWT.
     * It is populated after signing the token.
     * </p>
     */
    @JsonProperty("signature")
    private final String signature;

    /**
     * The JWT string representation of the signed AOAT.
     * <p>
     * This field stores the complete JWT string (header.payload.signature)
     * after the token has been signed. It is populated after signing the token.
     * </p>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final String jwtString;

    private AgentOperationAuthToken(Builder builder) {
        this.header = builder.header;
        this.claims = builder.claims;
        this.signature = builder.signature;
        this.jwtString = builder.jwtString;
    }

    /**
     * Gets the JOSE header of the AOAT.
     *
     * @return the header
     */
    public Header getHeader() {
        return header;
    }

    /**
     * Gets the claims (payload) of the AOAT.
     *
     * @return the claims
     */
    public Claims getClaims() {
        return claims;
    }

    /**
     * Gets the signature of the AOAT.
     *
     * @return the base64url-encoded signature, or null if not signed
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Returns the JWT string representation of this token.
     * <p>
     * This method is part of the {@link OthBindableToken} interface implementation.
     * It returns the complete JWT string (header.payload.signature) and is used by WPT generators
     * to compute the SHA-256 hash for the oth claim.
     * </p>
     *
     * @return the complete JWT string (header.payload.signature), or null if not signed
     * @throws JOSEException if the JWT string is not available
     */
    @Override
    public String getJwtString() throws JOSEException {
        if (ValidationUtils.isNullOrEmpty(jwtString)) {
            throw new JOSEException("AOAT JWT string is not available");
        }
        return jwtString;
    }

    /**
     * Returns the token type identifier used in the oth claim.
     * <p>
     * This method is part of the {@link OthBindableToken} interface implementation.
     * For AOAT, the token type identifier is "aoat" as per the WIMSE specification.
     * </p>
     *
     * @return the token type identifier ("aoat")
     */
    @Override
    public String getTokenType() {
        return "aoat";
    }

    /**
     * Gets the issuer (iss) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getIssuer()}.
     * </p>
     *
     * @return the issuer, or null if not present
     */
    public String getIssuer() {
        return claims != null ? claims.getIssuer() : null;
    }

    /**
     * Gets the subject (sub) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getSubject()}.
     * </p>
     *
     * @return the subject, or null if not present
     */
    public String getSubject() {
        return claims != null ? claims.getSubject() : null;
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
     * Gets the issued at (iat) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getIssuedAt()}.
     * </p>
     *
     * @return the issued at time as Instant, or null if not present
     */
    public Instant getIssuedAt() {
        return claims != null ? claims.getIssuedAt() : null;
    }

    /**
     * Gets the expiration time (exp) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getExpirationTime()}.
     * </p>
     *
     * @return the expiration time as Instant, or null if not present
     */
    public Instant getExpirationTime() {
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
     * Gets the evidence claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getEvidence()}.
     * </p>
     *
     * @return the evidence, or null if not present
     */
    public Evidence getEvidence() {
        return claims != null ? claims.getEvidence() : null;
    }

    /**
     * Gets the agent identity claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getAgentIdentity()}.
     * </p>
     *
     * @return the agent identity, or null if not present
     */
    public AgentIdentity getAgentIdentity() {
        return claims != null ? claims.getAgentIdentity() : null;
    }

    /**
     * Gets the agent operation authorization claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getAuthorization()}.
     * </p>
     *
     * @return the authorization, or null if not present
     */
    public AgentOperationAuthorization getAuthorization() {
        return claims != null ? claims.getAuthorization() : null;
    }

    /**
     * Gets the audit trail claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getAuditTrail()}.
     * </p>
     *
     * @return the audit trail, or null if not present
     */
    public AuditTrail getAuditTrail() {
        return claims != null ? claims.getAuditTrail() : null;
    }

    /**
     * Gets the references claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getReferences()}.
     * </p>
     *
     * @return the references, or null if not present
     */
    public References getReferences() {
        return claims != null ? claims.getReferences() : null;
    }

    /**
     * Gets the delegation chain claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getDelegationChain()}.
     * </p>
     *
     * @return the delegation chain, or null if not present
     */
    public List<DelegationChain> getDelegationChain() {
        return claims != null ? claims.getDelegationChain() : null;
    }

    /**
     * Gets the context claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getContext()}.
     * </p>
     *
     * @return the context, or null if not present
     */
    public TokenAuthorizationContext getContext() {
        return claims != null ? claims.getContext() : null;
    }

    /**
     * Checks if the token is expired.
     *
     * @return true if the token is expired, false otherwise
     */
    public boolean isExpired() {
        return claims != null && claims.isExpired();
    }

    /**
     * Checks if the AOAT is currently valid (not before current time and not expired).
     *
     * @return true if the AOAT is valid, false otherwise
     */
    public boolean isValid() {
        return claims != null && claims.isValid();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AgentOperationAuthToken that = (AgentOperationAuthToken) o;
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
        return "AgentOperationAuthToken{" +
                "header=" + header +
                ", claims=" + claims +
                ", signature='" + signature + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AgentOperationAuthToken}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AgentOperationAuthToken}.
     */
    /**
     * Builder for {@link AgentOperationAuthToken}.
     */
    public static class Builder {
        /**
         * The JOSE header of the AOAT.
         */
        private Header header;
        /**
         * The claims (payload) of the AOAT.
         */
        private Claims claims;
        /**
         * The base64url-encoded signature of the JWT.
         */
        private String signature;
        /**
         * The complete JWT string (header.payload.signature).
         */
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
         * Sets the signature.
         *
         * @param signature the base64url-encoded signature
         * @return this builder instance
         */
        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Sets the JWT string.
         *
         * @param jwtString the complete JWT string (header.payload.signature)
         * @return this builder instance
         */
        public Builder jwtString(String jwtString) {
            this.jwtString = jwtString;
            return this;
        }

        /**
         * Builds the {@link AgentOperationAuthToken}.
         * <p>
         * Validates that the required header and claims are present.
         * </p>
         *
         * @return the built token
         * @throws IllegalStateException if the required header or claims are not set
         */
        public AgentOperationAuthToken build() {
            if (header == null) {
                throw new IllegalStateException("header is REQUIRED for AOAT");
            }
            if (claims == null) {
                throw new IllegalStateException("claims is REQUIRED for AOAT");
            }
            return new AgentOperationAuthToken(this);
        }
    }

    /**
     * JOSE Header for Agent Operation Authorization Token (AOAT).
     * <p>
     * The AOAT JOSE header contains the following parameters:
     * </p>
     * <ul>
     *   <li><b>typ</b>: Media type, MUST be {@code JWT}</li>
     *   <li><b>alg</b>: JWS digital signature algorithm</li>
     * </ul>
     * <p>
     * According to draft-liu-agent-operation-authorization, the typ field MUST be "JWT"
     * to indicate that the token is a standard JSON Web Token.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 - JSON Web Signature (JWS)</a>
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Header {

        /**
         * The media type for AOAT.
         * <p>
         * According to draft-liu-agent-operation-authorization, this MUST be "JWT".
         * </p>
         */
        public static final String MEDIA_TYPE = "JWT";

        /**
         * Type parameter (typ).
         * <p>
         * The typ JOSE header parameter of the AOAT conveys a media type of {@code JWT}.
         * This is used to declare the media type of the complete JWT.
         * </p>
         */
        @JsonProperty("typ")
        private final String type;

        /**
         * Algorithm parameter (alg).
         * <p>
         * An identifier for a JWS digital signature algorithm.
         * The algorithm MUST be a signature algorithm supported by the Authorization Server.
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
         * @return the type, should be {@code JWT}
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

            /**
             * Type parameter (typ).
             * <p>
             * Default value is {@code JWT}.
             * </p>
             */
            private String type = MEDIA_TYPE;

            /**
             * Algorithm parameter (alg).
             * <p>
             * An identifier for a JWS digital signature algorithm.
             * </p>
             */
            private String algorithm;

            /**
             * Sets the type (typ) parameter.
             * <p>
             * Default value is {@code JWT}.
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
             * The algorithm MUST be a signature algorithm supported by the Authorization Server.
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
                    throw new IllegalStateException("type (typ) is REQUIRED and should be 'JWT'");
                }
                if (ValidationUtils.isNullOrEmpty(algorithm)) {
                    throw new IllegalStateException("algorithm (alg) is REQUIRED");
                }
                return new Header(this);
            }
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Claims {

        /**
         * Issuer claim (iss).
         * <p>
         * Identifies the principal that issued the token.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * </p>
         */
        @JsonProperty("iss")
        private final String issuer;

        /**
         * Subject claim (sub).
         * <p>
         * Identifies the user ID for whom the token was issued.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * </p>
         */
        @JsonProperty("sub")
        private final String subject;

        /**
         * Audience claim (aud).
         * <p>
         * Identifies the resource server that is the intended recipient of the token.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * </p>
         */
        @JsonProperty("aud")
        private final String audience;

        /**
         * Issued At claim (iat).
         * <p>
         * Identifies the time at which the JWT was issued.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * The value MUST be a NumericDate (seconds since Epoch, 1970-01-01T00:00:00Z UTC).
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</a>
         */
        @JsonProperty("iat")
        private final Instant issuedAt;

        /**
         * Expiration Time claim (exp).
         * <p>
         * Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * The value MUST be a NumericDate (seconds since Epoch, 1970-01-01T00:00:00Z UTC).
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</a>
         */
        @JsonProperty("exp")
        private final Instant expirationTime;

        /**
         * JWT ID claim (jti).
         * <p>
         * Provides a unique identifier for the JWT.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * The identifier value MUST be assigned in a manner that ensures that there is a negligible
         * probability that the same value will be accidentally assigned to a different JWT.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 Section 4.1.7</a>
         */
        @JsonProperty("jti")
        private final String jwtId;

        /**
         * Evidence claim.
         * <p>
         * This claim contains a JWT-VC (Verifiable Credential) that holds the original
         * user prompt credential, providing cryptographic proof of the user's original intent.
         * According to draft-liu-agent-operation-authorization, this claim is OPTIONAL.
         * </p>
         */
        @JsonProperty("evidence")
        private final Evidence evidence;

        /**
         * Agent Identity claim.
         * <p>
         * This claim identifies the agent that is authorized to perform operations.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * </p>
         */
        @JsonProperty("agent_identity")
        private final AgentIdentity agentIdentity;

        /**
         * Agent Operation Authorization claim.
         * <p>
         * This claim conveys authorization metadata for agent-performed operations,
         * including a reference to a registered policy via the policy_id field.
         * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
         * </p>
         */
        @JsonProperty("agent_operation_authorization")
        private final AgentOperationAuthorization authorization;

        /**
         * Context claim.
         * <p>
         * This claim contains contextual information for policy evaluation,
         * including rendered text that describes the authorized operation.
         * According to draft-liu-agent-operation-authorization, this claim is OPTIONAL.
         * </p>
         */
        @JsonProperty("context")
        private final TokenAuthorizationContext context;

        /**
         * Audit Trail claim.
         * <p>
         * This claim establishes a complete, semantically traceable chain from the user's
         * original intent to the system's final executed action, known as a Semantic Audit Trail.
         * According to draft-liu-agent-operation-authorization, this claim is OPTIONAL.
         * </p>
         */
        @JsonProperty("audit_trail")
        private final AuditTrail auditTrail;

        /**
         * References claim.
         * <p>
         * This claim contains optional references to related proposals or other resources.
         * According to draft-liu-agent-operation-authorization, this claim is OPTIONAL.
         * </p>
         */
        @JsonProperty("references")
        private final References references;

        /**
         * Delegation Chain claim.
         * <p>
         * This claim contains an array of delegation records when the operation involves
         * agent-to-agent delegation.
         * According to draft-liu-agent-operation-authorization, this claim is OPTIONAL.
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
         */
        @JsonProperty("delegation_chain")
        private final List<DelegationChain> delegationChain;

        private Claims(Builder builder) {
            this.issuer = builder.issuer;
            this.subject = builder.subject;
            this.audience = builder.audience;
            this.issuedAt = builder.issuedAt;
            this.expirationTime = builder.expirationTime;
            this.jwtId = builder.jwtId;
            this.agentIdentity = builder.agentIdentity;
            this.authorization = builder.authorization;
            this.context = builder.context;
            this.delegationChain = builder.delegationChain;
            this.evidence = builder.evidence;
            this.auditTrail = builder.auditTrail;
            this.references = builder.references;
        }

        /**
         * Gets the issuer (iss) claim.
         *
         * @return the issuer
         */
        public String getIssuer() {
            return issuer;
        }

        /**
         * Gets the subject (sub) claim.
         *
         * @return the subject
         */
        public String getSubject() {
            return subject;
        }

        /**
         * Gets the audience (aud) claim.
         *
         * @return the audience
         */
        public String getAudience() {
            return audience;
        }

        /**
         * Gets the issued at (iat) claim.
         *
         * @return the issued at time as Instant
         */
        public Instant getIssuedAt() {
            return issuedAt;
        }

        /**
         * Gets the expiration time (exp) claim.
         * <p>
         * This claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
         * </p>
         *
         * @return the expiration time as Instant
         */
        public Instant getExpirationTime() {
            return expirationTime;
        }

        /**
         * Gets the JWT ID (jti) claim.
         * <p>
         * This claim provides a unique identifier for the JWT.
         * </p>
         *
         * @return the JWT ID
         */
        public String getJwtId() {
            return jwtId;
        }

        /**
         * Gets the evidence claim.
         * <p>
         * This claim contains a JWT-VC (Verifiable Credential) that holds the original
         * user prompt credential, providing cryptographic proof of the user's original intent.
         * </p>
         *
         * @return the evidence, or null if not present
         */
        public Evidence getEvidence() {
            return evidence;
        }

        /**
         * Gets the agent identity claim.
         * <p>
         * This claim identifies the agent that is authorized to perform operations.
         * </p>
         *
         * @return the agent identity
         */
        public AgentIdentity getAgentIdentity() {
            return agentIdentity;
        }

        /**
         * Gets the agent operation authorization claim.
         * <p>
         * This claim conveys authorization metadata for agent-performed operations,
         * including a reference to a registered policy via the policy_id field.
         * </p>
         *
         * @return the authorization
         */
        public AgentOperationAuthorization getAuthorization() {
            return authorization;
        }

        /**
         * Gets the audit trail claim.
         * <p>
         * This claim establishes a complete, semantically traceable chain from the user's
         * original intent to the system's final executed action, known as a Semantic Audit Trail.
         * </p>
         *
         * @return the audit trail, or null if not present
         */
        public AuditTrail getAuditTrail() {
            return auditTrail;
        }

        /**
         * Gets the references claim.
         * <p>
         * This claim contains optional references to related proposals or other resources.
         * </p>
         *
         * @return the references, or null if not present
         */
        public References getReferences() {
            return references;
        }

        /**
         * Gets the delegation chain claim.
         * <p>
         * This claim contains an array of delegation records when the operation involves
         * agent-to-agent delegation.
         * </p>
         *
         * @return the delegation chain, or null if not present
         */
        public List<DelegationChain> getDelegationChain() {
            return delegationChain;
        }

        /**
         * Gets the context claim.
         * <p>
         * This claim contains contextual information for policy evaluation,
         * including rendered text that describes the authorized operation.
         * </p>
         *
         * @return the context, or null if not present
         */
        public TokenAuthorizationContext getContext() {
            return context;
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
            return expirationTime.isBefore(Instant.now());
        }

        /**
         * Checks if the claims indicate the token is currently valid (not expired).
         *
         * @return true if valid, false otherwise
         */
        public boolean isValid() {
            Instant now = Instant.now();
            if (expirationTime != null && now.isAfter(expirationTime)) {
                return false;
            }
            return true;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Claims that = (Claims) o;
            return Objects.equals(issuer, that.issuer) &&
                    Objects.equals(subject, that.subject) &&
                    Objects.equals(audience, that.audience) &&
                    Objects.equals(expirationTime, that.expirationTime) &&
                    Objects.equals(issuedAt, that.issuedAt) &&
                    Objects.equals(jwtId, that.jwtId) &&
                    Objects.equals(agentIdentity, that.agentIdentity) &&
                    Objects.equals(authorization, that.authorization) &&
                    Objects.equals(context, that.context) &&
                    Objects.equals(delegationChain, that.delegationChain) &&
                    Objects.equals(evidence, that.evidence) &&
                    Objects.equals(auditTrail, that.auditTrail) &&
                    Objects.equals(references, that.references);
        }

        @Override
        public int hashCode() {
            return Objects.hash(issuer, subject, audience, expirationTime, issuedAt, jwtId,
                    agentIdentity, authorization, delegationChain, context,
                    evidence, auditTrail, references);
        }

        @Override
        public String toString() {
            return "Claims{" +
                    "issuer='" + issuer + '\'' +
                    ", subject='" + subject + '\'' +
                    ", audience='" + audience + '\'' +
                    ", expirationTime=" + expirationTime +
                    ", issuedAt=" + issuedAt +
                    ", jwtId='" + jwtId + '\'' +
                    ", agentIdentity=" + agentIdentity +
                    ", authorization=" + authorization +
                    ", delegationChain=" + delegationChain +
                    ", context='" + context + '\'' +
                    ", evidence=" + evidence +
                    ", auditTrail=" + auditTrail +
                    ", references=" + references +
                    '}';
        }

        /**
         * Creates a new builder for {@link AgentOperationAuthToken}.
         *
         * @return a new builder instance
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * Builder for {@link Claims}.
         */
        public static class Builder {
            /**
             * Issuer claim (iss).
             */
            private String issuer;
            /**
             * Subject claim (sub).
             */
            private String subject;
            /**
             * Audience claim (aud).
             */
            private String audience;
            /**
             * Issued At claim (iat).
             */
            private Instant issuedAt;
            /**
             * Expiration Time claim (exp).
             */
            private Instant expirationTime;
            /**
             * JWT ID claim (jti).
             */
            private String jwtId;
            /**
             * Evidence claim.
             */
            private Evidence evidence;
            /**
             * Agent Identity claim.
             */
            private AgentIdentity agentIdentity;
            /**
             * Agent Operation Authorization claim.
             */
            private AgentOperationAuthorization authorization;
            /**
             * Audit Trail claim.
             */
            private AuditTrail auditTrail;
            /**
             * References claim.
             */
            private References references;
            /**
             * Delegation Chain claim.
             */
            private List<DelegationChain> delegationChain;
            /**
             * Context claim.
             */
            private TokenAuthorizationContext context;

            /**
             * Sets the issuer (iss) claim.
             * <p>
             * This claim identifies the Authorization Server that issued the token.
             * </p>
             *
             * @param issuer the issuer
             * @return this builder instance
             */
            public Builder issuer(String issuer) {
                this.issuer = issuer;
                return this;
            }

            /**
             * Sets the subject (sub) claim.
             * <p>
             * This claim identifies the user ID for whom the token was issued.
             * </p>
             *
             * @param subject the subject
             * @return this builder instance
             */
            public Builder subject(String subject) {
                this.subject = subject;
                return this;
            }

            /**
             * Sets the audience (aud) claim.
             * <p>
             * This claim identifies the resource server that is the intended recipient of the token.
             * </p>
             *
             * @param audience the audience
             * @return this builder instance
             */
            public Builder audience(String audience) {
                this.audience = audience;
                return this;
            }

            /**
             * Sets the issued at (iat) claim.
             * <p>
             * This claim identifies the time at which the JWT was issued.
             * </p>
             *
             * @param issuedAt the issued at time as Instant
             * @return this builder instance
             */
            public Builder issuedAt(Instant issuedAt) {
                this.issuedAt = issuedAt;
                return this;
            }

            /**
             * Sets the expiration time (exp) claim.
             * <p>
             * This claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
             * </p>
             *
             * @param expirationTime the expiration time as Instant
             * @return this builder instance
             */
            public Builder expirationTime(Instant expirationTime) {
                this.expirationTime = expirationTime;
                return this;
            }

            /**
             * Sets the JWT ID (jti) claim.
             * <p>
             * This claim provides a unique identifier for the JWT.
             * </p>
             *
             * @param jwtId the JWT ID
             * @return this builder instance
             */
            public Builder jwtId(String jwtId) {
                this.jwtId = jwtId;
                return this;
            }

            /**
             * Sets the evidence claim.
             * <p>
             * This claim contains a JWT-VC (Verifiable Credential) that holds the original
             * user prompt credential, providing cryptographic proof of the user's original intent.
             * </p>
             *
             * @param evidence the evidence
             * @return this builder instance
             */
            public Builder evidence(Evidence evidence) {
                this.evidence = evidence;
                return this;
            }

            /**
             * Sets the agent identity claim.
             * <p>
             * This claim identifies the agent that is authorized to perform operations.
             * </p>
             *
             * @param agentIdentity the agent identity
             * @return this builder instance
             */
            public Builder agentIdentity(AgentIdentity agentIdentity) {
                this.agentIdentity = agentIdentity;
                return this;
            }

            /**
             * Sets the agent operation authorization claim.
             * <p>
             * This claim conveys authorization metadata for agent-performed operations,
             * including a reference to a registered policy via the policy_id field.
             * </p>
             *
             * @param authorization the authorization
             * @return this builder instance
             */
            public Builder authorization(AgentOperationAuthorization authorization) {
                this.authorization = authorization;
                return this;
            }

            /**
             * Sets the audit trail claim.
             * <p>
             * This claim establishes a complete, semantically traceable chain from the user's
             * original intent to the system's final executed action, known as a Semantic Audit Trail.
             * </p>
             *
             * @param auditTrail the audit trail
             * @return this builder instance
             */
            public Builder auditTrail(AuditTrail auditTrail) {
                this.auditTrail = auditTrail;
                return this;
            }

            /**
             * Sets the references claim.
             * <p>
             * This claim contains optional references to related proposals or other resources.
             * </p>
             *
             * @param references the references
             * @return this builder instance
             */
            public Builder references(References references) {
                this.references = references;
                return this;
            }

            /**
             * Sets the delegation chain claim.
             * <p>
             * This claim contains an array of delegation records when the operation involves
             * agent-to-agent delegation.
             * </p>
             *
             * @param delegationChain the delegation chain
             * @return this builder instance
             */
            public Builder delegationChain(List<DelegationChain> delegationChain) {
                this.delegationChain = delegationChain;
                return this;
            }

            /**
             * Sets the context claim.
             * <p>
             * This claim contains contextual information for policy evaluation,
             * including rendered text that describes the authorized operation.
             * </p>
             *
             * @param context the context
             * @return this builder instance
             */
            public Builder context(TokenAuthorizationContext context) {
                this.context = context;
                return this;
            }

            /**
             * Builds the {@link Claims}.
             * <p>
             * Validates that the required claims are present.
             * According to draft-liu-agent-operation-authorization, the required claims are:
             * - iss (Issuer): Authorization Server URI (REQUIRED)
             * - sub (Subject): User ID (REQUIRED)
             * - aud (Audience): Resource Server URI (REQUIRED)
             * - exp (Expiration Time): Token expiration time (REQUIRED)
             * - iat (Issued At): Token issuance time (REQUIRED)
             * - jti (JWT ID): Unique token identifier (REQUIRED)
             * - agent_identity: Agent identity information (REQUIRED)
             * - agent_operation_authorization: Authorization metadata with policy_id (REQUIRED)
             * </p>
             *
             * @return the built claims
             * @throws IllegalStateException if required claims are not set
             */
            public Claims build() {
                if (ValidationUtils.isNullOrEmpty(issuer)) {
                    throw new IllegalStateException("issuer (iss) is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (ValidationUtils.isNullOrEmpty(subject)) {
                    throw new IllegalStateException("subject (sub) is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (ValidationUtils.isNullOrEmpty(audience)) {
                    throw new IllegalStateException("audience (aud) is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (expirationTime == null) {
                    throw new IllegalStateException("expirationTime (exp) is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (issuedAt == null) {
                    throw new IllegalStateException("issuedAt (iat) is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (ValidationUtils.isNullOrEmpty(jwtId)) {
                    throw new IllegalStateException("jwtId (jti) is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (agentIdentity == null) {
                    throw new IllegalStateException("agent_identity is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                if (authorization == null) {
                    throw new IllegalStateException("agent_operation_authorization is REQUIRED according to draft-liu-agent-operation-authorization");
                }
                return new Claims(this);
            }
        }
    }
}
