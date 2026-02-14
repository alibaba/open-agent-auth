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
package com.alibaba.openagentauth.core.token.aoat;

import com.alibaba.openagentauth.core.model.audit.AuditTrail;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.References;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Generator for Agent Operation Authorization Tokens (AOAT) following the draft-liu-agent-operation-authorization specification.
 * Creates JWT tokens that authorize agents to perform specific operations on behalf of users.
 * <p>
 * According to draft-liu-agent-operation-authorization, the token includes:
 * </p>
 * <ul>
 *   <li>Standard JWT claims: iss, sub, aud, iat, exp, jti</li>
 *   <li>Required claims: agent_identity, agent_operation_authorization</li>
 *   <li>Optional claims: evidence, context, auditTrail, references, delegation_chain</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
public class AoatGenerator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AoatGenerator.class);

    /**
     * The RSA key used for signing AOATs.
     */
    private final RSAKey signingKey;

    /**
     * The JWS algorithm to use (e.g., RS256).
     */
    private final JWSAlgorithm algorithm;

    /**
     * The issuer identifier (e.g., Authorization Server URL).
     */
    private final String issuer;

    /**
     * The audience identifier (e.g., Resource Server URL).
     */
    private final String audience;

    /**
     * Creates a new AOAT generator.
     *
     * @param signingKey the RSA key used for signing AOATs
     * @param algorithm the JWS algorithm to use (e.g., RS256)
     * @param issuer the issuer identifier (e.g., Authorization Server URL)
     * @param audience the audience identifier (e.g., Resource Server URL)
     */
    public AoatGenerator(RSAKey signingKey, JWSAlgorithm algorithm, String issuer, String audience) {

        // Set instance variables
        this.signingKey = ValidationUtils.validateNotNull(signingKey, "Signing key");
        this.algorithm = ValidationUtils.validateNotNull(algorithm, "Algorithm");
        this.issuer = ValidationUtils.validateNotEmpty(issuer, "Issuer");
        this.audience = ValidationUtils.validateNotEmpty(audience, "Audience");

        logger.info("AoatGenerator initialized with issuer: {}, audience: {}", issuer, audience);
    }

    /**
     * Creates a new builder for generating AOAT tokens.
     * <p>
     * Use this builder to construct AOAT tokens with a fluent API.
     * Required parameters: subject, agentIdentity, authorization, expirationSeconds
     * Optional parameters: evidence, context, auditTrail, references, delegationChain
     * </p>
     *
     * @param subject the user subject (original user identifier)
     * @param agentIdentity the agent identity claim (REQUIRED)
     * @param authorization the authorization metadata (REQUIRED)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a new AoatBuilder instance
     */
    public AoatBuilder newBuilder(String subject, AgentIdentity agentIdentity,
                                   AgentOperationAuthorization authorization,
                                   long expirationSeconds) {
        return new AoatBuilder(subject, agentIdentity, authorization, expirationSeconds);
    }

    /**
     * Generates an Agent Operation Authorization Token with required claims.
     * <p>
     * This is a convenience method that returns the structured AgentOperationAuthToken object.
     * For more flexibility, use {@link #newBuilder(String, AgentIdentity, AgentOperationAuthorization, long)}.
     * </p>
     *
     * @param subject the user subject (original user identifier)
     * @param agentIdentity the agent identity claim (REQUIRED)
     * @param authorization the authorization metadata (REQUIRED)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a signed AgentOperationAuthToken object
     * @throws JOSEException if token generation fails
     */
    public AgentOperationAuthToken generateAoat(String subject, AgentIdentity agentIdentity,
                                                 AgentOperationAuthorization authorization,
                                                 long expirationSeconds) throws JOSEException {
        return newBuilder(subject, agentIdentity, authorization, expirationSeconds).build();
    }

    /**
     * Generates an Agent Operation Authorization Token and returns it as a JWT string.
     * <p>
     * This is a convenience method that returns the JWT string representation
     * of the AOAT. Use this method when you only need the serialized JWT string.
     * </p>
     *
     * @param subject the user subject (original user identifier)
     * @param agentIdentity the agent identity claim (REQUIRED)
     * @param authorization the authorization metadata (REQUIRED)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a signed JWT string representing the AOAT
     * @throws JOSEException if token generation fails
     */
    public String generateAoatAsString(String subject, AgentIdentity agentIdentity,
                                        AgentOperationAuthorization authorization,
                                        long expirationSeconds) throws JOSEException {
        return newBuilder(subject, agentIdentity, authorization, expirationSeconds).build().getJwtString();
    }

    /**
     * Builds an AgentOperationAuthToken object from the claims.
     *
     * @param subject the subject
     * @param agentIdentity the agent identity
     * @param evidence the evidence
     * @param authorization the authorization
     * @param context the context
     * @param auditTrail the audit trail
     * @param references the references
     * @param delegationChain the delegation chain
     * @param issuedAt the issued at time
     * @param expiration the expiration time
     * @param jwtId the JWT ID
     * @return the AgentOperationAuthToken object
     */
    private AgentOperationAuthToken buildAoatObject(String subject,
                                                     AgentIdentity agentIdentity,
                                                     Evidence evidence,
                                                     AgentOperationAuthorization authorization,
                                                     TokenAuthorizationContext context,
                                                     AuditTrail auditTrail,
                                                     References references,
                                                     List<DelegationChain> delegationChain,
                                                     Instant issuedAt,
                                                     Instant expiration,
                                                     String jwtId) {

        // Build AOAT claims
        AgentOperationAuthToken.Claims.Builder claimsBuilder = AgentOperationAuthToken.Claims.builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .issuedAt(issuedAt)
                .expirationTime(expiration)
                .jwtId(jwtId)
                .agentIdentity(agentIdentity)
                .authorization(authorization);

        // Add optional claims
        if (evidence != null) {
            claimsBuilder.evidence(evidence);
        }
        if (context != null) {
            claimsBuilder.context(context);
        }
        if (auditTrail != null) {
            claimsBuilder.auditTrail(auditTrail);
        }
        if (references != null) {
            claimsBuilder.references(references);
        }
        if (delegationChain != null && !delegationChain.isEmpty()) {
            claimsBuilder.delegationChain(delegationChain);
        }

        // Build AOAT header
        // According to draft-liu-agent-operation-authorization, typ should be "JWT"
        AgentOperationAuthToken.Header header = AgentOperationAuthToken.Header.builder()
                .type("JWT")
                .algorithm(algorithm.getName())
                .build();

        // Assemble AOAT
        return AgentOperationAuthToken.builder()
                .header(header)
                .claims(claimsBuilder.build())
                .build();
    }

    /**
     * Signs and serializes the AOAT, returning a new AgentOperationAuthToken object with the signature.
     * <p>
     * This method uses the Serializer to serialize and sign the AOAT directly,
     * following the natural JWT flow of "build → sign → serialize".
     * </p>
     *
     * @param aoat the AgentOperationAuthToken object to sign and serialize
     * @return a new AgentOperationAuthToken object with the signature and JWT string populated
     * @throws JOSEException if signing or serialization fails
     */
    private AgentOperationAuthToken signAndSerializeAoat(AgentOperationAuthToken aoat) throws JOSEException {
        try {
            // Create signer
            JWSSigner signer = new RSASSASigner(signingKey);

            // Use Serializer to serialize and sign the AOAT with the signing key
            String signedJwtString = AoatSerializer.serialize(aoat, signer, algorithm, signingKey);

            // Extract signature from the signed JWT string
            String[] parts = signedJwtString.split("\\.");
            String signature = parts.length > 2 ? parts[2] : "";

            // Return new AOAT object with signature and JWT string populated
            return AgentOperationAuthToken.builder()
                    .header(aoat.getHeader())
                    .claims(aoat.getClaims())
                    .signature(signature)
                    .jwtString(signedJwtString)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to sign AOAT", e);
            throw new JOSEException("Failed to sign AOAT", e);
        }
    }

    /**
     * Gets the signing key.
     *
     * @return the RSA signing key
     */
    public RSAKey getSigningKey() {
        return signingKey;
    }

    /**
     * Gets the JWS algorithm.
     *
     * @return the JWS algorithm
     */
    public JWSAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the issuer.
     *
     * @return the issuer identifier
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the audience.
     *
     * @return the audience identifier
     */
    public String getAudience() {
        return audience;
    }

    /**
     * Builder for AOAT token generation.
     * <p>
     * Provides a fluent API for constructing AOAT tokens with optional claims.
     * This eliminates the need for long parameter lists and improves code readability.
     * </p>
     */
    public class AoatBuilder {

        /**
         * Fields for AOAT token generation.
         */
        private final String subject;
        private final AgentIdentity agentIdentity;
        private final AgentOperationAuthorization authorization;
        private final long expirationSeconds;
        private Evidence evidence;
        private TokenAuthorizationContext context;
        private AuditTrail auditTrail;
        private References references;
        private List<DelegationChain> delegationChain;

        /**
         * Creates a new AoatBuilder with required parameters.
         *
         * @param subject the user subject (original user identifier)
         * @param agentIdentity the agent identity claim (REQUIRED)
         * @param authorization the authorization metadata (REQUIRED)
         * @param expirationSeconds the token expiration time in seconds from now
         */
        private AoatBuilder(String subject, AgentIdentity agentIdentity,
                            AgentOperationAuthorization authorization, long expirationSeconds) {
            this.subject = subject;
            this.agentIdentity = agentIdentity;
            this.authorization = authorization;
            this.expirationSeconds = expirationSeconds;
        }

        /**
         * Sets the evidence claim.
         *
         * @param evidence the evidence claim containing user input
         * @return this builder instance
         */
        public AoatBuilder evidence(Evidence evidence) {
            this.evidence = evidence;
            return this;
        }

        /**
         * Sets the context claim.
         *
         * @param context the authorization context containing rendered text
         * @return this builder instance
         */
        public AoatBuilder context(TokenAuthorizationContext context) {
            this.context = context;
            return this;
        }

        /**
         * Sets the audit trail claim.
         *
         * @param auditTrail the semantic audit trail
         * @return this builder instance
         */
        public AoatBuilder auditTrail(AuditTrail auditTrail) {
            this.auditTrail = auditTrail;
            return this;
        }

        /**
         * Sets the references claim.
         *
         * @param references optional references to related proposals
         * @return this builder instance
         */
        public AoatBuilder references(References references) {
            this.references = references;
            return this;
        }

        /**
         * Sets the delegation chain claim.
         *
         * @param delegationChain delegation chain for agent-to-agent delegation
         * @return this builder instance
         */
        public AoatBuilder delegationChain(List<DelegationChain> delegationChain) {
            this.delegationChain = delegationChain;
            return this;
        }

        /**
         * Builds and signs the AOAT token.
         *
         * @return a signed AgentOperationAuthToken object
         * @throws JOSEException if token generation fails
         */
        public AgentOperationAuthToken build() throws JOSEException {

            // Validate arguments
            ValidationUtils.validateNotEmpty(subject, "Subject");
            ValidationUtils.validateNotNull(agentIdentity, "Agent identity");
            ValidationUtils.validateNotNull(authorization, "Authorization");
            if (expirationSeconds <= 0) {
                throw new IllegalArgumentException("Expiration seconds must be positive");
            }

            logger.info("Generating AOAT for agent: {} with subject: {}", agentIdentity.getId(), subject);

            // Calculate expiration time
            Instant now = Instant.now();
            Instant expiration = now.plusSeconds(expirationSeconds);
            String jwtId = UUID.randomUUID().toString();

            // Build structured AOAT object
            AgentOperationAuthToken aoat = buildAoatObject(subject, agentIdentity, evidence, authorization,
                                                           context, auditTrail, references, delegationChain,
                                                           now, expiration, jwtId);

            // Sign and serialize the AOAT
            aoat = signAndSerializeAoat(aoat);
            logger.debug("Successfully generated AOAT with JTI: {}", jwtId);

            return aoat;
        }
    }

}
