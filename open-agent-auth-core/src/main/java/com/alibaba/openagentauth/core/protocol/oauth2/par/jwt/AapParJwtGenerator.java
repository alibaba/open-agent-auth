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
package com.alibaba.openagentauth.core.protocol.oauth2.par.jwt;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.oauth2.par.AapParParameters;
import com.alibaba.openagentauth.core.token.common.JwtClaimConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for Pushed Authorization Request JWTs (PAR-JWT) following OAuth 2.0 PAR specification.
 * <p>
 * Creates signed JWTs that contain agent operation proposals, evidence, and context for authorization
 * as defined in IETF draft-liu-agent-operation-authorization-01.
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * </p>
 * <pre>{@code
 * RSAKey signingKey = RSAKeyGenerator.generateKey();
 * ParJwtGenerator generator = new ParJwtGenerator(
 *     signingKey,
 *     JWSAlgorithm.RS256,
 *     "https://client.myassistant.example",
 *     "https://as.online-shop.example"
 * );
 *
 * String parJwt = generator.generateParJwt(
 *     agentUserBindingProposal,
 *     evidence,
 *     operationProposal,
 *     context,
 *     3600 // 1 hour expiration
 * );
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
 *     draft-liu-agent-operation-authorization-01</a>
 */
public class AapParJwtGenerator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AapParJwtGenerator.class);

    /**
     * The RSA key used for signing PAR-JWTs.
     */
    private final RSAKey signingKey;

    /**
     * The JWS algorithm to use (e.g., RS256).
     */
    private final JWSAlgorithm algorithm;

    /**
     * The issuer identifier (e.g., client ID).
     */
    private final String issuer;

    /**
     * The audience identifier (e.g., Authorization Server URL).
     */
    private final String audience;

    /**
     * Creates a new PAR-JWT generator.
     *
     * @param signingKey the RSA key used for signing PAR-JWTs
     * @param algorithm the JWS algorithm to use (e.g., RS256)
     * @param issuer the issuer identifier (e.g., client ID)
     * @param audience the audience identifier (e.g., Authorization Server URL)
     */
    public AapParJwtGenerator(RSAKey signingKey, JWSAlgorithm algorithm, String issuer, String audience) {

        // Validate arguments
        ValidationUtils.validateNotNull(signingKey, "Signing key");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");
        if (ValidationUtils.isNullOrEmpty(issuer)) {
            throw new IllegalArgumentException("Issuer cannot be null or empty");
        }
        if (ValidationUtils.isNullOrEmpty(audience)) {
            throw new IllegalArgumentException("Audience cannot be null or empty");
        }

        // Set instance variables
        this.signingKey = signingKey;
        this.algorithm = algorithm;
        this.issuer = issuer;
        this.audience = audience;
    }

    /**
     * Generates a PAR-JWT with the given parameters.
     *
     * @param parameters the PAR-JWT parameters containing all necessary data
     * @return a signed JWT string representing the PAR-JWT
     * @throws JOSEException if token generation fails
     */
    public String generateParJwt(AapParParameters parameters) throws JOSEException {

        ValidationUtils.validateNotNull(parameters, "Parameters");
        logger.info("Generating PAR-JWT with parameters: {}", parameters);

        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(parameters.getExpirationSeconds());

        JWTClaimsSet.Builder claimsBuilder = buildClaims(parameters, now, expiration);
        SignedJWT signedJwt = buildSignedJwt(claimsBuilder);

        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    /**
     * Builds the JWT claims from the parameters.
     *
     * @param parameters the PAR-JWT parameters
     * @param now the current time
     * @param expiration the expiration time
     * @return the JWT claims builder
     */
    private JWTClaimsSet.Builder buildClaims(AapParParameters parameters, Instant now, Instant expiration) {
        String subject = extractSubject(parameters.getContext());
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiration))
                .jwtID(UUID.randomUUID().toString())
                .claim("evidence", JwtClaimConverter.convertEvidenceToMap(parameters.getEvidence()))
                .claim("agent_user_binding_proposal", JwtClaimConverter.convertAgentUserBindingProposalToMap(parameters.getAgentUserBindingProposal()))
                .claim("agent_operation_proposal", parameters.getOperationProposal().getPolicy())
                .claim("context", JwtClaimConverter.convertOperationRequestContextToMap(parameters.getContext()));
        
        // Add client_id to claims for RFC 9126 compliance (pure JWT form)
        if (!ValidationUtils.isNullOrEmpty(parameters.getClientId())) {
            claimsBuilder.claim("client_id", parameters.getClientId());
        }
        
        // Add redirect_uri to claims for RFC 9126 compliance (pure JWT form)
        if (!ValidationUtils.isNullOrEmpty(parameters.getRedirectUri())) {
            claimsBuilder.claim("redirect_uri", parameters.getRedirectUri());
        }
        
        // Add state parameter to claims for session restoration and CSRF protection
        if (!ValidationUtils.isNullOrEmpty(parameters.getState())) {
            claimsBuilder.claim("state", parameters.getState());
            logger.debug("State parameter added to PAR-JWT claims: {}", parameters.getState());
        }
        
        return claimsBuilder;
    }

    /**
     * Extracts the subject from the operation request context.
     * <p>
     * According to draft-liu-agent-operation-authorization-01 specification (Figure 1),
     * the subject claim MUST be derived from the user identity in the context.
     * </p>
     *
     * @param context the operation request context
     * @return the subject identifier
     * @throws IllegalArgumentException if context or user.id is null
     */
    private String extractSubject(OperationRequestContext context) {
        ValidationUtils.validateNotNull(context, "Context");
        ValidationUtils.validateNotNull(context.getUser(), "User context");
        if (ValidationUtils.isNullOrEmpty(context.getUser().getId())) {
            throw new IllegalArgumentException("User ID cannot be null or empty");
        }
        return context.getUser().getId();
    }

    /**
     * Builds the signed JWT from the claims.
     *
     * @param claimsBuilder the JWT claims builder
     * @return the signed JWT
     */
    private SignedJWT buildSignedJwt(JWTClaimsSet.Builder claimsBuilder) {
        JWSHeader header = new JWSHeader.Builder(algorithm)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("JWT"))
                .build();

        return new SignedJWT(header, claimsBuilder.build());
    }

}