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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.verify.SignatureVerificationUtils;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

/**
 * Validator for Agent Operation Authorization Tokens (AOAT) following the draft-liu-agent-operation-authorization specification.
 * Verifies the signature, expiration, and structure of AOATs.
 * <p>
 * According to draft-liu-agent-operation-authorization, the validator checks:
 * </p>
 * <ul>
 *   <li>Standard JWT claims: iss, sub, aud, iat, exp, jti</li>
 *   <li>Required claims: agent_identity, agent_operation_authorization</li>
 *   <li>Optional claims: evidence, context, auditTrail, references, delegation_chain</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
public class AoatValidator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AoatValidator.class);

    /**
     * The KeyManager used for managing cryptographic keys.
     * Supports dynamic key rotation through KeyManager abstraction.
     */
    private final KeyManager keyManager;

    /**
     * The verification key ID used for signature verification.
     */
    private final String verificationKeyId;

    /**
     * The expected issuer for validation.
     */
    private final String expectedIssuer;

    /**
     * The expected audience for validation.
     */
    private final String expectedAudience;

    /**
     * The AOAT parser.
     */
    private final AoatParser aoatParser;

    /**
     * Creates a new AOAT validator.
     *
     * @param keyManager the KeyManager for verifying AOAT signatures
     * @param verificationKeyId the verification key ID
     * @param expectedIssuer the expected issuer identifier
     * @param expectedAudience the expected audience identifier
     */
    public AoatValidator(KeyManager keyManager, String verificationKeyId, String expectedIssuer, String expectedAudience) {

        // Set instance variables
        this.keyManager = ValidationUtils.validateNotNull(keyManager, "Key manager");
        this.verificationKeyId = ValidationUtils.validateNotEmpty(verificationKeyId, "Verification key ID");
        this.expectedIssuer = ValidationUtils.validateNotEmpty(expectedIssuer, "Expected issuer");
        this.expectedAudience = ValidationUtils.validateNotEmpty(expectedAudience, "Expected audience");
        this.aoatParser = new AoatParser();

        logger.info("AoatValidator initialized with verification key ID: {}, expected issuer: {}, audience: {}",
                   verificationKeyId, expectedIssuer, expectedAudience);
    }

    /**
     * Validates an Agent Operation Authorization Token.
     *
     * @param aoatJwt the JWT string representing the AOAT
     * @return a TokenValidationResult containing the validation outcome and parsed token
     * @throws ParseException if the JWT cannot be parsed
     */
    public TokenValidationResult<AgentOperationAuthToken> validate(String aoatJwt) throws ParseException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(aoatJwt)) {
            return TokenValidationResult.failure("AOAT cannot be null or empty");
        }

        SignedJWT signedJwt = SignedJWT.parse(aoatJwt);

        // 1. Verify the signature of the AOAT
        if (!verifySignature(signedJwt)) {
            return TokenValidationResult.failure("Invalid AOAT signature");
        }

        // 2. Verify that the AOAT has not expired
        if (!verifyExpiration(signedJwt)) {
            return TokenValidationResult.failure("AOAT has expired");
        }

        // 3. Verify that the AOAT issuer matches the expected issuer
        if (!verifyIssuer(signedJwt)) {
            return TokenValidationResult.failure("Invalid issuer");
        }

        // 4. Verify that the AOAT audience matches the expected audience
        if (!verifyAudience(signedJwt)) {
            return TokenValidationResult.failure("Invalid audience");
        }

        // 5. Verify that all required claims are present in the AOAT
        if (!verifyRequiredClaims(signedJwt)) {
            return TokenValidationResult.failure("Missing required claims");
        }

        // Parse the AOAT and return the parsed token
        AgentOperationAuthToken aoat = aoatParser.parse(signedJwt);
        logger.debug("Successfully validated AOAT with subject: {}", aoat.getSubject());

        return TokenValidationResult.success(aoat);
    }

    /**
     * Verifies the signature of the AOAT.
     *
     * @param signedJwt the signed JWT
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifySignature(SignedJWT signedJwt) {
        return SignatureVerificationUtils.verifySignature(signedJwt, keyManager, verificationKeyId);
    }

    /**
     * Verifies that the AOAT has not expired.
     *
     * @param signedJwt the signed JWT
     * @return true if the token is not expired, false otherwise
     */
    private boolean verifyExpiration(SignedJWT signedJwt) {
        try {
            // Get AOAT expiration time
            var expirationTime = signedJwt.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null) {
                logger.warn("AOAT missing expiration time");
                return false;
            }

            // Verify that the token is not expired
            boolean isValid = expirationTime.after(Date.from(Instant.now()));
            if (!isValid) {
                logger.warn("AOAT has expired at: {}", expirationTime);
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing AOAT expiration time", e);
            return false;
        }
    }

    /**
     * Verifies that the AOAT issuer matches the expected issuer.
     *
     * @param signedJwt the signed JWT
     * @return true if the issuer is valid, false otherwise
     */
    private boolean verifyIssuer(SignedJWT signedJwt) {
        try {
            // Get AOAT issuer
            String issuer = signedJwt.getJWTClaimsSet().getIssuer();
            boolean isValid = expectedIssuer.equals(issuer);

            // Log if issuer is invalid
            if (!isValid) {
                logger.warn("AOAT issuer '{}' does not match expected issuer '{}'",
                           issuer, expectedIssuer);
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing AOAT issuer", e);
            return false;
        }
    }

    /**
     * Verifies that the AOAT audience matches the expected audience.
     *
     * @param signedJwt the signed JWT
     * @return true if the audience is valid, false otherwise
     */
    private boolean verifyAudience(SignedJWT signedJwt) {
        try {
            // Get AOAT audience
            var audiences = signedJwt.getJWTClaimsSet().getAudience();

            if (audiences == null || audiences.isEmpty()) {
                logger.warn("AOAT missing audience");
                return false;
            }

            boolean isValid = audiences.contains(expectedAudience);

            // Log if audience is invalid
            if (!isValid) {
                logger.warn("AOAT audience '{}' does not match expected audience '{}'",
                           audiences, expectedAudience);
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing AOAT audience", e);
            return false;
        }
    }

    /**
     * Verifies that all required claims are present in the AOAT.
     * <p>
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
     * <p>
     * Note: iss, aud, exp are verified separately in verifyIssuer, verifyAudience, and verifyExpiration methods.
     * This method verifies the remaining required claims: sub, iat, jti, agent_identity, and agent_operation_authorization.
     * </p>
     *
     * @param signedJwt the signed JWT
     * @return true if all required claims are present, false otherwise
     */
    private boolean verifyRequiredClaims(SignedJWT signedJwt) {
        try {
            // Get AOAT claims
            var claims = signedJwt.getJWTClaimsSet().getClaims();

            // Verify subject (sub) claim - REQUIRED
            if (!claims.containsKey("sub")) {
                logger.warn("AOAT missing required claim: sub (subject)");
                return false;
            }

            // Verify issued at (iat) claim - REQUIRED
            if (!claims.containsKey("iat")) {
                logger.warn("AOAT missing required claim: iat (issued at)");
                return false;
            }

            // Verify JWT ID (jti) claim - REQUIRED
            if (!claims.containsKey("jti")) {
                logger.warn("AOAT missing required claim: jti (JWT ID)");
                return false;
            }

            // Verify agent_identity claim - REQUIRED
            if (!claims.containsKey("agent_identity")) {
                logger.warn("AOAT missing required claim: agent_identity");
                return false;
            }

            // Verify agent_operation_authorization claim - REQUIRED
            if (!claims.containsKey("agent_operation_authorization")) {
                logger.warn("AOAT missing required claim: agent_operation_authorization");
                return false;
            }

            return true;
        } catch (ParseException e) {
            logger.error("Error parsing AOAT claims", e);
            return false;
        }
    }

}