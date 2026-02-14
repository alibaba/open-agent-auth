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
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.token.common.JwtClaimConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Validator for Pushed Authorization Request JWTs (PAR-JWT) following OAuth 2.0 PAR specification.
 * <p>
 * Verifies the signature, expiration, issuer, audience, and required claims of PAR-JWTs
 * as defined in IETF draft-liu-agent-operation-authorization-01.
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * </p>
 * <pre>{@code
 * RSAKey verificationKey = RSAKeyGenerator.generateKey();
 * ParJwtValidator validator = new ParJwtValidator(
 *     verificationKey,
 *     "https://client.myassistant.example",
 *     "https://as.online-shop.example"
 * );
 *
 * ParJwtValidator.ValidationResult result = validator.validate(parJwtString);
 * if (result.isValid()) {
 *     ParJwtClaims claims = result.getClaims().orElseThrow();
 *     // Process validated claims
 * } else {
 *     String error = result.getErrorMessage().orElse("Unknown error");
 *     // Handle validation failure
 * }
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
 *     draft-liu-agent-operation-authorization-01</a>
 */
public class AapParJwtValidator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AapParJwtValidator.class);

    /**
     * The RSA public key used for verifying PAR-JWT signatures.
     */
    private final RSAKey verificationKey;

    /**
     * The expected issuer for validation.
     */
    private final String expectedIssuer;

    /**
     * The expected audience for validation.
     */
    private final String expectedAudience;

    /**
     * Creates a new PAR-JWT validator.
     *
     * @param verificationKey the RSA public key used for verifying PAR-JWT signatures
     * @param expectedIssuer the expected issuer identifier
     * @param expectedAudience the expected audience identifier
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public AapParJwtValidator(RSAKey verificationKey, String expectedIssuer, String expectedAudience) {
        this.verificationKey = validateParameter(verificationKey, "Verification key");
        this.expectedIssuer = validateNotBlank(expectedIssuer, "Expected issuer");
        this.expectedAudience = validateNotBlank(expectedAudience, "Expected audience");
    }

    /**
     * Validates a PAR-JWT.
     *
     * @param parJwt the JWT string representing the PAR-JWT
     * @return a ValidationResult containing the validation outcome and parsed claims
     */
    public ValidationResult validate(String parJwt) {
        try {
            return performValidation(parJwt);
        } catch (ParseException e) {
            logger.error("Error parsing PAR-JWT", e);
            return ValidationResult.failure("Error parsing PAR-JWT: " + e.getMessage());
        }
    }

    /**
     * Performs the actual validation of a PAR-JWT.
     *
     * @param parJwt the JWT string representing the PAR-JWT
     * @return a ValidationResult containing the validation outcome and parsed claims
     */
    private ValidationResult performValidation(String parJwt) throws ParseException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(parJwt)) {
            return ValidationResult.failure("PAR-JWT cannot be null or empty");
        }

        // Parsed and acquired the signed JWT
        logger.debug("Validating PAR-JWT");
        SignedJWT signedJwt = SignedJWT.parse(parJwt);

        // Validate JWT structure
        ValidationStepResult result = validateJwtStructure(signedJwt);
        if (!result.isValid()) {
            return ValidationResult.failure(result.errorMessage());
        }

        // Validate JWT claims
        ParJwtClaims claims = extractClaims(signedJwt);
        logger.info("Successfully validated PAR-JWT with JTI: {}", claims.getJwtId());

        // Return success
        return ValidationResult.success(claims);
    }

    /**
     * Validates the structure of a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ValidationStepResult containing the validation outcome
     */
    private ValidationStepResult validateJwtStructure(SignedJWT signedJwt) throws ParseException {

        // 1. The PAR-JWT must be signed with a valid RSA key
        ValidationStepResult signatureResult = verifySignature(signedJwt);
        if (!signatureResult.isValid()) {
            return signatureResult;
        }

        // 2. The PAR-JWT should not have expired
        ValidationStepResult expirationResult = verifyExpiration(signedJwt);
        if (!expirationResult.isValid()) {
            return expirationResult;
        }

        // 3. The PAR-JWT issuer should match the expected issuer
        ValidationStepResult issuerResult = verifyIssuer(signedJwt);
        if (!issuerResult.isValid()) {
            return issuerResult;
        }

        // 4. The PAR-JWT audience should match the expected audience
        ValidationStepResult audienceResult = verifyAudience(signedJwt);
        if (!audienceResult.isValid()) {
            return audienceResult;
        }

        // 5. The PAR-JWT should contain the required claims
        ValidationStepResult claimsResult = verifyRequiredClaims(signedJwt);
        if (!claimsResult.isValid()) {
            return claimsResult;
        }

        // Return success
        return ValidationStepResult.success();
    }

    /**
     * Verifies the signature of a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ValidationStepResult containing the validation outcome
     */
    private ValidationStepResult verifySignature(SignedJWT signedJwt) {
        try {
            JWSVerifier verifier = new RSASSAVerifier(verificationKey);
            boolean isValid = signedJwt.verify(verifier);

            if (!isValid) {
                logger.warn("PAR-JWT signature verification failed");
                return ValidationStepResult.failure("Invalid PAR-JWT signature");
            }
            return ValidationStepResult.success();

        } catch (JOSEException e) {
            logger.error("Error verifying PAR-JWT signature", e);
            return ValidationStepResult.failure("Error verifying signature: " + e.getMessage());
        }
    }

    /**
     * Verifies the expiration of a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ValidationStepResult containing the validation outcome
     */
    private ValidationStepResult verifyExpiration(SignedJWT signedJwt) throws ParseException {

        // Get PAR-JWT expiration time
        Date expirationTime = signedJwt.getJWTClaimsSet().getExpirationTime();

        // Verify that the token is valid
        if (expirationTime == null) {
            logger.warn("PAR-JWT missing expiration time");
            return ValidationStepResult.failure("PAR-JWT missing expiration time");
        }
        boolean isValid = expirationTime.after(Date.from(Instant.now()));

        if (!isValid) {
            logger.warn("PAR-JWT has expired at: {}", expirationTime);
            return ValidationStepResult.failure("PAR-JWT has expired");
        }
        return ValidationStepResult.success();
    }

    /**
     * Verifies the issuer of a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ValidationStepResult containing the validation outcome
     */
    private ValidationStepResult verifyIssuer(SignedJWT signedJwt) throws ParseException {

        // Get PAR-JWT issuer
        String issuer = signedJwt.getJWTClaimsSet().getIssuer();

        // Currently, we only support a single issuer
        if (!expectedIssuer.equals(issuer)) {
            logger.warn("PAR-JWT issuer '{}' does not match expected issuer '{}'", issuer, expectedIssuer);
            return ValidationStepResult.failure("Invalid issuer: '" + issuer + "'");
        }

        return ValidationStepResult.success();
    }

    /**
     * Verifies the audience of a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ValidationStepResult containing the validation outcome
     */
    private ValidationStepResult verifyAudience(SignedJWT signedJwt) throws ParseException {

        List<String> audiences = signedJwt.getJWTClaimsSet().getAudience();

        if (audiences == null || audiences.isEmpty()) {
            logger.warn("PAR-JWT missing audience");
            return ValidationStepResult.failure("PAR-JWT missing audience");
        }

        // Currently, we only support a single audience
        if (!audiences.contains(expectedAudience)) {
            logger.warn("PAR-JWT audience '{}' does not match expected audience '{}'", audiences, expectedAudience);
            return ValidationStepResult.failure("Invalid audience: " + audiences);
        }

        return ValidationStepResult.success();
    }

    /**
     * Verifies the required claims of a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ValidationStepResult containing the validation outcome
     */
    private ValidationStepResult verifyRequiredClaims(SignedJWT signedJwt) throws ParseException {

        // Get PAR-JWT custom claims
        Map<String, Object> claims = signedJwt.getJWTClaimsSet().getClaims();

        // According to IETF draft-liu-agent-operation-authorization-01, PAR-JWT must contain:
        // evidence, agent_user_binding_proposal, agent_operation_proposal, and context
        String[] requiredClaims = {"evidence", "agent_user_binding_proposal", "agent_operation_proposal", "context"};

        // Verify that the token contains all required claims
        for (String claimName : requiredClaims) {
            if (!claims.containsKey(claimName)) {
                logger.warn("PAR-JWT missing required claim: {}", claimName);
                return ValidationStepResult.failure("Missing required claim: " + claimName);
            }
        }

        return ValidationStepResult.success();
    }

    /**
     * Extracts the claims from a PAR-JWT.
     *
     * @param signedJwt the signed JWT
     * @return a ParJwtClaims containing the extracted claims
     */
    private ParJwtClaims extractClaims(SignedJWT signedJwt) throws ParseException {

        // Get claims set from the signed JWT
        var claimsSet = signedJwt.getJWTClaimsSet();

        // Build ParJwtClaims
        return ParJwtClaims.builder()
                .issuer(claimsSet.getIssuer())
                .subject(claimsSet.getSubject())
                .audience(claimsSet.getAudience())
                .issueTime(claimsSet.getIssueTime())
                .expirationTime(claimsSet.getExpirationTime())
                .jwtId(claimsSet.getJWTID())
                .state(claimsSet.getStringClaim("state"))
                .evidence(extractEvidence(claimsSet))
                .agentUserBindingProposal(extractAgentUserBindingProposal(claimsSet))
                .operationProposal(extractOperationProposal(claimsSet))
                .context(extractContext(claimsSet))
                .build();
    }

    /**
     * Extracts the evidence from a PAR-JWT.
     * Claims are stored as Map in JWT and need to be converted to domain objects.
     *
     * @param claimsSet the JWT claims set
     * @return an Evidence containing the extracted evidence
     */
    private Evidence extractEvidence(JWTClaimsSet claimsSet) {
        Object evidenceClaim = claimsSet.getClaim("evidence");
        if (evidenceClaim instanceof Map) {
            try {
                return JwtClaimConverter.convertMapToEvidence(evidenceClaim);
            } catch (Exception e) {
                logger.warn("Failed to convert evidence claim to Evidence object", e);
            }
        }
        return null;
    }

    /**
     * Extracts the agent user binding proposal from a PAR-JWT.
     * Claims are stored as Map in JWT and need to be converted to domain objects.
     *
     * @param claimsSet the JWT claims set
     * @return an AgentUserBindingProposal containing the extracted agent user binding proposal
     */
    private AgentUserBindingProposal extractAgentUserBindingProposal(JWTClaimsSet claimsSet) {
        Object proposalClaim = claimsSet.getClaim("agent_user_binding_proposal");
        if (proposalClaim instanceof Map) {
            try {
                return JwtClaimConverter.convertMapToAgentUserBindingProposal(proposalClaim);
            } catch (Exception e) {
                logger.warn("Failed to convert agent_user_binding_proposal claim to AgentUserBindingProposal object", e);
            }
        }
        return null;
    }

    /**
     * Extracts the agent operation proposal from a PAR-JWT.
     *
     * @param claimsSet the JWT claims set
     * @return an AgentOperationProposal containing the extracted agent operation proposal
     */
    private String extractOperationProposal(JWTClaimsSet claimsSet) {
        Object proposalClaim = claimsSet.getClaim("agent_operation_proposal");
        if (proposalClaim instanceof String) {
            return (String) proposalClaim;
        }
        return null;
    }

    /**
     * Extracts the operation request context from a PAR-JWT.
     * Claims are stored as Map in JWT and need to be converted to domain objects.
     *
     * @param claimsSet the JWT claims set
     * @return an OperationRequestContext containing the extracted operation request context
     */
    @SuppressWarnings("unchecked")
    private OperationRequestContext extractContext(JWTClaimsSet claimsSet) {
        Object contextClaim = claimsSet.getClaim("context");
        logger.info("extractContext called - contextClaim: {}, type: {}", 
                   contextClaim != null ? contextClaim.toString() : "null",
                   contextClaim != null ? contextClaim.getClass().getName() : "null");
        
        if (contextClaim instanceof Map) {
            try {
                Map<String, Object> contextMap = (Map<String, Object>) contextClaim;
                logger.info("Context map keys: {}", contextMap.keySet());
                
                OperationRequestContext context = JwtClaimConverter.convertMapToOperationRequestContext(contextMap);
                logger.info("Extracted context - agent: {}", 
                           context != null && context.getAgent() != null ? context.getAgent().toString() : "null");
                return context;
            } catch (Exception e) {
                logger.error("Failed to convert context claim to OperationRequestContext object", e);
            }
        } else {
            logger.warn("Context claim is not a Map, type: {}", 
                       contextClaim != null ? contextClaim.getClass().getName() : "null");
        }
        return null;
    }

    /**
     * Validates that a string is not null or blank.
     *
     * @param value the string to validate
     * @param fieldName the name of the field
     * @return the validated string
     */
    private static String validateNotBlank(String value, String fieldName) {
        if (ValidationUtils.isNullOrEmpty(value)) {
            throw new IllegalArgumentException(fieldName + " cannot be null or blank");
        }
        return value.trim();
    }

    /**
     * Validates that a parameter is not null.
     *
     * @param value the parameter to validate
     * @param fieldName the name of the field
     * @return the validated parameter
     */
    private static <T> T validateParameter(T value, String fieldName) {
        return ValidationUtils.validateNotNull(value, fieldName);
    }

    /**
     * Represents the result of a single validation step.
     */
    private static class ValidationStepResult {
        private final boolean valid;
        private final String errorMessage;

        private ValidationStepResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        boolean isValid() {
            return valid;
        }

        String errorMessage() {
            return errorMessage;
        }

        static ValidationStepResult success() {
            return new ValidationStepResult(true, null);
        }

        static ValidationStepResult failure(String errorMessage) {
            return new ValidationStepResult(false, errorMessage);
        }
    }

    /**
     * Represents the result of PAR-JWT validation.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final ParJwtClaims claims;

        private ValidationResult(boolean valid, String errorMessage, ParJwtClaims claims) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.claims = claims;
        }

        public boolean isValid() {
            return valid;
        }

        public Optional<String> getErrorMessage() {
            return Optional.ofNullable(errorMessage);
        }

        public Optional<ParJwtClaims> getClaims() {
            return Optional.ofNullable(claims);
        }

        public static ValidationResult success(ParJwtClaims claims) {
            return new ValidationResult(true, null, claims);
        }

        public static ValidationResult failure(String errorMessage) {
            return new ValidationResult(false, errorMessage, null);
        }
    }
}
