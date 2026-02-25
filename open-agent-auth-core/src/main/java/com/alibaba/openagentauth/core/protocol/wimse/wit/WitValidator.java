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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.verify.SignatureVerificationUtils;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Validator for Workload Identity Tokens (WIT) following the WIMSE protocol.
 * Verifies the signature, expiration, and structure of WITs.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds-00</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/">draft-ietf-wimse-http-signature-01</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-mutual-tls/">draft-ietf-wimse-mutual-tls-00</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt-00</a>
 */
public class WitValidator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WitValidator.class);

    /**
     * The expected trust domain for validation.
     */
    private final TrustDomain expectedTrustDomain;

    /**
     * The key manager used for verifying WIT signatures.
     * Supports dynamic key rotation through KeyManager abstraction.
     */
    private final KeyManager keyManager;

    /**
     * The key ID used for signature verification.
     */
    private final String verificationKeyId;

    /**
     * The WIT parser.
     */
    private final WitParser witParser;

    /**
     * Creates a new WIT validator with a key manager, verification key ID, and trust domain.
     * <p>
     * This constructor supports dynamic key rotation through the KeyManager abstraction.
     * </p>
     *
     * @param keyManager the key manager for signature verification
     * @param verificationKeyId the key ID used for signature verification
     * @param expectedTrustDomain the expected trust domain for validation
     * @throws IllegalArgumentException if keyManager or expectedTrustDomain is null, or verificationKeyId is empty
     */
    public WitValidator(KeyManager keyManager, String verificationKeyId, TrustDomain expectedTrustDomain) {
        this.keyManager = ValidationUtils.validateNotNull(keyManager, "Key manager");
        this.verificationKeyId = ValidationUtils.validateNotEmpty(verificationKeyId, "Verification key ID");
        this.expectedTrustDomain = ValidationUtils.validateNotNull(expectedTrustDomain, "Expected trust domain");
        this.witParser = new WitParser();

        logger.info("WitValidator initialized with KeyManager: {}, keyId: {}, domain: {}",
                keyManager.getClass().getSimpleName(), verificationKeyId, expectedTrustDomain.getDomainId());
    }

    /**
     * Validates a Workload Identity Token.
     *
     * @param witJwt the JWT string representing the WIT
     * @return a TokenValidationResult containing the validation outcome and parsed token
     * @throws ParseException if the JWT cannot be parsed
     */
    public TokenValidationResult<WorkloadIdentityToken> validate(String witJwt) throws ParseException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(witJwt)) {
            return TokenValidationResult.failure("WIT cannot be null or empty");
        }

        SignedJWT signedJwt = SignedJWT.parse(witJwt);

        // 1. Verify the signature of the WIT
        if (!verifySignature(signedJwt)) {
            return TokenValidationResult.failure("Invalid WIT signature");
        }

        // 2. Verify that the WIT has not expired
        if (!verifyExpiration(signedJwt)) {
            return TokenValidationResult.failure("WIT has expired");
        }

        // 3. Verify that the WIT issuer matches the expected trust domain
        if (!verifyTrustDomain(signedJwt)) {
            return TokenValidationResult.failure("Invalid trust domain");
        }

        // 4. Verify that all required claims are present in the WIT
        if (!verifyRequiredClaims(signedJwt)) {
            return TokenValidationResult.failure("Missing required claims");
        }

        // 5. Verify that the cnf claim contains a valid JWK
        // cnf is REQUIRED in this implementation, so missing cnf is a required claims error
        CnfValidationResult cnfResult = verifyCnfClaim(signedJwt);
        if (!cnfResult.valid()) {
            if (cnfResult.missing()) {
                return TokenValidationResult.failure("Missing required claims");
            } else {
                return TokenValidationResult.failure("Invalid cnf claim");
            }
        }

        // Parse the WIT and return the parsed token
        WorkloadIdentityToken wit = witParser.parse(signedJwt);
        logger.debug("Successfully validated WIT with subject: {}", wit.getSubject());

        return TokenValidationResult.success(wit);
    }

    /**
     * Verifies the signature of the WIT.
     *
     * @param signedJwt the signed JWT
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifySignature(SignedJWT signedJwt) {
        return SignatureVerificationUtils.verifySignature(signedJwt, keyManager, verificationKeyId);
    }

    /**
     * Verifies that the WIT has not expired.
     *
     * @param signedJwt the signed JWT
     * @return true if the token is not expired, false otherwise
     */
    private boolean verifyExpiration(SignedJWT signedJwt) {
        try {
            // Get WIT expiration time
            Date expirationTime = signedJwt.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null) {
                logger.warn("WIT missing expiration time");
                return false;
            }

            // Verify that the token is not expired
            boolean isValid = expirationTime.after(Date.from(Instant.now()));
            if (!isValid) {
                logger.warn("WIT has expired at: {}", expirationTime);
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing WIT expiration time", e);
            return false;
        }
    }

    /**
     * Verifies that the WIT issuer matches the expected trust domain.
     *
     * @param signedJwt the signed JWT
     * @return true if the trust domain is valid, false otherwise
     */
    private boolean verifyTrustDomain(SignedJWT signedJwt) {
        try {
            // Get WIT issuer
            String issuer = signedJwt.getJWTClaimsSet().getIssuer();
            boolean isValid = expectedTrustDomain.getDomainId().equals(issuer);

            // Log if trust domain is invalid
            if (!isValid) {
                logger.warn("WIT issuer '{}' does not match expected trust domain '{}'",
                           issuer, expectedTrustDomain.getDomainId());
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing WIT issuer", e);
            return false;
        }
    }

    /**
     * Verifies that all required claims are present in the WIT.
     * <p>
     * According to draft-ietf-wimse-workload-creds, the required claims are:
     * - sub (Subject): Workload Identifier (REQUIRED)
     * - exp (Expiration Time): Token expiration time (REQUIRED)
     * - cnf (Confirmation): Contains the public key for WPT/HTTP-Sig verification (REQUIRED)
     * </p>
     *
     * @param signedJwt the signed JWT
     * @return true if all required claims are present, false otherwise
     */
    private boolean verifyRequiredClaims(SignedJWT signedJwt) {
        try {
            // Get WIT claims
            var claims = signedJwt.getJWTClaimsSet().getClaims();

            // Verify subject (sub) claim - REQUIRED
            if (!claims.containsKey("sub")) {
                logger.warn("WIT missing required claim: sub (subject)");
                return false;
            }

            // Verify expiration (exp) claim - REQUIRED
            if (!claims.containsKey("exp")) {
                logger.warn("WIT missing required claim: exp (expiration time)");
                return false;
            }

            // cnf (confirmation) claim is REQUIRED for application-level authentication
            // as per draft-ietf-wimse-s2s-protocol-04 and later versions
            if (!claims.containsKey("cnf")) {
                logger.warn("WIT missing required claim: cnf (confirmation)");
                return false;
            }

            return true;

        } catch (ParseException e) {
            logger.error("Error parsing WIT claims", e);
            return false;
        }
    }

    /**
     * Verifies the cnf claim contains a valid JWK.
     * <p>
     * The cnf claim is REQUIRED in this implementation for WPT verification.
     * According to draft-ietf-wimse-workload-creds, cnf is OPTIONAL, but this
     * implementation requires it for proof-of-possession verification scenarios.
     * </p>
     *
     * @param signedJwt the signed JWT
     * @return a CnfValidationResult indicating whether the cnf claim is valid, missing, or invalid
     */
    private CnfValidationResult verifyCnfClaim(SignedJWT signedJwt) {
        try {
            // Get WIT cnf claim
            Map<String, Object> cnfClaim = signedJwt.getJWTClaimsSet().getJSONObjectClaim("cnf");

            // cnf claim is REQUIRED in this implementation
            if (cnfClaim == null) {
                logger.warn("WIT cnf claim is not present (required)");
                return new CnfValidationResult(false, true);
            }

            // Verify it contains a valid jwk
            if (!cnfClaim.containsKey("jwk")) {
                logger.warn("WIT cnf claim missing jwk");
                return new CnfValidationResult(false, false);
            }

            // Validate that the jwk is a valid JWK with safe type conversion
            Object jwkObj = cnfClaim.get("jwk");
            if (!(jwkObj instanceof Map)) {
                logger.warn("WIT cnf.jwk is not a Map");
                return new CnfValidationResult(false, false);
            }

            // Validate that the jwk is a valid JWK
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) jwkObj;
            try {
                JWK.parse(jwkMap);
                logger.debug("WIT cnf.jwk is valid");
                return new CnfValidationResult(true, false);
            } catch (ParseException e) {
                logger.warn("WIT cnf.jwk is invalid: {}", e.getMessage());
                return new CnfValidationResult(false, false);
            }
        } catch (ParseException e) {
            logger.error("Error parsing WIT cnf claim", e);
            return new CnfValidationResult(false, false);
        }
    }

    /**
     * Result of cnf claim validation.
     */
    private record CnfValidationResult(boolean valid, boolean missing) { }

}