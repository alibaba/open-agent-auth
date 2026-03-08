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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.authenticator;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitExtractor;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitFormatValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.jwk.JwkUtils;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * WIMSE-based DCR authenticator.
 * <p>
 * This implementation authenticates DCR requests using the WIMSE (Workload Identity
 * Management for Service Environments) protocol. It validates Workload Identity Tokens
 * (WIT) and extracts workload identity claims for client authentication.
 * </p>
 * <p>
 * <b>WIMSE Authentication Flow:</b></p>
 * <ol>
 *   <li>Extract WIT from request (via {@code wit} parameter in {@code additionalParameters})</li>
 *   <li>Validate WIT format (JWT structure)</li>
 *   <li>Verify WIT signature against WIMSE trust anchor</li>
 *   <li>Validate WIT claims (iss, sub, aud, exp, nbf)</li>
 *   <li>Extract subject identifier from validated WIT</li>
 * </ol>
 * <p>
 * <b>Security Considerations:</b></p>
 * <ul>
 *   <li>WIT MUST be signed by a trusted WIMSE trust anchor</li>
 *   <li>WIT MUST be valid (not expired, not used before nbf)</li>
 *   <li>WIT audience MUST include the Authorization Server</li>
 *   <li>Subject identifier MUST be extracted from validated claims</li>
 * </ul>
 *
 * @see OAuth2DcrAuthenticator
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">
 *     draft-ietf-wimse-workload-creds - Workload Identity Credentials</a>
 * @since 1.0
 */
public class WimseOAuth2DcrAuthenticator implements OAuth2DcrAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(WimseOAuth2DcrAuthenticator.class);

    /**
     * The WIT validator for signature and claims verification.
     */
    private final WitValidator witValidator;

    /**
     * Creates a new WIMSE DCR authenticator.
     *
     * @param keyManager the key manager for resolving verification keys (supports key rotation)
     * @param verificationKeyId the key ID used to resolve the WIT verification key
     * @param trustDomain the expected trust domain for validation
     * @throws IllegalArgumentException if any parameter is null or verificationKeyId is empty
     */
    public WimseOAuth2DcrAuthenticator(KeyManager keyManager, String verificationKeyId, TrustDomain trustDomain) {
        this.witValidator = new WitValidator(
                ValidationUtils.validateNotNull(keyManager, "Key manager"),
                ValidationUtils.validateNotEmpty(verificationKeyId, "Verification key ID"),
                ValidationUtils.validateNotNull(trustDomain, "Trust domain")
        );
        logger.info("WimseDcrAuthenticator initialized with trust domain: {}", trustDomain.getDomainId());
    }

    @Override
    public String authenticate(DcrRequest request) throws DcrException {

        // Validate request
        ValidationUtils.validateNotNull(request, "DCR request");
        logger.debug("Authenticating DCR request using WIMSE protocol");

        // Extract WIT from additional parameters (WitExtractor now prioritizes software_statement)
        String wit = WitExtractor.extractFromDcrRequest(request);
        if (ValidationUtils.isNullOrEmpty(wit)) {
            throw DcrException.invalidClientMetadata("WIT is required for WIMSE authentication");
        }

        // Validate WIT format
        WitFormatValidator.validateFormat(wit);

        // Validate WIT signature and claims
        String subject = validateWitClaims(wit);

        // Verify cnf.jwk consistency with jwks in DCR request
        verifyCnfJwkConsistency(wit, request);

        logger.info("WIMSE authentication successful for subject: {}", subject);
        return subject;
    }

    @Override
    public boolean canAuthenticate(DcrRequest request) {
        return WitExtractor.hasWitInDcrRequest(request);
    }

    @Override
    public String getAuthenticationMethod() {
        return "software_statement";
    }

    /**
     * Returns {@code true} because WIMSE authentication provides a stable workload identity
     * (the WIT subject) that should be used as the OAuth {@code client_id}.
     * <p>
     * This ensures identity consistency between the WIMSE workload identity layer
     * and the OAuth client layer, as recommended by the WIMSE specification.
     * </p>
     *
     * @return {@code true} always
     */
    @Override
    public boolean providesClientIdentity() {
        return true;
    }

    /**
     * Validates the claims of a Workload Identity Token.
     * <p>
     * This method validates the WIT signature and claims according to WIMSE protocol.
     * It uses the underlying {@link WitValidator} to perform:
     * <ol>
     *   <li>Verify WIT signature against WIMSE trust anchor</li>
     *   <li>Verify WIT has not expired</li>
     *   <li>Verify WIT issuer matches expected trust domain</li>
     *   <li>Verify all required claims are present (sub, exp)</li>
     *   <li>Verify cnf claim contains a valid JWK</li>
     * </ol>
     * </p>
     *
     * @param wit the Workload Identity Token
     * @return the subject identifier from the validated WIT
     * @throws DcrException if validation fails
     */
    private String validateWitClaims(String wit) throws DcrException {
        try {
            // Validate WIT using WitValidator
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(wit);

            // Check if validation failed
            if (!result.isValid()) {
                String errorMessage = result.getErrorMessage();
                logger.warn("WIT validation failed: {}", errorMessage);
                throw DcrException.invalidClientMetadata("WIT validation failed: " + errorMessage);
            }

            // Extract subject from validated WIT
            WorkloadIdentityToken validatedWit = result.getToken();
            String subject = validatedWit.getSubject();

            logger.debug("WIT claims validated successfully for subject: {}", subject);
            return subject;

        } catch (ParseException e) {
            logger.error("Failed to parse WIT during validation", e);
            throw DcrException.invalidClientMetadata("Failed to parse WIT: " + e.getMessage());
        }
    }

    /**
     * Verifies that the cnf.jwk in the WIT matches the jwks in the DCR request.
     * <p>
     * This ensures that the public key in the software statement (WIT) matches
     * the public key the client is registering for private_key_jwt authentication.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param request the DCR request containing jwks
     * @throws DcrException if validation fails
     */
    private void verifyCnfJwkConsistency(String wit, DcrRequest request) throws DcrException {
        try {
            // Skip validation if jwks is not provided (backward compatibility)
            Map<String, Object> jwks = request.getJwks();
            if (jwks == null) {
                logger.debug("Skipping cnf.jwk consistency check - jwks not provided in DCR request");
                return;
            }

            // Parse WIT to get cnf.jwk
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(wit);
            if (!result.isValid()) {
                throw DcrException.invalidClientMetadata("WIT validation failed: " + result.getErrorMessage());
            }

            WorkloadIdentityToken validatedWit = result.getToken();
            Jwk cnfJwk = validatedWit.getJwk();
            
            if (cnfJwk == null) {
                throw DcrException.invalidClientMetadata("WIT cnf claim does not contain jwk");
            }

            // Get the first key from jwks
            List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
            if (keys == null || keys.isEmpty()) {
                throw DcrException.invalidClientMetadata("jwks in DCR request must contain at least one key");
            }

            Map<String, Object> firstKey = keys.get(0);
            JWK jwksKey = JWK.parse(firstKey);

            // Compare the cryptographic key material (kty, crv, x, y for EC; kty, n, e for RSA).
            // We intentionally compare only the core public key parameters, not metadata
            // fields like kid, alg, or use, because the WIT cnf.jwk and the DCR jwks may
            // carry different metadata while representing the same underlying public key.
            if (!JwkUtils.publicKeysMatch(cnfJwk, jwksKey)) {
                logger.error("cnf.jwk in WIT does not match jwks in DCR request");
                throw DcrException.invalidClientMetadata(
                    "cnf.jwk in software statement does not match jwks in DCR request");
            }

            logger.debug("cnf.jwk consistency check passed - WIT cnf.jwk matches DCR request jwks");

        } catch (ParseException e) {
            logger.error("Failed to parse WIT during cnf.jwk consistency check", e);
            throw DcrException.invalidClientMetadata("Failed to parse WIT: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Failed to verify cnf.jwk consistency", e);
            throw DcrException.invalidClientMetadata("Failed to verify cnf.jwk consistency: " + e.getMessage());
        }
    }

}