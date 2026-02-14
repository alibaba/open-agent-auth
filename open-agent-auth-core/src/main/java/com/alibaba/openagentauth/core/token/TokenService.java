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
package com.alibaba.openagentauth.core.token;

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitGenerator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptGenerator;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unified service for managing Workload Identity Tokens (WIT) and Workload Proof Tokens (WPT).
 * <p>
 * This service provides a high-level API for token generation according to the
 * WIMSE protocol. It encapsulates the complexity of key management and token generation,
 * providing a simple and consistent interface for token operations.
 * </p>
 * <p>
 * The service manages:
 * </p>
 * <ul>
 *   <li><b>WIT Generation</b>: Creates signed Workload Identity Tokens for agent authentication</li>
 *   <li><b>WPT Generation</b>: Creates signed Workload Proof Tokens for request authentication</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol-07.html">draft-ietf-wimse-s2s-protocol-07</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds.html">draft-ietf-wimse-workload-creds</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt-00.html">draft-ietf-wimse-wpt-00</a>
 */
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    /**
     * Generator for Workload Identity Tokens.
     */
    private final WitGenerator witGenerator;

    /**
     * Generator for Workload Proof Tokens.
     */
    private final WptGenerator wptGenerator;

    /**
     * Creates a new TokenService with JWK keys.
     * <p>
     * Note: WPT signing key is not required here because WPT must be signed with
     * the private key corresponding to the public key in the WIT's cnf.jwk claim.
     * This ensures cryptographic binding between WIT and WPT per WIMSE protocol.
     * </p>
     *
     * @param witSigningKey the JWK key used for signing WITs (can be RSA or EC)
     * @param trustDomain the trust domain for WIMSE ID generation
     * @param algorithm the JWS algorithm to use for WITs (e.g., RS256, ES256)
     */
    public TokenService(JWK witSigningKey, TrustDomain trustDomain, JWSAlgorithm algorithm) {
        this.witGenerator = new WitGenerator(
            ValidationUtils.validateNotNull(witSigningKey, "WIT signing key"),
            ValidationUtils.validateNotNull(trustDomain, "Trust domain"),
            ValidationUtils.validateNotNull(algorithm, "Algorithm")
        );
        this.wptGenerator = new WptGenerator();

        logger.info("TokenService initialized with trust domain: {}", trustDomain.getDomainId());
    }

    /**
     * Generates a Workload Identity Token for the given subject.
     *
     * @param subject the subject (Workload Identifier) to embed in the WIT
     * @param wptPublicKey the public key to include in the WIT for WPT verification (JWK format)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a signed WorkloadIdentityToken object
     * @throws JOSEException if token generation fails
     */
    public WorkloadIdentityToken generateWit(String subject, String wptPublicKey,
                                            long expirationSeconds) throws JOSEException {
        logger.debug("Generating WIT for subject: {}", subject);
        return witGenerator.generateWit(subject, wptPublicKey, expirationSeconds);
    }

    /**
     * Generates a Workload Identity Token and returns it as a JWT string.
     *
     * @param subject the subject (Workload Identifier) to embed in the WIT
     * @param wptPublicKey the public key to include in the WIT for WPT verification (JWK format)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a signed JWT string representing the WIT
     * @throws JOSEException if token generation fails
     */
    public String generateWitAsString(String subject, String wptPublicKey,
                                      long expirationSeconds) throws JOSEException {
        logger.debug("Generating WIT as string for subject: {}", subject);
        return witGenerator.generateWitAsString(subject, wptPublicKey, expirationSeconds);
    }

    /**
     * Generates a Workload Proof Token for an HTTP request.
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @return a WorkloadProofToken object
     * @throws JOSEException if token generation fails
     */
    public WorkloadProofToken generateWpt(WorkloadIdentityToken wit, JWK wptPrivateKey, long expirationSeconds)
            throws JOSEException {
        logger.debug("Generating WPT");
        return wptGenerator.generateWpt(wit, wptPrivateKey, expirationSeconds);
    }

    /**
     * Generates a Workload Proof Token and returns it as a JWT string.
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @return a signed JWT string representing the WPT
     * @throws JOSEException if token generation fails
     */
    public String generateWptAsString(WorkloadIdentityToken wit, JWK wptPrivateKey, long expirationSeconds) throws JOSEException {
        logger.debug("Generating WPT as string");
        return wptGenerator.generateWptAsString(wit, wptPrivateKey, expirationSeconds);
    }

    /**
     * Generates a Workload Proof Token and returns it as a JWT string with optional AOAT binding.
     * <p>
     * This method allows binding the WPT to an Agent Operation Authorization Token (AOAT)
     * by including the AOAT hash in the oth (other tokens hashes) claim. This creates
     * a cryptographic binding between the WPT and the AOAT, ensuring that the workload
     * presenting the WPT also possesses the corresponding AOAT authorization.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @param aoatToken the optional Agent Operation Authorization Token to bind to the WPT
     * @return a signed JWT string representing the WPT
     * @throws JOSEException if token generation fails
     */
    public String generateWptAsString(
            WorkloadIdentityToken wit,
            JWK wptPrivateKey,
            long expirationSeconds,
            AgentOperationAuthToken aoatToken
    ) throws JOSEException {
        logger.debug("Generating WPT as string with optional AOAT binding");
        if (aoatToken != null) {
            logger.debug("WPT will be bound to AOAT: {}", aoatToken.getJwtString());
        }
        return wptGenerator.generateWptAsString(wit, wptPrivateKey, expirationSeconds, aoatToken);
    }

    /**
     * Validates a Workload Proof Token.
     *
     * @param wpt the WorkloadProofToken to validate
     * @param wit the Workload Identity Token to verify against
     * @return a TokenValidationResult containing the validation outcome and parsed token
     */
    public TokenValidationResult<WorkloadProofToken> validateWpt(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        logger.debug("Validating WPT, WIT: {}, WPT: {}", wit, wpt);
        // Create validator on-demand with WIT's cnf.jwk
        WptValidator validator = new WptValidator();
        return validator.validate(wpt, wit);
    }

    /**
     * Gets the WIT generator.
     *
     * @return the WitGenerator instance
     */
    public WitGenerator getWitGenerator() {
        return witGenerator;
    }

}