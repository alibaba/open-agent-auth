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
package com.alibaba.openagentauth.core.protocol.wimse.wpt;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Generator for Workload Proof Tokens (WPT) following the WIMSE protocol.
 * Creates JWT-based proof tokens that prove request authenticity.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds-00</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/">draft-ietf-wimse-http-signature-01</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-mutual-tls/">draft-ietf-wimse-mutual-tls-00</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt-00.html">draft-ietf-wimse-wpt-00</a>
 */
public class WptGenerator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WptGenerator.class);

    /**
     * The media type of WPTs.
     */
    private static final String MEDIA_TYPE = "wpt+jwt";

    /**
     * Creates a new WPT generator.
     * <p>
     * According to WIMSE protocol, the WPT must be signed with the private key
     * corresponding to the public key in the WIT's cnf.jwk claim. This ensures
     * that only the entity that possesses the private key can generate valid WPTs.
     * </p>
     */
    public WptGenerator() {
        // No signing key needed - it will be extracted from WIT's cnf.jwk
    }

    /**
     * Generates a Workload Proof Token for an HTTP request.
     * <p>
     * This is the primary method that returns the structured WorkloadProofToken object.
     * Use this method when you need access to the token's structured representation.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @return a WorkloadProofToken object
     * @throws JOSEException if token generation fails
     */
    public WorkloadProofToken generateWpt(
            WorkloadIdentityToken wit, 
            JWK wptPrivateKey, 
            long expirationSeconds
    ) throws JOSEException {
        return generateWpt(wit, wptPrivateKey, expirationSeconds, null);
    }

    /**
     * Generates a Workload Proof Token for an HTTP request with optional token binding.
     * <p>
     * This method allows binding the WPT to another token (e.g., AOAT, Transaction Token, DPoP)
     * by including its hash in the oth (other tokens hashes) claim. This creates
     * a cryptographic binding between the WPT and the bound token, ensuring that the workload
     * presenting the WPT also possesses the corresponding token.
     * </p>
     * <p>
     * This is a flexible, extensible design that follows the Dependency Inversion Principle.
     * Any token implementing {@link OthBindableToken} can be bound to the WPT without requiring
     * modifications to this generator.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @param othBindableToken the optional token to bind to the WPT (e.g., AOAT)
     * @return a WorkloadProofToken object
     * @throws JOSEException if token generation fails
     */
    public WorkloadProofToken generateWpt(
            WorkloadIdentityToken wit, 
            JWK wptPrivateKey, 
            long expirationSeconds, 
            OthBindableToken othBindableToken
    ) throws JOSEException {

        // Validate arguments
        ValidationUtils.validateNotNull(wit, "WIT");
        ValidationUtils.validateNotNull(wptPrivateKey, "WPT private key");
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Expiration seconds must be positive");
        }

        // Calculate expiration time
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(expirationSeconds);

        // Use the JWT string to calculate hash (wth) as per WIMSE spec
        String witJwtString = wit.getJwtString();
        if (ValidationUtils.isNullOrEmpty(witJwtString)) {
            throw new JOSEException("WIT missing JWT string, cannot compute wth");
        }
        String wth = JwtHashUtil.computeWitHash(witJwtString);

        // Extract algorithm from WIT's cnf.jwk.alg
        String algorithm = extractAlgorithmFromWit(wit);

        // Build other token hashes (oth) if a bindable token is provided
        Map<String, String> otherTokenHashes = null;
        if (othBindableToken != null) {
            otherTokenHashes = buildOtherTokenHashes(othBindableToken);
            logger.debug("WPT will be bound to token type {} with hash: {}", 
                othBindableToken.getTokenType(), otherTokenHashes.get(othBindableToken.getTokenType()));
        }

        // Build structured WPT object first, then sign and serialize
        WorkloadProofToken wpt = buildWptObject(wth, expiration, algorithm, otherTokenHashes);

        // Sign and serialize the WPT using the private key corresponding to WIT's cnf.jwk
        wpt = signAndSerializeWpt(wpt, wptPrivateKey);

        logger.debug("Successfully generated and signed WPT: {}", wpt.getJwtString());
        return wpt;
    }

    /**
     * Generates a Workload Proof Token and returns it as a JWT string.
     * <p>
     * This is a convenience method that returns the JWT string representation
     * of the WPT. Use this method when you only need the serialized JWT string.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @return a signed JWT string representing the WPT
     * @throws JOSEException if token generation fails
     */
    public String generateWptAsString(WorkloadIdentityToken wit, JWK wptPrivateKey, long expirationSeconds) throws JOSEException {
        return generateWptAsString(wit, wptPrivateKey, expirationSeconds, null);
    }

    /**
     * Generates a Workload Proof Token and returns it as a JWT string with optional token binding.
     * <p>
     * This is a convenience method that returns the JWT string representation
     * of the WPT with optional token binding. Use this method when you only need the
     * serialized JWT string.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param wptPrivateKey the private key corresponding to WIT's cnf.jwk for signing WPT
     * @param expirationSeconds the WPT expiration time in seconds from now
     * @param othBindableToken the optional token to bind to the WPT (e.g., AOAT)
     * @return a signed JWT string representing the WPT
     * @throws JOSEException if token generation fails
     */
    public String generateWptAsString(WorkloadIdentityToken wit, JWK wptPrivateKey, long expirationSeconds, OthBindableToken othBindableToken) throws JOSEException {
        WorkloadProofToken wpt = generateWpt(wit, wptPrivateKey, expirationSeconds, othBindableToken);
        return wpt.getJwtString();
    }

    /**
     * Builds the other token hashes (oth) claim for the WPT.
     * <p>
     * This method creates a map of token type to token hash by using the
     * {@link OthBindableToken} interface. The token type is determined by
     * {@link OthBindableToken#getTokenType()}, and the hash is computed using
     * {@link JwtHashUtil#computeAoatHash(String)}.
     * </p>
     * <p>
     * This design is flexible and extensible - any token implementing
     * {@link OthBindableToken} can be bound to the WPT without requiring
     * modifications to this generator.
     * </p>
     *
     * @param othBindableToken the token to bind to the WPT
     * @return a map of token type to token hash
     * @throws JOSEException if hash computation fails
     */
    private Map<String, String> buildOtherTokenHashes(OthBindableToken othBindableToken) throws JOSEException {
        if (othBindableToken == null) {
            return null;
        }

        Map<String, String> otherTokenHashes = new HashMap<>();

        // Get the token's JWT string
        String tokenJwtString = othBindableToken.getJwtString();
        if (tokenJwtString == null || tokenJwtString.isEmpty()) {
            throw new JOSEException("Token missing JWT string, cannot compute hash");
        }

        // Compute the token hash using the standard hash computation method
        String tokenHash = JwtHashUtil.computeAoatHash(tokenJwtString);
        otherTokenHashes.put(othBindableToken.getTokenType(), tokenHash);

        logger.debug("Computed token hash for WPT oth claim: type={}, hash={}", 
            othBindableToken.getTokenType(), tokenHash);
        return otherTokenHashes;
    }

    /**
     * Extracts the algorithm from WIT's cnf.jwk.alg.
     * <p>
     * According to draft-ietf-wimse-wpt, the WPT header alg parameter MUST match the alg value
     * of the jwk in the cnf claim of the WIT.
     * </p>
     *
     * @param wit the WorkloadIdentityToken
     * @return the algorithm name
     * @throws JOSEException if algorithm cannot be extracted
     */
    private String extractAlgorithmFromWit(WorkloadIdentityToken wit) throws JOSEException {

        // Check if WIT has cnf.jwk
        if (wit == null || wit.getConfirmation() == null || wit.getConfirmation().getJwk() == null) {
            throw new JOSEException("WIT missing cnf.jwk claim");
        }

        // Extract algorithm from WIT's cnf.jwk.alg
        Jwk jwk = wit.getConfirmation().getJwk();
        String algorithm = jwk.getAlgorithm();

        // Check if algorithm is present
        if (ValidationUtils.isNullOrEmpty(algorithm)) {
            throw new JOSEException("WIT cnf.jwk missing alg field");
        }
        return algorithm;
    }

    /**
     * Builds a WorkloadProofToken object from the claims.
     *
     * @param wth        the Workload Identity Token hash
     * @param expiration the expiration time
     * @param algorithm  the algorithm name from WIT's cnf.jwk.alg
     * @param otherTokenHashes the optional other token hashes (oth claim)
     * @return the WorkloadProofToken object
     */
    private WorkloadProofToken buildWptObject(String wth, Instant expiration, String algorithm, Map<String, String> otherTokenHashes) {

        // Build WPT claims
        String jwtId = UUID.randomUUID().toString();
        WorkloadProofToken.Claims.ClaimsBuilder claimsBuilder = WorkloadProofToken.Claims.builder()
                .workloadTokenHash(wth)
                .expirationTime(Date.from(expiration))
                .jwtId(jwtId);

        // Add other token hashes if provided
        if (otherTokenHashes != null && !otherTokenHashes.isEmpty()) {
            claimsBuilder.otherTokenHashes(otherTokenHashes);
        }

        // Assemble WPT
        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type(MEDIA_TYPE)
                        .algorithm(algorithm)
                        .build())
                .claims(claimsBuilder.build())
                .build();
    }

    /**
     * Signs and serializes the WPT, returning a new WorkloadProofToken object with the signature.
     * <p>
     * This method uses the Serializer to serialize and sign the WPT directly,
     * following the natural JWT flow of "build → sign → serialize".
     * This approach eliminates the need for manual string concatenation and
     * intermediate serialization/parsing.
     * </p>
     *
     * @param wpt the WorkloadProofToken object to sign and serialize
     * @param signingKey the private key for signing WPT (must correspond to WIT's cnf.jwk)
     * @return a new WorkloadProofToken object with the signature and JWT string populated
     * @throws JOSEException if signing or serialization fails
     */
    private WorkloadProofToken signAndSerializeWpt(WorkloadProofToken wpt, JWK signingKey) throws JOSEException {
        try {
            // Create signer based on key type
            JWSSigner signer = createSigner(signingKey);

            // Use Serializer to serialize and sign the WPT
            String signedJwtString = WptSerializer.serialize(wpt, signer);

            // Extract signature from the signed JWT string
            String[] parts = signedJwtString.split("\\.");
            String signature = parts.length > 2 ? parts[2] : "";

            // Return new WPT object with signature and JWT string populated
            return WorkloadProofToken.builder()
                    .header(wpt.getHeader())
                    .claims(wpt.getClaims())
                    .signature(signature)
                    .jwtString(signedJwtString)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to sign WPT", e);
            throw new JOSEException("Failed to sign WPT", e);
        }
    }

    /**
     * Creates a JWSSigner based on the key type.
     *
     * @param signingKey the JWK key
     * @return the appropriate signer
     * @throws JOSEException if the key type is not supported
     */
    private JWSSigner createSigner(JWK signingKey) throws JOSEException {
        if (signingKey instanceof RSAKey) {
            return new RSASSASigner((RSAKey) signingKey);
        } else if (signingKey instanceof ECKey) {
            return new ECDSASigner((ECKey) signingKey);
        } else {
            throw new JOSEException("Unsupported key type: " + signingKey.getClass().getSimpleName());
        }
    }

}