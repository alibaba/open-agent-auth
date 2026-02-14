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

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.JwkConverter;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for Workload Identity Tokens (WIT) following the WIMSE protocol.
 * Creates JWT-SVID tokens that authenticate workloads and embed agent identity claims.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol-07.html">draft-ietf-wimse-s2s-protocol-07</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds.html">draft-ietf-wimse-workload-creds</a>
 */
public class WitGenerator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WitGenerator.class);

    /**
     * The JWK key used for signing WITs (can be RSA or EC).
     */
    private final JWK signingKey;

    /**
     * The trust domain for WIMSE ID generation.
     */
    private final TrustDomain trustDomain;

    /**
     * The JWS algorithm to use (e.g., RS256).
     */
    private final JWSAlgorithm algorithm;

    /**
     * Creates a new WIT generator.
     *
     * @param signingKey the JWK key used for signing WITs (can be RSA or EC)
     * @param trustDomain the trust domain for WIMSE ID generation
     * @param algorithm the JWS algorithm to use (e.g., RS256, ES256)
     */
    public WitGenerator(JWK signingKey, TrustDomain trustDomain, JWSAlgorithm algorithm) {

        // Validate arguments
        ValidationUtils.validateNotNull(signingKey, "Signing key");
        ValidationUtils.validateNotNull(trustDomain, "Trust domain");
        ValidationUtils.validateNotNull(algorithm, "Algorithm");

        // Set instance variables
        this.signingKey = signingKey;
        this.trustDomain = trustDomain;
        this.algorithm = algorithm;
    }

    /**
     * Generates a Workload Identity Token for the given subject.
     * According to WIMSE protocol, the subject (sub) claim should be a Workload Identifier.
     * <p>
     * This is the primary method that returns the structured WorkloadIdentityToken object.
     * Use this method when you need access to the token's structured representation.
     * </p>
     *
     * @param subject the subject (Workload Identifier) to embed in the WIT
     * @param wptPublicKey the public key to include in the WIT for WPT verification (JWK format)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a signed WorkloadIdentityToken object
     * @throws JOSEException if token generation fails
     */
    public WorkloadIdentityToken generateWit(String subject, String wptPublicKey, long expirationSeconds) throws JOSEException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(subject)) {
            throw new IllegalArgumentException("Subject cannot be null or empty");
        }
        if (ValidationUtils.isNullOrEmpty(wptPublicKey)) {
            throw new IllegalArgumentException("WPT public key cannot be null or empty");
        }
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Expiration seconds must be positive");
        }

        logger.debug("Generating WIT for subject: {}", subject);

        // Calculate expiration time
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(expirationSeconds);

        // Parse the WPT public key as JWK and infer algorithm if needed
        JWK wptJwk = parseAndInferJwkAlgorithm(wptPublicKey);

        // Build structured WIT object
        WorkloadIdentityToken wit = buildWitObject(subject, expiration, wptJwk);

        // Sign and serialize the WIT
        wit = signAndSerializeWit(wit);
        logger.debug("Successfully generated WIT with subject: {}", subject);

        return wit;
    }

    /**
     * Generates a Workload Identity Token and returns it as a JWT string.
     * <p>
     * This is a convenience method that returns the JWT string representation
     * of the WIT. Use this method when you only need the serialized JWT string.
     * </p>
     *
     * @param subject the subject (Workload Identifier) to embed in the WIT
     * @param wptPublicKey the public key to include in the WIT for WPT verification (JWK format)
     * @param expirationSeconds the token expiration time in seconds from now
     * @return a signed JWT string representing the WIT
     * @throws JOSEException if token generation fails
     */
    public String generateWitAsString(String subject, String wptPublicKey, long expirationSeconds) throws JOSEException {
        WorkloadIdentityToken wit = generateWit(subject, wptPublicKey, expirationSeconds);
        return wit.getJwtString();
    }

    /**
     * Builds a WorkloadIdentityToken object from the claims.
     *
     * @param subject the subject (Workload Identifier)
     * @param expiration the expiration time
     * @param wptJwk the WPT public key as JWK
     * @return the WorkloadIdentityToken object
     */
    private WorkloadIdentityToken buildWitObject(String subject, Instant expiration, JWK wptJwk) {

        // Convert WPT JWK to our Jwk model
        Jwk jwkModel = JwkConverter.convertMapToJwk(wptJwk.toJSONObject());

        // Build confirmation claim
        WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(jwkModel)
                .build();

        // Build WIT claims
        String jwtId = UUID.randomUUID().toString();
        WorkloadIdentityToken.Claims.ClaimsBuilder claimsBuilder = WorkloadIdentityToken.Claims.builder()
                .issuer(trustDomain.getDomainId())
                .subject(subject)
                .expirationTime(Date.from(expiration))
                .jwtId(jwtId)
                .confirmation(confirmation);

        // Build WIT header
        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm(algorithm.getName())
                .build();

        // Assemble WIT
        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claimsBuilder.build())
                .build();
    }

    /**
     * Signs and serializes the WIT, returning a new WorkloadIdentityToken object with the signature.
     * <p>
     * This method uses the Serializer to serialize and sign the WIT directly,
     * following the natural JWT flow of "build → sign → serialize".
     * This approach eliminates the need for manual string concatenation and
     * intermediate serialization/parsing.
     * </p>
     *
     * @param wit the WorkloadIdentityToken object to sign and serialize
     * @return a new WorkloadIdentityToken object with the signature and JWT string populated
     * @throws JOSEException if signing or serialization fails
     */
    private WorkloadIdentityToken signAndSerializeWit(WorkloadIdentityToken wit) throws JOSEException {
        try {
            // Create signer based on key type
            JWSSigner signer = createSigner(signingKey);
            logger.debug("Created WIT signer: keyType={}, keyId={}, algorithm={}", 
                        signingKey.getKeyType(), signingKey.getKeyID(), signingKey.getAlgorithm());

            // Get key ID from signing key to include in JWT header
            String keyId = signingKey.getKeyID();

            // Use Serializer to serialize and sign the WIT
            String signedJwtString = WitSerializer.serialize(wit, signer, keyId);
            logger.debug("Signed WIT successfully: keyId={}, jwtLength={}", keyId, signedJwtString.length());

            // Extract signature from the signed JWT string
            String[] parts = signedJwtString.split("\\.");
            String signature = parts.length > 2 ? parts[2] : "";

            // Return new WIT object with signature and JWT string populated
            return WorkloadIdentityToken.builder()
                    .header(wit.getHeader())
                    .claims(wit.getClaims())
                    .signature(signature)
                    .jwtString(signedJwtString)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to sign WIT: signingKeyType={}, signingKeyId={}", 
                        signingKey.getKeyType(), signingKey.getKeyID(), e);
            throw new JOSEException("Failed to sign WIT", e);
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



    /**
     * Parses the WPT public key as JWK and infers the algorithm if not specified.
     * <p>
     * This method handles the parsing of the JWK string and ensures the algorithm
     * field is populated. If the JWK doesn't have an algorithm, it infers it from
     * the key type and curve (for EC keys).
     * </p>
     *
     * @param wptPublicKey the WPT public key in JWK format
     * @return the parsed JWK with algorithm inferred if necessary
     * @throws IllegalArgumentException if the JWK format is invalid
     */
    private JWK parseAndInferJwkAlgorithm(String wptPublicKey) {
        try {
            JWK jwk = JWK.parse(wptPublicKey);

            // If algorithm is already specified, return as-is
            if (jwk.getAlgorithm() != null) {
                return jwk;
            }

            // Infer algorithm from key type
            return inferAlgorithmFromKeyType(jwk);

        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid WPT public key format", e);
        }
    }

    /**
     * Infers the JWS algorithm from the JWK key type and curve.
     * <p>
     * For EC keys, the algorithm is inferred from the curve:
     * - P-256 → ES256
     * - P-384 → ES384
     * - P-521 → ES512
     * For RSA keys, defaults to RS256.
     * </p>
     *
     * @param jwk the JWK without algorithm specified
     * @return the JWK with algorithm inferred
     */
    private JWK inferAlgorithmFromKeyType(JWK jwk) {
        if (jwk instanceof ECKey ecKey) {
            return inferAlgorithmFromEcCurve(ecKey);
        } else if (jwk instanceof RSAKey rsaKey) {
            // Default to RS256 for RSA keys
            return new RSAKey.Builder(rsaKey).algorithm(JWSAlgorithm.RS256).build();
        }
        // Return as-is for unsupported key types
        return jwk;
    }

    /**
     * Infers the JWS algorithm from the EC key's curve.
     *
     * @param ecKey the EC key
     * @return the EC key with algorithm inferred
     */
    private JWK inferAlgorithmFromEcCurve(ECKey ecKey) {
        String curve = ecKey.getCurve().getName();
        return switch (curve) {
            case "P-256" -> new ECKey.Builder(ecKey).algorithm(JWSAlgorithm.ES256).build();
            case "P-384" -> new ECKey.Builder(ecKey).algorithm(JWSAlgorithm.ES384).build();
            case "P-521" -> new ECKey.Builder(ecKey).algorithm(JWSAlgorithm.ES512).build();
            default -> ecKey;
        };
    }

    /**
     * Gets the trust domain for WIT generation.
     *
     * @return the trust domain
     */
    public TrustDomain getTrustDomain() {
        return trustDomain;
    }
}