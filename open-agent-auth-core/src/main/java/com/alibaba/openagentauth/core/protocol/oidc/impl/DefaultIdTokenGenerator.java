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
package com.alibaba.openagentauth.core.protocol.oidc.impl;

import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;

/**
 * Default implementation of {@link IdTokenGenerator}.
 * <p>
 * This implementation generates ID Tokens according to the OpenID Connect Core 1.0
 * specification. It supports signing with various algorithms and includes all
 * required claims.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Supports standard JWT signing algorithms</li>
 *   <li>Automatically sets iat and exp claims</li>
 *   <li>Validates required claims before token generation</li>
 *   <li>Supports custom token lifetimes</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
 * @since 1.0
 */
public class DefaultIdTokenGenerator implements IdTokenGenerator {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultIdTokenGenerator.class);

    /**
     * Default token lifetime in seconds (1 hour).
     */
    private static final long DEFAULT_LIFETIME_SECONDS = 3600;

    /**
     * The issuer identifier.
     */
    private final String issuer;

    /**
     * The signing algorithm.
     */
    private final String algorithm;

    /**
     * The signing key.
     */
    private final Object signingKey;

    /**
     * Creates a new DefaultIdTokenGenerator.
     *
     * @param issuer the issuer identifier
     * @param algorithm the signing algorithm (e.g., "RS256", "ES256")
     * @param signingKey the signing key
     */
    public DefaultIdTokenGenerator(String issuer, String algorithm, Object signingKey) {

        // Validate parameters
        this.issuer = ValidationUtils.validateNotNull(issuer, "Issuer");
        this.algorithm = ValidationUtils.validateNotNull(algorithm, "Algorithm");
        this.signingKey = ValidationUtils.validateNotNull(signingKey, "Signing key");
        
        logger.info("DefaultIdTokenGenerator initialized with issuer: {}, algorithm: {}", issuer, algorithm);
    }

    /**
     * Generates an ID token with the specified claims and default lifetime.
     *
     * @param claims the ID token claims
     * @return the generated ID token
     */
    @Override
    public IdToken generate(IdTokenClaims claims) {
        return generate(claims, DEFAULT_LIFETIME_SECONDS);
    }

    /**
     * Generates an ID token with the specified claims and lifetime.
     *
     * @param claims the ID token claims
     * @param lifetimeInSeconds the token lifetime in seconds
     * @return the generated ID token
     */
    @Override
    public IdToken generate(IdTokenClaims claims, long lifetimeInSeconds) {

        // Validate parameters
        ValidationUtils.validateNotNull(claims, "Claims");
        if (lifetimeInSeconds <= 0) {
            throw new IllegalArgumentException("Lifetime must be positive");
        }

        logger.debug("Generating ID token for subject: {}, lifetime: {} seconds", claims.getSub(), lifetimeInSeconds);

        // Build the final claims with automatic timestamps
        IdTokenClaims finalClaims = buildIdTokenClaims(claims, lifetimeInSeconds);

        // Generate the JWT token
        String tokenValue = generateJwtToken(finalClaims);

        logger.info("ID token generated successfully for subject: {}", claims.getSub());
        return IdToken.builder()
                .tokenValue(tokenValue)
                .claims(finalClaims)
                .build();
    }

    /**
     * Builds the final ID token claims with automatic timestamps.
     *
     * @param claims the input claims
     * @param lifetimeInSeconds the token lifetime in seconds
     * @return the final claims with timestamps set
     */
    private IdTokenClaims buildIdTokenClaims(IdTokenClaims claims, long lifetimeInSeconds) {

        // Build final claims
        IdTokenClaims.Builder claimsBuilder = IdTokenClaims.builder()
                .iss(claims.getIss() != null ? claims.getIss() : issuer)
                .sub(claims.getSub())
                .aud(claims.getAud())
                .iat(claims.getIat() != null ? claims.getIat() : Instant.now().getEpochSecond())
                .exp(claims.getExp() != null ? claims.getExp() : Instant.now().plusSeconds(lifetimeInSeconds).getEpochSecond());

        // Copy optional claims
        if (claims.getAuthTime() != null) {
            claimsBuilder.authTime(claims.getAuthTime());
        }
        if (claims.getNonce() != null) {
            claimsBuilder.nonce(claims.getNonce());
        }
        if (claims.getAcr() != null) {
            claimsBuilder.acr(claims.getAcr());
        }
        if (claims.getAmr() != null) {
            claimsBuilder.amr(claims.getAmr());
        }
        if (claims.getAzp() != null) {
            claimsBuilder.azp(claims.getAzp());
        }
        if (claims.getAtHash() != null) {
            claimsBuilder.atHash(claims.getAtHash());
        }
        if (claims.getAdditionalClaims() != null) {
            claimsBuilder.additionalClaims(claims.getAdditionalClaims());
        }

        return claimsBuilder.build();
    }

    /**
     * Generates a JWT token from the specified claims.
     * <p>
     * This method creates a signed JWT containing the provided claims.
     * The actual signing implementation depends on the configured algorithm.
     * </p>
     *
     * @param claims the claims to include in the token
     * @return the signed JWT string
     * @throws IdTokenException if token generation fails
     */
    private String generateJwtToken(IdTokenClaims claims) {
        try {
            // Parse the signing algorithm
            JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithm);

            // Create JWS header with key ID if available
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(jwsAlgorithm);
            
            // Extract key ID from signing key if it's a JWK (RSAKey or ECKey)
            String keyId = extractKeyId();
            if (!ValidationUtils.isNullOrEmpty(keyId)) {
                headerBuilder.keyID(keyId);
                logger.debug("Setting kid in JWT header: {}", keyId);
            }
            
            JWSHeader header = headerBuilder.build();

            // Build JWT claims set
            JWTClaimsSet claimsSet = buildJwtClaimsSet(claims);

            // Create signed JWT
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            // Sign the JWT with appropriate signer based on algorithm
            JWSSigner signer = createSigner(jwsAlgorithm);
            signedJWT.sign(signer);

            logger.debug("JWT token generated and signed successfully");
            return signedJWT.serialize();

        } catch (Exception e) {
            logger.error("Failed to generate JWT token", e);
            throw new IdTokenException("Failed to generate ID token: " + e.getMessage(), e);
        }
    }

    /**
     * Builds a JWT claims set from ID token claims.
     *
     * @param claims the ID token claims
     * @return the JWT claims set
     */
    private JWTClaimsSet buildJwtClaimsSet(IdTokenClaims claims) {

        // Build JWT claims set
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .issuer(claims.getIss())
                .subject(claims.getSub())
                .audience(claims.getAud())
                .expirationTime(new Date(claims.getExp() * 1000))
                .issueTime(new Date(claims.getIat() * 1000));

        // Add optional claims
        if (claims.getAuthTime() != null) {
            claimsSetBuilder.claim("auth_time", claims.getAuthTime());
        }
        if (claims.getNonce() != null) {
            claimsSetBuilder.claim("nonce", claims.getNonce());
        }
        if (claims.getAcr() != null) {
            claimsSetBuilder.claim("acr", claims.getAcr());
        }
        if (claims.getAmr() != null) {
            claimsSetBuilder.claim("amr", claims.getAmr());
        }
        if (claims.getAzp() != null) {
            claimsSetBuilder.claim("azp", claims.getAzp());
        }
        if (claims.getAtHash() != null) {
            claimsSetBuilder.claim("at_hash", claims.getAtHash());
        }
        if (claims.getAdditionalClaims() != null) {
            claims.getAdditionalClaims().forEach(claimsSetBuilder::claim);
        }

        return claimsSetBuilder.build();
    }

    /**
     * Creates a JWT signer based on the algorithm.
     *
     * @param algorithm the JWS algorithm
     * @return the JWT signer
     * @throws IdTokenException if the signer cannot be created
     */
    private JWSSigner createSigner(JWSAlgorithm algorithm) {
        try {
            if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
                return createRSASigner();
            } else if (JWSAlgorithm.Family.EC.contains(algorithm)) {
                return createECSigner();
            } else {
                throw new IdTokenException("Unsupported signing algorithm: " + algorithm);
            }
        } catch (Exception e) {
            logger.error("Failed to create JWT signer", e);
            throw new IdTokenException("Failed to create JWT signer: " + e.getMessage(), e);
        }
    }

    /**
     * Creates an RSA-based JWT signer.
     *
     * @return the RSA signer
     * @throws IdTokenException if the signer cannot be created
     */
    private JWSSigner createRSASigner() throws com.nimbusds.jose.JOSEException {
        if (signingKey instanceof RSAKey) {
            return new RSASSASigner((RSAKey) signingKey);
        } else if (signingKey instanceof java.security.interfaces.RSAPrivateKey) {
            return new RSASSASigner((java.security.interfaces.RSAPrivateKey) signingKey);
        } else {
            throw new IdTokenException("Invalid signing key for RSA algorithm: " +
                    signingKey.getClass().getName());
        }
    }

    /**
     * Creates an EC-based JWT signer.
     *
     * @return the EC signer
     * @throws IdTokenException if the signer cannot be created
     */
    private JWSSigner createECSigner() throws com.nimbusds.jose.JOSEException {
        if (signingKey instanceof ECKey) {
            return new ECDSASigner((ECKey) signingKey);
        } else if (signingKey instanceof java.security.interfaces.ECPrivateKey) {
            return new ECDSASigner((java.security.interfaces.ECPrivateKey) signingKey);
        } else {
            throw new IdTokenException("Invalid signing key for EC algorithm: " +
                    signingKey.getClass().getName());
        }
    }

    /**
     * Gets the issuer identifier.
     *
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the signing algorithm.
     *
     * @return the algorithm
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the signing key.
     *
     * @return the signing key
     */
    public Object getSigningKey() {
        return signingKey;
    }

    /**
     * Extracts the key ID from the signing key.
     * <p>
     * This method attempts to extract the kid from JWK objects (RSAKey, ECKey).
     * If the signing key is a standard Java key (PrivateKey), it returns null.
     * </p>
     *
     * @return the key ID, or null if not available
     */
    private String extractKeyId() {
        if (signingKey instanceof RSAKey) {
            return ((RSAKey) signingKey).getKeyID();
        } else if (signingKey instanceof ECKey) {
            return ((ECKey) signingKey).getKeyID();
        }
        // For standard Java keys, we don't have a kid
        return null;
    }

    /**
     * Computes the at_hash claim value for an access token.
     * <p>
     * The at_hash is computed as the base64url-encoded hash of the left half
     * of the access token. The hash algorithm is determined by the signing
     * algorithm used for the ID token.
     * </p>
     * <p>
     * Algorithm mapping:
     * <ul>
     *   <li>RS256, ES256, PS256 → SHA-256</li>
     *   <li>RS384, ES384, PS384 → SHA-384</li>
     *   <li>RS512, ES512, PS512 → SHA-512</li>
     * </ul>
     * </p>
     *
     * @param accessToken the access token value
     * @param algorithm the signing algorithm (e.g., "RS256", "ES256")
     * @return the base64url-encoded at_hash value
     * @throws IllegalArgumentException if the algorithm is unsupported
     */
    public static String computeAtHash(String accessToken, String algorithm) {
        try {
            // Determine hash algorithm based on signing algorithm
            String hashAlgorithm;
            int hashLength;
            
            if (algorithm == null) {
                throw new IllegalArgumentException("Algorithm cannot be null");
            }
            
            switch (algorithm) {
                case "RS256":
                case "ES256":
                case "PS256":
                    hashAlgorithm = "SHA-256";
                    hashLength = 32; // 256 bits = 32 bytes
                    break;
                case "RS384":
                case "ES384":
                case "PS384":
                    hashAlgorithm = "SHA-384";
                    hashLength = 48; // 384 bits = 48 bytes
                    break;
                case "RS512":
                case "ES512":
                case "PS512":
                    hashAlgorithm = "SHA-512";
                    hashLength = 64; // 512 bits = 64 bytes
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported algorithm for at_hash: " + algorithm);
            }
            
            // Compute hash of access token
            MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            
            // Take left half of hash (first hashLength/2 bytes)
            byte[] leftHalf = new byte[hashLength / 2];
            System.arraycopy(hash, 0, leftHalf, 0, leftHalf.length);
            
            // Base64URL encode
            return Base64URL.encode(leftHalf).toString();
            
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Hash algorithm not available", e);
        }
    }

}