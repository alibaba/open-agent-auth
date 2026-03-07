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
package com.alibaba.openagentauth.core.protocol.oauth2.client;

import com.alibaba.openagentauth.core.exception.oauth2.ClientAssertionException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
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
 * Generator for OAuth 2.0 Client Assertions according to RFC 7523.
 * <p>
 * This class generates JWT-based client assertions for OAuth 2.0 client authentication.
 * It follows RFC 7523 "JWT Profile for OAuth 2.0 Client Authentication" specification.
 * </p>
 * <p>
 * <b>JWT Assertion Structure (RFC 7523):</b></p>
 * <pre>
 * {
 *   "iss": "client_id",
 *   "sub": "client_id",
 *   "aud": "https://as.example.com/token",
 *   "exp": 1731668100,
 *   "iat": 1731664500,
 *   "jti": "urn:uuid:..."
 * }
 * </pre>
 * <p>
 * <b>WIMSE Integration:</b></p>
 * <p>
 * When using WIMSE-based authentication, the client assertion includes additional
 * claims that bind the assertion to a Workload Identity Token (WIT). This allows
 * the Authorization Server to verify the workload's identity in addition to the
 * OAuth client's credentials.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 1.0
 */
public class ClientAssertionGenerator {

    private static final Logger logger = LoggerFactory.getLogger(ClientAssertionGenerator.class);

    /**
     * The client identifier.
     */
    private final String clientId;

    /**
     * The RSA key used for signing assertions.
     */
    private final RSAKey signingKey;

    /**
     * The JWS algorithm to use (e.g., RS256).
     */
    private final JWSAlgorithm algorithm;

    /**
     * Default assertion expiration time in seconds (5 minutes).
     */
    private static final long DEFAULT_EXPIRATION_SECONDS = 300;

    /**
     * Creates a new ClientAssertionGenerator.
     *
     * @param clientId the client identifier
     * @param signingKey the RSA key used for signing assertions
     * @param algorithm the JWS algorithm to use
     * @throws IllegalArgumentException if any parameter is null or invalid
     */
    public ClientAssertionGenerator(String clientId, RSAKey signingKey, JWSAlgorithm algorithm) {
        this.clientId = requireNotBlank(clientId, "Client ID cannot be null or blank");
        this.signingKey = ValidationUtils.validateNotNull(signingKey, "Signing key");
        this.algorithm = ValidationUtils.validateNotNull(algorithm, "Algorithm");
        
        logger.info("ClientAssertionGenerator initialized for client: {}", clientId);
    }

    /**
     * Generates a client assertion JWT for the specified token endpoint.
     * Uses the default client_id configured at construction time.
     *
     * @param tokenEndpoint the token endpoint URL (audience)
     * @return the client assertion JWT string
     * @throws ClientAssertionException if generation fails
     */
    public String generateAssertion(String tokenEndpoint) {
        return generateAssertion(tokenEndpoint, clientId, DEFAULT_EXPIRATION_SECONDS);
    }

    /**
     * Generates a client assertion JWT with custom expiration.
     * Uses the default client_id configured at construction time.
     *
     * @param tokenEndpoint the token endpoint URL (audience)
     * @param expirationSeconds the assertion expiration time in seconds
     * @return the client assertion JWT string
     * @throws ClientAssertionException if generation fails
     */
    public String generateAssertion(String tokenEndpoint, long expirationSeconds) {
        return generateAssertion(tokenEndpoint, clientId, expirationSeconds);
    }

    /**
     * Generates a client assertion JWT with a dynamic client_id override and default expiration.
     * <p>
     * This overload supports DCR (Dynamic Client Registration) scenarios where the
     * effective {@code client_id} differs from the static default configured at
     * construction time.
     * </p>
     *
     * @param tokenEndpoint the token endpoint URL (audience)
     * @param effectiveClientId the client_id to use as {@code iss} and {@code sub} in the JWT
     * @return the client assertion JWT string
     * @throws ClientAssertionException if generation fails
     */
    public String generateAssertion(String tokenEndpoint, String effectiveClientId) {
        return generateAssertion(tokenEndpoint, effectiveClientId, DEFAULT_EXPIRATION_SECONDS);
    }

    /**
     * Generates a client assertion JWT with a dynamic client_id override and custom expiration.
     * <p>
     * This overload supports DCR (Dynamic Client Registration) scenarios where the
     * effective {@code client_id} differs from the static default configured at
     * construction time. Per RFC 7523 Section 3, the {@code iss} and {@code sub}
     * claims in the assertion JWT MUST match the {@code client_id} that the
     * Authorization Server will use for authentication.
     * </p>
     *
     * @param tokenEndpoint the token endpoint URL (audience)
     * @param effectiveClientId the client_id to use as {@code iss} and {@code sub} in the JWT
     * @param expirationSeconds the assertion expiration time in seconds
     * @return the client assertion JWT string
     * @throws ClientAssertionException if generation fails
     * @throws IllegalArgumentException if any parameter is null/blank or expirationSeconds is not positive
     */
    public String generateAssertion(String tokenEndpoint, String effectiveClientId, long expirationSeconds) {
        requireNotBlank(tokenEndpoint, "Token endpoint cannot be null or blank");
        requireNotBlank(effectiveClientId, "Effective client ID cannot be null or blank");
        
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Expiration seconds must be positive");
        }

        logger.debug("Generating client assertion for client: {}, audience: {}", effectiveClientId, tokenEndpoint);

        try {
            Instant now = Instant.now();
            Instant expirationTime = now.plusSeconds(expirationSeconds);
            
            // Build JWT claims set according to RFC 7523
            // iss and sub MUST match the client_id used for authentication
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(effectiveClientId)                    // iss: effective client_id
                    .subject(effectiveClientId)                   // sub: effective client_id
                    .audience(tokenEndpoint)                      // aud: token endpoint
                    .expirationTime(Date.from(expirationTime))    // exp
                    .issueTime(Date.from(now))                    // iat
                    .jwtID(UUID.randomUUID().toString())           // jti
                    .build();
            
            // Build JWS header
            JWSHeader header = new JWSHeader.Builder(algorithm)
                    .keyID(signingKey.getKeyID())
                    .build();
            
            // Sign the JWT
            SignedJWT signedJwt = new SignedJWT(header, claimsSet);
            signedJwt.sign(new RSASSASigner(signingKey));
            
            String assertion = signedJwt.serialize();
            logger.debug("Successfully generated client assertion for client: {}", effectiveClientId);
            
            return assertion;
            
        } catch (JOSEException e) {
            logger.error("Failed to generate client assertion for client: {}", effectiveClientId, e);
            throw new ClientAssertionException("Failed to generate client assertion: " + e.getMessage(), e);
        }
    }

    /**
     * Validates that a string is not null or blank.
     *
     * @param value the string to validate
     * @param fieldName the name of the field for error messages
     * @return the validated string
     * @throws IllegalArgumentException if the value is null or blank
     */
    private static String requireNotBlank(String value, String fieldName) {
        if (ValidationUtils.isNullOrEmpty(value)) {
            throw new IllegalArgumentException(fieldName);
        }
        return value.trim();
    }
}