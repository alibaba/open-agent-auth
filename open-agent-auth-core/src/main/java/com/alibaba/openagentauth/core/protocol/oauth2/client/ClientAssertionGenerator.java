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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.UUID;

/**
 * Utility class for generating standard OAuth 2.0 client assertion JWTs.
 * <p>
 * This generator creates JWT-based client assertions according to 
 * <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>.
 * The generated JWT follows the {@code private_key_jwt} authentication method where the client
 * uses its private key to sign the assertion.
 * </p>
 * <p>
 * <b>JWT Structure:</b></p>
 * <ul>
 *   <li><b>Header:</b> {@code typ=client-authentication+jwt}, {@code alg} (signature algorithm), {@code kid} (key ID)</li>
 *   <li><b>Claims:</b> {@code iss} (issuer = client_id), {@code sub} (subject = client_id), 
 *       {@code aud} (audience = authorization server URL), {@code jti} (unique JWT ID), 
 *       {@code iat} (issued at), {@code exp} (expiration, 5 minutes from now)</li>
 *   <li><b>Signature:</b> Signed using the workload's private key (EC or RSA)</li>
 * </ul>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * JWK privateKey = JWK.parse(privateKeyJson);
 * String clientAssertion = ClientAssertionGenerator.generateClientAssertion(
 *     "my-client-id", 
 *     "https://auth-server.com/token", 
 *     privateKey
 * );
 * }</pre>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 1.0
 */
public final class ClientAssertionGenerator {

    private static final Logger logger = LoggerFactory.getLogger(ClientAssertionGenerator.class);

    /**
     * The JWT type value for client authentication assertions.
     */
    private static final JOSEObjectType CLIENT_AUTHENTICATION_JWT_TYPE = new JOSEObjectType("client-authentication+jwt");

    /**
     * Default signature algorithm if not specified in the JWK.
     */
    private static final JWSAlgorithm DEFAULT_ALGORITHM = JWSAlgorithm.ES256;

    /**
     * Client assertion validity duration in seconds (5 minutes).
     */
    private static final long ASSERTION_VALIDITY_SECONDS = 300L;

    /**
     * Private constructor to prevent instantiation.
     * <p>
     * This is a utility class with only static methods.
     * </p>
     */
    private ClientAssertionGenerator() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Generates a standard OAuth 2.0 client assertion JWT.
     * <p>
     * This method creates a JWT assertion conforming to RFC 7523, suitable for
     * {@code private_key_jwt} client authentication. The assertion is signed using
     * the provided private key and contains the required claims for OAuth 2.0 client
     * authentication.
     * </p>
     * <p>
     * <b>JWT Header:</b></p>
     <ul>
     *   <li>{@code typ}: {@code client-authentication+jwt}</li>
     *   <li>{@code alg}: Signature algorithm from the JWK, defaults to {@code ES256}</li>
     *   <li>{@code kid}: Key ID from the JWK</li>
     * </ul>
     * <p>
     * <b>JWT Claims:</b></p>
     * <ul>
     *   <li>{@code iss}: The client ID (issuer)</li>
     *   <li>{@code sub}: The client ID (subject)</li>
     *   <li>{@code aud}: The authorization server URL (audience)</li>
     *   <li>{@code jti}: A unique identifier for this JWT</li>
     *   <li>{@code iat}: Current timestamp (issued at)</li>
     *   <li>{@code exp}: Current timestamp + 300 seconds (expiration)</li>
     * </ul>
     * <p>
     * <b>Supported Key Types:</b></p>
     * <ul>
     *   <li>EC (Elliptic Curve) keys: Signed using {@code ECDSASigner}</li>
     *   <li>RSA keys: Signed using {@code RSASSASigner}</li>
     * </ul>
     * </p>
     *
     * @param clientId            The OAuth 2.0 client identifier (used as both issuer and subject)
     * @param authorizationServerUrl The authorization server token endpoint URL (used as audience)
     * @param privateKey          The JWK representing the private key used for signing
     * @return A signed JWT string representing the client assertion
     * @throws JOSEException     If the JWT cannot be created or signed
     * @throws IllegalArgumentException If the JWK type is not supported or required parameters are missing
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
     */
    public static String generateClientAssertion(String clientId, String authorizationServerUrl, JWK privateKey) 
            throws JOSEException {
        
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId must not be null or blank");
        }
        
        if (authorizationServerUrl == null || authorizationServerUrl.isBlank()) {
            throw new IllegalArgumentException("authorizationServerUrl must not be null or blank");
        }
        
        if (privateKey == null) {
            throw new IllegalArgumentException("privateKey must not be null");
        }

        logger.debug("Generating client assertion for client: {}", clientId);

        // Determine the signature algorithm from the JWK
        Algorithm algorithm = privateKey.getAlgorithm();
        JWSAlgorithm jwsAlgorithm;
        if (algorithm == null) {
            jwsAlgorithm = DEFAULT_ALGORITHM;
            logger.debug("No algorithm specified in JWK, using default: {}", jwsAlgorithm);
        } else if (algorithm instanceof JWSAlgorithm) {
            jwsAlgorithm = (JWSAlgorithm) algorithm;
        } else {
            throw new IllegalArgumentException(
                    "Unsupported algorithm in JWK: " + algorithm + 
                    ". Only JWS algorithms (e.g., ES256, RS256) are supported for client assertion generation.");
        }

        // Build JWT Header
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(jwsAlgorithm)
                .type(CLIENT_AUTHENTICATION_JWT_TYPE);
        
        String keyId = privateKey.getKeyID();
        if (keyId != null && !keyId.isBlank()) {
            headerBuilder.keyID(keyId);
        }
        
        JWSHeader header = headerBuilder.build();

        // Build JWT Claims
        Date now = new Date();
        Date expirationTime = new Date(now.getTime() + ASSERTION_VALIDITY_SECONDS * 1000L);
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(authorizationServerUrl)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(now)
                .expirationTime(expirationTime)
                .build();

        // Create and sign the JWT
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        // Sign based on key type
        if (privateKey instanceof ECKey) {
            ECKey ecKey = (ECKey) privateKey;
            ECPrivateKey ecPrivateKey = ecKey.toECPrivateKey();
            com.nimbusds.jose.crypto.ECDSASigner signer = new com.nimbusds.jose.crypto.ECDSASigner(ecPrivateKey);
            signedJWT.sign(signer);
            logger.debug("Client assertion signed with EC key");
        } else if (privateKey instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) privateKey;
            RSAPrivateKey rsaPrivateKey = rsaKey.toRSAPrivateKey();
            com.nimbusds.jose.crypto.RSASSASigner signer = new com.nimbusds.jose.crypto.RSASSASigner(rsaPrivateKey);
            signedJWT.sign(signer);
            logger.debug("Client assertion signed with RSA key");
        } else {
            throw new IllegalArgumentException(
                    "Unsupported JWK type: " + privateKey.getClass().getSimpleName() + 
                    ". Only EC and RSA keys are supported for client assertion generation.");
        }

        String clientAssertion = signedJWT.serialize();
        logger.debug("Client assertion generated successfully for client: {}", clientId);

        return clientAssertion;
    }
}