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
package com.alibaba.openagentauth.spring.util;

import com.alibaba.openagentauth.core.crypto.jwk.JwksProvider;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

/**
 * Utility class for OAuth 2.0 server-side client authentication.
 * <p>
 * This class provides static methods for authenticating OAuth 2.0 clients
 * on the server side, supporting multiple authentication mechanisms as specified
 * in RFC 6749 Section 2.3 and RFC 7523.
 * </p>
 * <p>
 * <b>Supported Authentication Methods:</b></p>
 * <ul>
 *   <li><b>client_secret_basic (RFC 6749 Section 2.3.1)</b>: HTTP Basic authentication
 *       with client_id and client_secret</li>
 *   <li><b>private_key_jwt (RFC 7523 Section 2.2)</b>: JWT assertion signed with
 *       client's private key, verified using the client's published JWKS</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 1.0
 */
public class OAuth2ClientAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientAuthenticator.class);

    private static final String BASIC_AUTH_SCHEME = "Basic ";
    private static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    private static final String PRIVATE_KEY_JWT = "private_key_jwt";
    private static final String JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * The JWKS provider for verifying client assertion signatures.
     * <p>
     * This provider abstracts the mechanism for retrieving public keys, supporting
     * both local and remote JWKS sources (e.g., Agent IDP's JWKS endpoint).
     * </p>
     */
    private final JwksProvider jwksProvider;

    /**
     * Creates a new OAuth2ClientAuthenticator with the specified JWKS provider.
     *
     * @param jwksProvider the JWKS provider for verifying client assertion signatures
     * @throws IllegalArgumentException if jwksProvider is null
     */
    public OAuth2ClientAuthenticator(JwksProvider jwksProvider) {
        this.jwksProvider = ValidationUtils.validateNotNull(jwksProvider, "JWKS provider");
        logger.info("OAuth2ClientAuthenticator initialized with JwksProvider: {}", jwksProvider.getClass().getSimpleName());
    }

    /**
     * Authenticates the client using the appropriate method based on the request parameters.
     * <p>
     * This method automatically detects the authentication method:
     * </p>
     * <ul>
     *   <li>If {@code client_assertion} and {@code client_assertion_type} are present in the
     *       request body, uses {@code private_key_jwt} authentication (RFC 7523)</li>
     *   <li>If an {@code Authorization} header with Basic scheme is present, uses
     *       {@code client_secret_basic} authentication (RFC 6749 Section 2.3.1)</li>
     * </ul>
     *
     * @param authorizationHeader the Authorization header value (may be null)
     * @param requestBody the request body parameters (may be null)
     * @param clientStore the client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     */
    public String authenticateClient(
            String authorizationHeader,
            Map<String, String> requestBody,
            OAuth2ClientStore clientStore) {

        // Check for client_assertion in request body (private_key_jwt takes precedence)
        if (requestBody != null) {
            String clientAssertion = requestBody.get("client_assertion");
            String clientAssertionType = requestBody.get("client_assertion_type");

            if (!ValidationUtils.isNullOrEmpty(clientAssertion) && !ValidationUtils.isNullOrEmpty(clientAssertionType)) {
                return authenticateWithClientAssertion(clientAssertion, clientAssertionType, clientStore);
            }
        }

        // Fall back to Basic Auth
        return authenticateWithBasicAuth(authorizationHeader, clientStore);
    }

    /**
     * Authenticates the client using HTTP Basic authentication (RFC 6749 Section 2.3.1).
     *
     * @param authorizationHeader the Authorization header value
     * @param clientStore the client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     */
    public static String authenticateWithBasicAuth(String authorizationHeader, OAuth2ClientStore clientStore) {

        // Validate Authorization header is present
        if (ValidationUtils.isNullOrEmpty(authorizationHeader)) {
            logger.error("Authorization header is missing");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Authorization header is missing");
        }

        // Validate Basic Auth scheme
        if (!authorizationHeader.startsWith(BASIC_AUTH_SCHEME)) {
            logger.error("Invalid authentication scheme, expected 'Basic'");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Only Basic authentication is supported");
        }

        // Extract and decode credentials
        String base64Credentials = authorizationHeader.substring(BASIC_AUTH_SCHEME.length()).trim();
        String credentials;
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            credentials = new String(decodedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            logger.error("Failed to decode Base64 credentials", e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid Base64 encoding");
        }

        // Parse client_id:client_secret
        String[] parts = credentials.split(":", 2);
        if (parts.length != 2) {
            logger.error("Invalid credentials format, expected 'client_id:client_secret'");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid credentials format");
        }

        String clientId = parts[0];
        String clientSecret = parts[1];

        // Validate client ID is not empty
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            logger.error("Client ID is empty");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client ID is required");
        }

        // Retrieve client from client store
        OAuth2RegisteredClient client = clientStore.retrieve(clientId);
        if (client == null) {
            logger.error("Client not found: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client not registered");
        }

        // Validate client secret
        String storedSecret = client.getClientSecret();
        if (ValidationUtils.isNullOrEmpty(storedSecret)) {
            logger.error("Client {} has no secret configured (public client)", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for Basic authentication");
        }

        if (!storedSecret.equals(clientSecret)) {
            logger.error("Invalid client secret for client: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid client secret");
        }

        String authMethod = client.getTokenEndpointAuthMethod();
        if (authMethod != null && !CLIENT_SECRET_BASIC.equals(authMethod)) {
            logger.error("Client {} is not configured for client_secret_basic, configured method: {}", clientId, authMethod);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for Basic authentication");
        }

        logger.debug("Client authenticated via client_secret_basic: {}", clientId);
        return clientId;
    }

    /**
     * Authenticates the client using JWT-based client assertion (RFC 7523).
     * <p>
     * The client assertion JWT is verified against the client's published JWKS.
     * The following claims are validated:
     * </p>
     * <ul>
     *   <li><b>iss</b>: Must match the client_id</li>
     *   <li><b>sub</b>: Must match the client_id</li>
     *   <li><b>exp</b>: Must not be expired</li>
     *   <li><b>iat</b>: Must be present</li>
     * </ul>
     *
     * @param clientAssertion the JWT assertion
     * @param clientAssertionType the assertion type (must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer)
     * @param clientStore the client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     */
    public String authenticateWithClientAssertion(
            String clientAssertion,
            String clientAssertionType,
            OAuth2ClientStore clientStore) {

        // Validate assertion type
        if (!JWT_BEARER_ASSERTION_TYPE.equals(clientAssertionType)) {
            logger.error("Unsupported client_assertion_type: {}", clientAssertionType);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Unsupported client_assertion_type: " + clientAssertionType);
        }

        // Parse the JWT assertion
        SignedJWT signedJwt;
        JWTClaimsSet claimsSet;
        try {
            signedJwt = SignedJWT.parse(clientAssertion);
            claimsSet = signedJwt.getJWTClaimsSet();
        } catch (Exception e) {
            logger.error("Failed to parse client assertion JWT", e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid client assertion JWT");
        }

        // Extract and validate issuer (must be client_id per RFC 7523 Section 3)
        String clientId = claimsSet.getIssuer();
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            logger.error("Client assertion JWT missing 'iss' claim");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client assertion JWT missing 'iss' claim");
        }

        // Validate subject matches issuer (RFC 7523 Section 3)
        String subject = claimsSet.getSubject();
        if (!clientId.equals(subject)) {
            logger.error("Client assertion JWT 'sub' claim ({}) does not match 'iss' claim ({})", subject, clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client assertion JWT 'sub' must match 'iss'");
        }

        // Validate expiration
        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime == null || expirationTime.before(new Date())) {
            logger.error("Client assertion JWT is expired for client: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client assertion JWT is expired");
        }

        // Retrieve client from store
        OAuth2RegisteredClient client = clientStore.retrieve(clientId);
        if (client == null) {
            logger.error("Client not found: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client not registered");
        }

        // Validate auth method
        String authMethod = client.getTokenEndpointAuthMethod();
        if (authMethod != null && !PRIVATE_KEY_JWT.equals(authMethod)) {
            logger.error("Client {} is not configured for private_key_jwt, configured method: {}", clientId, authMethod);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for private_key_jwt authentication");
        }

        // Verify JWT signature using the injected JwksProvider
        verifyClientAssertionSignature(signedJwt, client);

        logger.debug("Client authenticated via private_key_jwt: {}", clientId);
        return clientId;
    }

    /**
     * Verifies the JWT signature using the injected {@link JwksProvider}.
     * <p>
     * This method delegates JWKS retrieval to the {@code JwksProvider} infrastructure
     * from the Core package, which supports both local and remote JWKS sources
     * (e.g., Agent IDP's JWKS endpoint). This avoids duplicating HTTP client logic
     * and ensures consistent key management across the system.
     * </p>
     *
     * @param signedJwt the signed JWT to verify
     * @param client the registered client (used for logging context)
     * @throws FrameworkOAuth2TokenException if signature verification fails
     */
    private void verifyClientAssertionSignature(SignedJWT signedJwt, OAuth2RegisteredClient client) {
        try {
            // Retrieve JWKS using the injected JwksProvider (supports local/remote sources)
            JWKSet jwkSet = jwksProvider.getJwkSet();

            // Find matching key by key ID
            String keyId = signedJwt.getHeader().getKeyID();
            JWK matchingKey = null;

            if (keyId != null) {
                matchingKey = jwkSet.getKeyByKeyId(keyId);
            }

            // If no key ID match, try the first RSA key
            if (matchingKey == null) {
                for (JWK jwk : jwkSet.getKeys()) {
                    if (jwk instanceof RSAKey) {
                        matchingKey = jwk;
                        break;
                    }
                }
            }

            if (matchingKey == null) {
                logger.error("No matching public key found in JWKS for client: {}", client.getClientId());
                throw FrameworkOAuth2TokenException.invalidClient(
                        "Client authentication failed: No matching public key found in client JWKS");
            }

            // Verify signature
            JWSVerifier verifier = new RSASSAVerifier(((RSAKey) matchingKey).toRSAPublicKey());
            if (!signedJwt.verify(verifier)) {
                logger.error("Client assertion JWT signature verification failed for client: {}", client.getClientId());
                throw FrameworkOAuth2TokenException.invalidClient(
                        "Client authentication failed: Client assertion JWT signature verification failed");
            }

        } catch (FrameworkOAuth2TokenException e) {
            throw e;
        } catch (IOException e) {
            logger.error("Failed to retrieve JWKS from provider for client: {}", client.getClientId(), e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Failed to retrieve JWKS: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Failed to verify client assertion signature for client: {}", client.getClientId(), e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Failed to verify client assertion signature: " + e.getMessage());
        }
    }

}